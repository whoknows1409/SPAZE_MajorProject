"""
SPAZE Server - Presence-Attested Key Leasing (PAKL)

Primitives used when SECURITY_MODE == "pakl":

1. Presence tokens
   The badge broadcasts a rolling token in BLE manufacturer data:
       [0xFF 0xFF][0x5A][ver=0x01][badge_id:4][counter:4][tag:8]
   tag = HMAC-SHA256(K_badge, 0x5A || ver || badge_id || counter)[:8]
   The counter is monotonic (boot epoch << 20 | seconds since boot).

2. Freshness
   A token is accepted only if its counter is not older than the last
   accepted counter AND its clock offset (counter - server_time) has not
   moved backwards by more than TOKEN_SLACK_S. The reference offset may
   only decay at a crystal-drift rate, so old recordings cannot be
   replayed later than TOKEN_SLACK_S after they were captured.

3. Device request signatures
   Agent requests carry X-SPAZE-Device / X-SPAZE-Timestamp /
   X-SPAZE-Signature, where
       signature = HMAC-SHA256(K_device, METHOD \\n PATH \\n ts \\n sha256(body))

4. FEK wrapping
   FEKs are stored wrapped with a server master key (AES-256-GCM, AAD
   binds the device id and file path).

5. Leases
   Keys are released together with a short lease that must be renewed
   with a fresh presence token every few seconds.
"""

import base64
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_MAGIC = 0x5A
TOKEN_VERSION = 0x01
COMPANY_ID = b"\xff\xff"          # Bluetooth SIG "reserved for testing"
TOKEN_LEN = 20                    # bytes of manufacturer data
TAG_LEN = 8

# Crystal drift allowance for the badge clock (20 ppm; ESP32 RF crystals are
# specified at roughly +-10 ppm)
DRIFT_RATE = 2e-5

WRAP_PREFIX = b"W1"


# ============================================================
# Presence tokens
# ============================================================

@dataclass
class PresenceToken:
    badge_id: int
    counter: int
    tag: bytes
    signed_part: bytes


def parse_token(token_hex: str) -> Optional[PresenceToken]:
    """Parse a hex-encoded manufacturer-data payload. Returns None if malformed."""
    try:
        raw = bytes.fromhex(token_hex)
    except (ValueError, TypeError):
        return None
    if len(raw) != TOKEN_LEN or raw[:2] != COMPANY_ID:
        return None
    if raw[2] != TOKEN_MAGIC or raw[3] != TOKEN_VERSION:
        return None
    badge_id, counter = struct.unpack(">II", raw[4:12])
    return PresenceToken(
        badge_id=badge_id,
        counter=counter,
        tag=raw[12:12 + TAG_LEN],
        signed_part=raw[2:12],
    )


def compute_tag(badge_key: bytes, signed_part: bytes) -> bytes:
    return hmac.new(badge_key, signed_part, hashlib.sha256).digest()[:TAG_LEN]


def make_token(badge_key: bytes, badge_id: int, counter: int) -> str:
    """Build a token exactly as the badge firmware does (used by tests and tools)."""
    signed_part = bytes([TOKEN_MAGIC, TOKEN_VERSION]) + struct.pack(">II", badge_id, counter)
    return (COMPANY_ID + signed_part + compute_tag(badge_key, signed_part)).hex()


def verify_token_tag(token: PresenceToken, badge_key: bytes) -> bool:
    return hmac.compare_digest(compute_tag(badge_key, token.signed_part), token.tag)


@dataclass
class FreshnessState:
    """Per-badge anti-replay state (persisted on the Badge row)."""
    last_counter: Optional[int] = None
    offset_ref: Optional[float] = None   # counter - server_time at reference
    ref_time: Optional[float] = None     # server_time when offset_ref was set
    last_counter_time: Optional[float] = None  # when last_counter was first accepted


def check_freshness(
    counter: int,
    state: FreshnessState,
    now: float,
    slack_s: float,
    max_reuse_s: float,
) -> tuple[bool, str, FreshnessState]:
    """
    Decide whether a correctly-authenticated counter is fresh.
    Returns (accepted, reason, new_state). The input state is not modified.
    """
    offset = counter - now

    if state.last_counter is None:
        # First token ever seen for this badge (trust on first use)
        return True, "first_use", FreshnessState(counter, offset, now, now)

    if counter < state.last_counter:
        return False, "counter_regressed", state

    if counter == state.last_counter:
        if now - (state.last_counter_time or now) > max_reuse_s:
            return False, "token_reused_too_long", state
        return True, "same_counter", state

    # Reference offset may only decay at the drift rate
    decayed_ref = state.offset_ref - DRIFT_RATE * (now - state.ref_time)
    if offset < decayed_ref - slack_s:
        return False, "stale_token", state

    new_ref = max(offset, decayed_ref)
    return True, "fresh", FreshnessState(counter, new_ref, now, now)


# ============================================================
# Device request signatures
# ============================================================

def request_signing_string(method: str, path: str, ts: str, body: bytes) -> bytes:
    return "\n".join([
        method.upper(), path, ts, hashlib.sha256(body).hexdigest(),
    ]).encode()


def sign_request(device_key: bytes, method: str, path: str, ts: str, body: bytes) -> str:
    return hmac.new(
        device_key, request_signing_string(method, path, ts, body), hashlib.sha256
    ).hexdigest()


def verify_request_signature(
    device_key: bytes, method: str, path: str, ts: str, body: bytes,
    signature: str, now: float, max_skew_s: float,
) -> tuple[bool, str]:
    try:
        ts_val = float(ts)
    except (TypeError, ValueError):
        return False, "bad_timestamp"
    if abs(now - ts_val) > max_skew_s:
        return False, "timestamp_skew"
    expected = sign_request(device_key, method, path, ts, body)
    if not hmac.compare_digest(expected, signature or ""):
        return False, "bad_signature"
    return True, "ok"


# ============================================================
# FEK wrapping
# ============================================================

def _fek_aad(device_id: int, file_path: str) -> bytes:
    return f"spaze-fek|{device_id}|{file_path}".encode()


def wrap_fek(master_key: bytes, fek: bytes, device_id: int, file_path: str) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(master_key).encrypt(nonce, fek, _fek_aad(device_id, file_path))
    return WRAP_PREFIX + nonce + ct


def is_wrapped(blob: bytes) -> bool:
    return blob.startswith(WRAP_PREFIX) and len(blob) == len(WRAP_PREFIX) + 12 + 32 + 16


def unwrap_fek(master_key: Optional[bytes], blob: bytes, device_id: int, file_path: str) -> bytes:
    """Unwrap a stored FEK. Legacy (unwrapped) 32-byte keys are returned as-is."""
    if not is_wrapped(blob):
        return blob
    if master_key is None:
        raise ValueError("FEK is wrapped but no MASTER_KEY is configured")
    nonce = blob[len(WRAP_PREFIX):len(WRAP_PREFIX) + 12]
    ct = blob[len(WRAP_PREFIX) + 12:]
    return AESGCM(master_key).decrypt(nonce, ct, _fek_aad(device_id, file_path))


# ============================================================
# Challenge-response with anchor-measured round-trip time (PAKL-CR)
# ============================================================

CR_NONCE_LEN = 16


def cr_response(badge_key: bytes, nonce: bytes) -> bytes:
    """Badge answer to a server challenge (computed on the badge over BLE GATT)."""
    return hmac.new(badge_key, b"CR" + nonce, hashlib.sha256).digest()[:8]


def cr_attestation(anchor_key: bytes, nonce: bytes, resp: bytes, rtt_us: int) -> bytes:
    """Anchor's signature over the challenge, the badge answer and the measured RTT."""
    msg = b"AT" + nonce + resp + struct.pack(">I", rtt_us)
    return hmac.new(anchor_key, msg, hashlib.sha256).digest()[:16]


def verify_cr(badge_key: bytes, anchor_key: bytes, nonce: bytes, resp: bytes,
              rtt_us: int, att: bytes, max_rtt_us: int) -> tuple[bool, str]:
    if not hmac.compare_digest(cr_attestation(anchor_key, nonce, resp, rtt_us), att):
        return False, "cr_bad_attestation"
    if not hmac.compare_digest(cr_response(badge_key, nonce), resp):
        return False, "cr_bad_response"
    if rtt_us > max_rtt_us:
        return False, f"cr_rtt_exceeded({rtt_us}us)"
    return True, "ok"


# ============================================================
# Wrapping of badge / device / anchor secrets stored in the DB
# ============================================================

SECRET_PREFIX = "w1:"


def wrap_secret(master_key: bytes, secret: bytes, label: str) -> str:
    """Wrap a 32-byte HMAC key for storage; `label` (e.g. 'badge|3') is bound as AAD."""
    nonce = os.urandom(12)
    ct = AESGCM(master_key).encrypt(nonce, secret, f"spaze-secret|{label}".encode())
    return SECRET_PREFIX + base64.b64encode(nonce + ct).decode()


def unwrap_secret(master_key: Optional[bytes], stored: str, label: str) -> bytes:
    """Return the raw key; legacy unwrapped 64-hex values are accepted as-is."""
    if not stored.startswith(SECRET_PREFIX):
        return bytes.fromhex(stored)
    if master_key is None:
        raise ValueError("secret is wrapped but no MASTER_KEY is configured")
    blob = base64.b64decode(stored[len(SECRET_PREFIX):])
    return AESGCM(master_key).decrypt(blob[:12], blob[12:], f"spaze-secret|{label}".encode())


def master_key_from_hex(hex_str: str) -> Optional[bytes]:
    if not hex_str:
        return None
    key = bytes.fromhex(hex_str)
    if len(key) != 32:
        raise ValueError("MASTER_KEY must be 32 bytes (64 hex characters)")
    return key


def now() -> float:
    return time.time()
