"""
SPAZE Server - PAKL request dependencies

FastAPI helpers that enforce device request signatures, presence-token
freshness and key leases when SECURITY_MODE == "pakl". In "baseline"
mode they are no-ops so the original behaviour is preserved.
"""

import json
import logging
import math
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.cache import get_redis
from server.config import get_settings
from server.db.database import get_db
from server.db.models import AuditLog, Badge, Device
from server.security import pakl

logger = logging.getLogger("spaze-server.pakl")
settings = get_settings()


def pakl_enabled() -> bool:
    return settings.SECURITY_MODE.lower() == "pakl"


def master_key() -> Optional[bytes]:
    return pakl.master_key_from_hex(settings.MASTER_KEY)


def badge_key(badge: Badge) -> bytes:
    return pakl.unwrap_secret(master_key(), badge.hmac_secret, f"badge|{badge.id}")


def device_key(device: Device) -> bytes:
    return pakl.unwrap_secret(master_key(), device.api_secret, f"device|{device.id}")


def anchor_key(device: Device) -> bytes:
    return pakl.unwrap_secret(master_key(), device.anchor_secret, f"anchor|{device.id}")


async def require_device_signature(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[Device]:
    """Verify the HMAC signature of an agent request (PAKL mode only)."""
    if not pakl_enabled():
        return None

    hostname = request.headers.get("X-SPAZE-Device", "")
    ts = request.headers.get("X-SPAZE-Timestamp", "")
    signature = request.headers.get("X-SPAZE-Signature", "")
    if not (hostname and ts and signature):
        raise HTTPException(status_code=401, detail="Missing device signature")

    result = await db.execute(select(Device).where(Device.hostname == hostname))
    device = result.scalars().first()
    if device is None or not device.api_secret:
        raise HTTPException(status_code=401, detail="Unknown or unprovisioned device")

    body = await request.body()
    try:
        dkey = device_key(device)
    except Exception:
        raise HTTPException(status_code=401, detail="Device key unavailable")
    ok, reason = pakl.verify_request_signature(
        dkey, request.method, request.url.path,
        ts, body, signature, pakl.now(), settings.SIG_MAX_SKEW_S,
    )
    if not ok:
        logger.warning(f"Rejected agent request from {hostname}: {reason}")
        raise HTTPException(status_code=401, detail=f"Invalid device signature ({reason})")

    # Reject replays of a captured signed request
    r = await get_redis()
    fresh = await r.set(
        f"spaze:sig:{signature}", "1",
        ex=int(settings.SIG_MAX_SKEW_S * 2), nx=True,
    )
    if not fresh:
        raise HTTPException(status_code=401, detail="Replayed request")

    return device


async def verify_presence(
    db: AsyncSession, badge: Badge, token_hex: Optional[str],
) -> tuple[bool, str]:
    """
    Check a rolling presence token for `badge` and advance its anti-replay
    state. Returns (ok, reason).
    """
    if not badge.hmac_secret:
        return False, "badge_not_provisioned"
    if not token_hex:
        return False, "missing_presence_token"

    token = pakl.parse_token(token_hex)
    if token is None:
        return False, "malformed_token"
    if token.badge_id != badge.id:
        return False, "token_badge_mismatch"
    try:
        bkey = badge_key(badge)
    except Exception:
        return False, "badge_key_unavailable"
    if not pakl.verify_token_tag(token, bkey):
        return False, "bad_token_tag"

    state = pakl.FreshnessState(
        last_counter=badge.tok_last_counter,
        offset_ref=badge.tok_offset_ref,
        ref_time=badge.tok_ref_time,
        last_counter_time=badge.tok_last_counter_time,
    )
    ok, reason, new_state = pakl.check_freshness(
        token.counter, state, pakl.now(),
        settings.TOKEN_SLACK_S, settings.TOKEN_MAX_REUSE_S,
    )
    if ok:
        badge.tok_last_counter = new_state.last_counter
        badge.tok_offset_ref = new_state.offset_ref
        badge.tok_ref_time = new_state.ref_time
        badge.tok_last_counter_time = new_state.last_counter_time
        await db.flush()
    return ok, reason


# ============================================================
# Leases (Redis, auto-expiring)
# ============================================================

# ============================================================
# Challenges for PAKL-CR (Redis, single use, auto-expiring)
# ============================================================

def cr_enabled() -> bool:
    return pakl_enabled() and settings.CR_REQUIRED


async def issue_challenge(badge: Badge, device: Device) -> str:
    nonce = secrets.token_hex(pakl.CR_NONCE_LEN)
    r = await get_redis()
    await r.set(f"spaze:chal:{nonce}", json.dumps({"badge_id": badge.id, "device_id": device.id}),
                px=int(settings.CHALLENGE_TTL_S * 1000))
    return nonce


async def check_cr(badge: Badge, device: Device, cr: Optional[dict]) -> tuple[bool, str]:
    """Verify a challenge answer: single-use nonce, badge HMAC, anchor attestation, RTT bound."""
    if not cr:
        return False, "cr_missing"
    try:
        nonce_hex = str(cr["nonce"])
        resp = bytes.fromhex(cr["resp"])
        att = bytes.fromhex(cr["att"])
        rtt_us = int(cr["rtt_us"])
    except (KeyError, ValueError, TypeError):
        return False, "cr_malformed"
    r = await get_redis()
    data = await r.getdel(f"spaze:chal:{nonce_hex}")
    if data is None:
        return False, "cr_unknown_or_used_challenge"
    owner = json.loads(data)
    if owner != {"badge_id": badge.id, "device_id": device.id}:
        return False, "cr_challenge_mismatch"
    if not device.anchor_secret:
        return False, "cr_anchor_not_provisioned"
    return pakl.verify_cr(badge_key(badge), anchor_key(device), bytes.fromhex(nonce_hex),
                          resp, rtt_us, att, settings.CR_MAX_RTT_US)


def _lease_key(lease_id: str) -> str:
    return f"spaze:lease:{lease_id}"


async def create_lease(badge: Badge, device: Device) -> str:
    lease_id = secrets.token_hex(16)
    r = await get_redis()
    await r.set(
        _lease_key(lease_id),
        json.dumps({"badge_id": badge.id, "device_id": device.id}),
        px=int(math.ceil(settings.LEASE_TTL_S * 1000)),
    )
    return lease_id


async def get_lease(lease_id: str) -> Optional[dict]:
    r = await get_redis()
    data = await r.get(_lease_key(lease_id))
    return json.loads(data) if data else None


async def extend_lease(lease_id: str):
    r = await get_redis()
    await r.pexpire(_lease_key(lease_id), int(math.ceil(settings.LEASE_TTL_S * 1000)))
    await r.delete(_lease_key(lease_id) + ":cr_retry")


async def end_lease(lease_id: str):
    r = await get_redis()
    await r.delete(_lease_key(lease_id), _lease_key(lease_id) + ":cr_retry")


async def allow_cr_retry(lease_id: str) -> bool:
    """One retry per renewal for a genuine but slow CR answer (cleared when the lease is extended)."""
    r = await get_redis()
    return bool(await r.set(_lease_key(lease_id) + ":cr_retry", "1", nx=True,
                            px=int(math.ceil(settings.LEASE_TTL_S * 1000))))


def audit(db: AsyncSession, action: str, details: str,
          badge_id: Optional[int] = None, device_id: Optional[int] = None):
    db.add(AuditLog(badge_id=badge_id, device_id=device_id,
                    action=action, details=details))
