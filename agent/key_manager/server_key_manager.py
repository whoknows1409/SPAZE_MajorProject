"""
SPAZE - Server Key Manager

Fetches and stores File Encryption Keys (FEKs) via the SPAZE server API.
Replaces local .keys.json with server-backed key distribution.

Flow:
  1. Badge detected → fetch_keys() → GET keys from server
  2. New file encrypted → store_key() → POST key to server
  3. File deleted → delete_key() → DELETE key from server
  4. Events → log_event() → POST audit entry to server
"""

import base64
import hashlib
import hmac
import json
import logging
import socket
import time
from typing import Callable, Optional

import httpx

from .key_manager import EphemeralKeyManager
from .. import trace

logger = logging.getLogger("spaze-agent.server-keymgr")

# A renewal that takes longer than this counts as "no answer" (fail-closed path)
RENEW_TIMEOUT_S = 2.0


class ServerKeyManager(EphemeralKeyManager):
    """
    Server-backed key manager that fetches keys from the SPAZE server.
    
    Inherits from EphemeralKeyManager for:
    - In-memory key storage (bytearray for secure wipe)
    - Key generation (AES-256-GCM)
    - Secure wipe on lock
    
    Adds server integration for:
    - Fetching keys on vault unlock
    - Storing new keys on vault lock
    - Deleting keys when files are removed
    - Audit event logging
    """

    def __init__(
        self,
        server_url: str,
        badge_mac: str,
        device_hostname: Optional[str] = None,
        security_mode: str = "baseline",
        device_key: Optional[bytes] = None,
        ca_cert: Optional[str] = None,
    ):
        # No local keystore in server mode
        super().__init__(keystore_path=None)

        self.server_url = server_url.rstrip("/")
        self.badge_mac = badge_mac
        self.device_hostname = device_hostname or socket.gethostname()
        self._authorized = False

        # PAKL: signed requests, presence tokens and key leases
        self.security_mode = security_mode
        self.device_key = device_key
        self.token_provider: Optional[Callable[[], Optional[str]]] = None
        self.lease_id: Optional[str] = None
        self.lease_ttl: float = 0.0
        self.last_lease_ok: float = 0.0

        # PAKL-CR: answer server challenges through the anchor
        self.cr_enabled = False
        self.cr_provider: Optional[Callable[[str], Optional[dict]]] = None
        self.pending_challenge: Optional[str] = None

        # HTTP client with timeout (verify server cert against ca_cert if given)
        self._client = httpx.Client(timeout=5.0, verify=ca_cert if ca_cert else True)

        logger.info(f"ServerKeyManager initialized")
        logger.info(f"  Server: {self.server_url}")
        logger.info(f"  Badge:  {self.badge_mac}")
        logger.info(f"  Device: {self.device_hostname}")

    @property
    def authorized(self) -> bool:
        """Whether the last key request was authorized by the server."""
        return self._authorized

    def fetch_keys(self) -> bool:
        """
        Fetch all FEKs from the server for this badge+device pair.
        
        Returns True if authorized and keys loaded, False otherwise.
        This is called when badge comes in range, BEFORE decrypting vault.
        """
        try:
            body = {
                "badge_mac": self.badge_mac,
                "device_hostname": self.device_hostname,
            }
            if self.pakl:
                body["presence_token"] = self._current_token()
            if self.pakl and self.cr_enabled:
                chal = self._post("/api/keys/challenge", {
                    "badge_mac": self.badge_mac, "device_hostname": self.device_hostname})
                if chal.status_code != 200:
                    logger.warning(f"🚫 No challenge from server: HTTP {chal.status_code}")
                    trace.event("key_request_denied", message=f"challenge HTTP {chal.status_code}")
                    return False
                body["cr"] = self._answer_challenge(chal.json()["challenge"])
            response = self._post("/api/keys/request", body)

            if response.status_code != 200:
                logger.error(f"Key request failed: HTTP {response.status_code}")
                self._authorized = False
                return False

            data = response.json()
            self._authorized = data.get("authorized", False)

            if not self._authorized:
                message = data.get("message", "Access denied")
                logger.warning(f"🚫 Server denied access: {message}")
                trace.event("key_request_denied", message=message)
                return False

            self.lease_id = data.get("lease_id")
            self.lease_ttl = float(data.get("lease_ttl") or 0.0)
            self.last_lease_ok = time.time()
            self.pending_challenge = data.get("challenge")

            # Load keys into memory
            keys = data.get("keys", {})
            for filename, key_b64 in keys.items():
                key_bytes = base64.b64decode(key_b64)
                self._keys[filename] = bytearray(key_bytes)

            logger.info(
                f"✅ Server authorized: {len(keys)} keys loaded | "
                f"msg={data.get('message', '')}"
            )
            return True

        except httpx.ConnectError:
            logger.error("❌ Cannot connect to SPAZE server — access DENIED (fail-closed)")
            self._authorized = False
            return False
        except Exception as e:
            logger.error(f"❌ Key fetch failed: {e} — access DENIED (fail-closed)")
            self._authorized = False
            return False

    def store_key(self, file_path: str, key: bytes) -> bool:
        """
        Upload a new/updated FEK to the server.
        Called when a new file is encrypted or an existing file is re-encrypted.
        """
        try:
            response = self._post("/api/keys/store", {
                "badge_mac": self.badge_mac,
                "device_hostname": self.device_hostname,
                "file_path": file_path,
                "encrypted_fek": base64.b64encode(key).decode("utf-8"),
            })

            if response.status_code == 200:
                logger.info(f"📤 Key stored on server: {file_path}")
                return True
            else:
                logger.error(
                    f"Failed to store key: HTTP {response.status_code} — "
                    f"{response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to store key for {file_path}: {e}")
            return False

    def delete_key(self, file_path: str) -> bool:
        """
        Remove a FEK from the server when a file is deleted.
        """
        try:
            response = self._post("/api/keys/delete", {
                "badge_mac": self.badge_mac,
                "device_hostname": self.device_hostname,
                "file_path": file_path,
            })

            if response.status_code == 200:
                logger.info(f"🗑️ Key deleted from server: {file_path}")
                return True
            else:
                logger.error(f"Failed to delete key: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to delete key for {file_path}: {e}")
            return False

    def log_event(
        self,
        action: str,
        details: str = "",
        file_path: Optional[str] = None,
        rssi_value: Optional[int] = None,
    ) -> bool:
        """
        Send an audit event to the server.
        
        Actions: vault_unlock, vault_lock, file_encrypt, file_decrypt, etc.
        """
        try:
            payload = {
                "badge_mac": self.badge_mac,
                "device_hostname": self.device_hostname,
                "action": action,
                "details": details,
            }
            if file_path:
                payload["file_path"] = file_path
            if rssi_value is not None:
                payload["rssi_value"] = rssi_value

            response = self._post("/api/audit/log", payload)

            if response.status_code == 200:
                logger.debug(f"Audit logged: {action}")
                return True
            else:
                logger.warning(f"Audit log failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")
            return False

    # ---------------------------------------------------------
    # PAKL helpers
    # ---------------------------------------------------------

    @property
    def pakl(self) -> bool:
        return self.security_mode == "pakl"

    def _current_token(self) -> Optional[str]:
        return self.token_provider() if self.token_provider else None

    def _post(self, path: str, payload: dict, timeout: Optional[float] = None) -> httpx.Response:
        """POST JSON; in PAKL mode the request is signed with the device key."""
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if self.pakl and self.device_key:
            ts = f"{time.time():.3f}"
            signing = "\n".join([
                "POST", path, ts, hashlib.sha256(body).hexdigest(),
            ]).encode()
            headers.update({
                "X-SPAZE-Device": self.device_hostname,
                "X-SPAZE-Timestamp": ts,
                "X-SPAZE-Signature": hmac.new(self.device_key, signing, hashlib.sha256).hexdigest(),
            })
        kwargs = {"timeout": timeout} if timeout is not None else {}
        return self._client.post(f"{self.server_url}{path}", content=body, headers=headers, **kwargs)

    def renew_lease(self, _retry: bool = False) -> Optional[bool]:
        """
        Renew the current key lease with a fresh presence token.
        Returns True (renewed), False (denied by server) or None (no answer).
        """
        if not self.pakl or not self.lease_id:
            return True
        body = {
            "badge_mac": self.badge_mac,
            "device_hostname": self.device_hostname,
            "lease_id": self.lease_id,
            "presence_token": self._current_token(),
        }
        if self.cr_enabled and self.pending_challenge:
            body["cr"] = self._answer_challenge(self.pending_challenge)
            self.pending_challenge = None
        # Never wait past the end of the lease: an unanswered renewal must not
        # hold off the lease-expiry lock in the agent's lease tick.
        timeout = RENEW_TIMEOUT_S
        if self.lease_ttl > 0:
            left = self.lease_ttl - (time.time() - self.last_lease_ok)
            timeout = min(RENEW_TIMEOUT_S, max(0.05, left + 0.05))
        t0 = time.time()
        try:
            response = self._post("/api/keys/renew", body, timeout=timeout)
        except Exception as e:
            trace.event("lease_renew_error", error=type(e).__name__)
            logger.warning(f"Lease renewal failed (no answer): {e}")
            return None

        rtt_ms = (time.time() - t0) * 1000
        if response.status_code != 200:
            trace.event("lease_renew_error", status=response.status_code, rtt_ms=round(rtt_ms, 2))
            logger.warning(f"Lease renewal HTTP {response.status_code}")
            # Auth failures are definitive; server errors are treated as no answer
            return False if response.status_code in (401, 403) else None

        data = response.json()
        self.pending_challenge = data.get("challenge") or self.pending_challenge
        if data.get("renewed"):
            self.last_lease_ok = time.time()
            trace.event("lease_renew_ok", rtt_ms=round(rtt_ms, 2))
            return True
        if data.get("retry") and not _retry and self.cr_enabled and self.pending_challenge:
            # Server allows one immediate retry when the answer was genuine but slow
            trace.event("lease_renew_retry", message=data.get("message", ""), rtt_ms=round(rtt_ms, 2))
            logger.info(f"Lease renewal: {data.get('message', '')} - retrying with a fresh challenge")
            return self.renew_lease(_retry=True)
        trace.event("lease_renew_denied", message=data.get("message", ""), rtt_ms=round(rtt_ms, 2))
        logger.warning(f"🚫 Lease renewal denied: {data.get('message', '')}")
        return False

    def _answer_challenge(self, nonce: str) -> Optional[dict]:
        """Have the anchor relay the challenge to the badge and time the answer."""
        if not self.cr_provider:
            return None
        res = self.cr_provider(nonce)
        if res is None:
            trace.event("cr_result", ok=False, err="no_answer")
            return None
        trace.event("cr_result", ok=True, rtt_us=res.get("rtt_us"))
        return res

    def lease_expired(self) -> bool:
        """True if the lease has not been renewed within its TTL (fail-closed)."""
        if not self.pakl or not self.lease_id or self.lease_ttl <= 0:
            return False
        return time.time() - self.last_lease_ok > self.lease_ttl

    def end_lease(self):
        self.lease_id = None
        self.lease_ttl = 0.0
        self.pending_challenge = None

    def generate_key(self, filename: str) -> bytes:
        """
        Generate a new key and store it on the server.
        Overrides parent to add server upload.
        """
        key = super().generate_key(filename)

        # Upload to server (best-effort — key is still in memory)
        self.store_key(filename, key)

        return key

    def close(self):
        """Clean up HTTP client."""
        try:
            self._client.close()
        except Exception:
            pass
