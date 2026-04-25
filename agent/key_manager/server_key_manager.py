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
import logging
import socket
from typing import Optional

import httpx

from .key_manager import EphemeralKeyManager

logger = logging.getLogger("spaze-agent.server-keymgr")


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
    ):
        # No local keystore in server mode
        super().__init__(keystore_path=None)

        self.server_url = server_url.rstrip("/")
        self.badge_mac = badge_mac
        self.device_hostname = device_hostname or socket.gethostname()
        self._authorized = False

        # HTTP client with timeout
        self._client = httpx.Client(timeout=10.0)

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
            response = self._client.post(
                f"{self.server_url}/api/keys/request",
                json={
                    "badge_mac": self.badge_mac,
                    "device_hostname": self.device_hostname,
                },
            )

            if response.status_code != 200:
                logger.error(f"Key request failed: HTTP {response.status_code}")
                self._authorized = False
                return False

            data = response.json()
            self._authorized = data.get("authorized", False)

            if not self._authorized:
                message = data.get("message", "Access denied")
                logger.warning(f"🚫 Server denied access: {message}")
                return False

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
            response = self._client.post(
                f"{self.server_url}/api/keys/store",
                json={
                    "badge_mac": self.badge_mac,
                    "device_hostname": self.device_hostname,
                    "file_path": file_path,
                    "encrypted_fek": base64.b64encode(key).decode("utf-8"),
                },
            )

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
            response = self._client.post(
                f"{self.server_url}/api/keys/delete",
                json={
                    "badge_mac": self.badge_mac,
                    "device_hostname": self.device_hostname,
                    "file_path": file_path,
                },
            )

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

            response = self._client.post(
                f"{self.server_url}/api/audit/log",
                json=payload,
            )

            if response.status_code == 200:
                logger.debug(f"Audit logged: {action}")
                return True
            else:
                logger.warning(f"Audit log failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")
            return False

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
