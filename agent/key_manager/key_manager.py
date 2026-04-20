"""
SPAZE - Ephemeral Key Manager

Manages File Encryption Keys (FEKs) in memory.
- Generates keys for new files
- Stores keys ONLY in RAM (never persisted to disk)
- Securely wipes all keys when badge leaves range

In Phase 3, keys will be fetched from the server instead of generated locally.
For Phase 2 (standalone mode), keys are generated and stored locally in a
JSON keyfile within the vault directory.
"""

import json
import logging
import os
import base64
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("spaze-agent.keymgr")


class EphemeralKeyManager:
    """
    Manages ephemeral File Encryption Keys in memory.
    
    Keys are stored as bytearrays (mutable) so they can be
    zeroed out from memory on wipe.
    """

    def __init__(self, keystore_path: Optional[str] = None):
        # Active keys in memory: {filename: bytearray(key)}
        self._keys: dict[str, bytearray] = {}
        # Path to persist key mappings (Phase 2 standalone only)
        # In Phase 3, this is replaced by server API calls
        self.keystore_path = Path(keystore_path) if keystore_path else None

        # Load existing keys from keystore at startup
        # This prevents overwriting old keys when encrypting new files
        if self.keystore_path:
            self._load_keystore()

    def generate_key(self, filename: str) -> bytes:
        """Generate a new AES-256 key for a file and store in memory."""
        key = AESGCM.generate_key(bit_length=256)
        self._keys[filename] = bytearray(key)
        logger.info(f"Generated key for: {filename}")

        # Persist mapping (Phase 2 standalone)
        if self.keystore_path:
            self._save_keystore()

        return bytes(self._keys[filename])

    def get_key(self, filename: str) -> Optional[bytes]:
        """Retrieve a key from memory. Returns None if not found."""
        key = self._keys.get(filename)
        if key is None:
            # Try loading from keystore (Phase 2 standalone)
            if self.keystore_path:
                self._load_keystore()
                key = self._keys.get(filename)
        return bytes(key) if key else None

    def has_key(self, filename: str) -> bool:
        """Check if a key exists for the given file."""
        return filename in self._keys

    def wipe_all_keys(self):
        """
        Securely wipe ALL keys from memory.
        Overwrites each byte with 0x00 before clearing the dict.
        """
        count = len(self._keys)
        for filename, key in self._keys.items():
            # Zero out every byte
            for i in range(len(key)):
                key[i] = 0
            logger.debug(f"Wiped key for: {filename}")

        self._keys.clear()
        logger.info(f"Wiped {count} keys from memory")

    def wipe_key(self, filename: str):
        """Securely wipe a single key from memory."""
        key = self._keys.get(filename)
        if key:
            for i in range(len(key)):
                key[i] = 0
            del self._keys[filename]
            logger.debug(f"Wiped key for: {filename}")

    @property
    def key_count(self) -> int:
        return len(self._keys)

    def _save_keystore(self):
        """
        Persist keys to disk (Phase 2 standalone only).
        In Phase 3, keys come from the server and are never stored locally.
        
        WARNING: This is only for Phase 2 development.
        In production, keys should NEVER be persisted to disk.
        """
        if not self.keystore_path:
            return
        try:
            data = {}
            for filename, key in self._keys.items():
                data[filename] = base64.b64encode(bytes(key)).decode("utf-8")

            self.keystore_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.keystore_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Keystore saved: {self.keystore_path}")
        except Exception as e:
            logger.error(f"Failed to save keystore: {e}")

    def _load_keystore(self):
        """Load keys from disk keystore (Phase 2 standalone only)."""
        if not self.keystore_path or not self.keystore_path.exists():
            return
        try:
            with open(self.keystore_path, "r") as f:
                data = json.load(f)

            for filename, key_b64 in data.items():
                if filename not in self._keys:
                    self._keys[filename] = bytearray(base64.b64decode(key_b64))

            logger.debug(f"Loaded {len(data)} keys from keystore")
        except Exception as e:
            logger.error(f"Failed to load keystore: {e}")
