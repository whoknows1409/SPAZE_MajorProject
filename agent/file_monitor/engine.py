"""
SPAZE - File Encryption Engine

Orchestrates file encryption/decryption using:
- AES-256-GCM (crypto.py)
- Vault Manager (vault.py)  
- Ephemeral Key Manager (key_manager.py)

Provides high-level operations:
- encrypt_vault(): encrypt all plaintext files in the vault
- decrypt_vault(): decrypt all .enc files to tmpfs (RAM)
- lock_vault(): wipe keys + remove decrypted files
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

from .crypto import encrypt_file, decrypt_file_to_memory, secure_wipe_bytes
from .vault import VaultManager
from ..key_manager.key_manager import EphemeralKeyManager

logger = logging.getLogger("spaze-agent.engine")


class FileEncryptionEngine:
    """
    High-level encryption engine that ties together crypto, vault, and keys.
    
    Lifecycle:
    1. User drops file into vault/ → auto-encrypt
    2. Badge comes in range → decrypt_vault() → files appear in tmpfs
    3. Badge leaves range → lock_vault() → files vanish, keys wiped
    """

    def __init__(
        self,
        vault_dir: str = os.path.expanduser("~/spaze-vault"),
        mount_point: str = "/tmp/spaze-mount",
    ):
        self.vault = VaultManager(vault_dir=vault_dir, mount_point=mount_point)
        self.key_manager = EphemeralKeyManager(
            keystore_path=os.path.join(vault_dir, ".keys.json")
        )
        self._is_unlocked = False
        # SHA-256 hashes of decrypted files at time of decryption
        # Used to detect modifications before locking
        self._file_hashes: dict[str, str] = {}

    def setup(self):
        """Initialize vault directory and mount point."""
        self.vault.setup()
        logger.info("File Encryption Engine initialized")
        logger.info(f"  Vault: {self.vault.vault_dir}")
        logger.info(f"  Decryption zone: {self.vault.mount_point}")

    def encrypt_new_file(self, filepath: str) -> Optional[str]:
        """
        Encrypt a new plaintext file and move it to the vault.
        Returns the path to the encrypted file, or None on failure.
        """
        filepath = Path(filepath)

        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return None

        if filepath.suffix == ".enc":
            logger.debug(f"Already encrypted: {filepath}")
            return str(filepath)

        filename = filepath.name
        logger.info(f"Encrypting: {filename}")

        try:
            # Generate a key for this file
            key = self.key_manager.generate_key(filename + ".enc")

            # Encrypt the file (writes .enc, securely deletes original)
            encrypted_path = encrypt_file(str(filepath), key)
            
            # Move to vault if not already there
            encrypted_file = Path(encrypted_path)
            vault_path = self.vault.vault_dir / encrypted_file.name
            
            if encrypted_file.parent != self.vault.vault_dir:
                import shutil
                shutil.move(str(encrypted_file), str(vault_path))
                encrypted_path = str(vault_path)

            logger.info(f"Encrypted → {vault_path.name}")
            return encrypted_path

        except Exception as e:
            logger.error(f"Encryption failed for {filename}: {e}")
            return None

    def decrypt_vault(self) -> int:
        """
        Decrypt all .enc files in the vault to the tmpfs mount point.
        Returns the number of files successfully decrypted.
        """
        if self._is_unlocked:
            logger.debug("Vault already unlocked")
            return 0

        # Prepare the decryption zone
        if not self.vault.mount_tmpfs():
            return 0

        encrypted_files = self.vault.get_encrypted_files()
        if not encrypted_files:
            logger.info("No encrypted files in vault")
            self._is_unlocked = True
            return 0

        self._file_hashes.clear()
        decrypted_count = 0

        for enc_file in encrypted_files:
            try:
                # Get the key for this file
                key = self.key_manager.get_key(enc_file.name)
                if key is None:
                    logger.warning(f"No key found for {enc_file.name}, skipping")
                    continue

                # Decrypt to memory
                plaintext = decrypt_file_to_memory(str(enc_file), key)

                # Write to tmpfs (RAM)
                decrypted_path = self.vault.get_decrypted_path(enc_file)
                with open(decrypted_path, "wb") as f:
                    f.write(plaintext)

                # Store hash of original content for change detection
                file_hash = hashlib.sha256(plaintext).hexdigest()
                self._file_hashes[str(decrypted_path)] = file_hash

                # Wipe plaintext from Python memory
                if isinstance(plaintext, bytearray):
                    secure_wipe_bytes(plaintext)

                decrypted_count += 1
                logger.info(f"Decrypted → {decrypted_path.name} (in RAM)")

            except Exception as e:
                logger.error(f"Failed to decrypt {enc_file.name}: {e}")

        self._is_unlocked = True
        logger.info(
            f"Vault unlocked: {decrypted_count}/{len(encrypted_files)} files decrypted to RAM"
        )
        return decrypted_count

    def _sync_modified_files(self):
        """
        Check if any decrypted files were modified by the user.
        If so, re-encrypt them back to the vault before wiping.
        """
        if not self.vault.mount_point.exists():
            return

        for decrypted_file in self.vault.mount_point.iterdir():
            if not decrypted_file.is_file():
                continue

            filepath_str = str(decrypted_file)
            original_hash = self._file_hashes.get(filepath_str)

            if original_hash is None:
                # New file created in mount point — encrypt it
                logger.info(f"New file detected: {decrypted_file.name}, encrypting...")
                self._re_encrypt_file(decrypted_file)
                continue

            # Compare current hash with original
            try:
                current_content = decrypted_file.read_bytes()
                current_hash = hashlib.sha256(current_content).hexdigest()

                if current_hash != original_hash:
                    logger.info(f"Modified file detected: {decrypted_file.name}, re-encrypting...")
                    self._re_encrypt_file(decrypted_file, current_content)
                else:
                    logger.debug(f"Unchanged: {decrypted_file.name}")
            except Exception as e:
                logger.error(f"Error checking {decrypted_file.name}: {e}")

        self._file_hashes.clear()

    def _re_encrypt_file(self, decrypted_path: Path, content: bytes = None):
        """Re-encrypt a modified file back to the vault."""
        try:
            enc_filename = decrypted_path.name + ".enc"
            key = self.key_manager.get_key(enc_filename)

            if key is None:
                # New file — generate a key
                key = self.key_manager.generate_key(enc_filename)

            if content is None:
                content = decrypted_path.read_bytes()

            # Encrypt using AES-256-GCM
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os as _os
            nonce = _os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, content, associated_data=None)

            # Write updated .enc file to vault
            vault_enc_path = self.vault.vault_dir / enc_filename
            with open(vault_enc_path, "wb") as f:
                f.write(nonce)
                f.write(ciphertext)

            logger.info(f"Re-encrypted → {enc_filename}")

        except Exception as e:
            logger.error(f"Failed to re-encrypt {decrypted_path.name}: {e}")

    def lock_vault(self) -> bool:
        """
        Lock the vault:
        1. Sync modified files back to vault (re-encrypt changes)
        2. Wipe all decrypted files from tmpfs
        3. Wipe all encryption keys from memory
        
        After this, files are ONLY available as .enc ciphertext on disk.
        """
        logger.info("LOCKING VAULT...")

        # Step 1: Re-encrypt any files the user modified
        self._sync_modified_files()

        # Step 2: Wipe decrypted files from RAM
        self.vault.unmount_tmpfs()

        # Step 3: Wipe all keys from memory
        self.key_manager.wipe_all_keys()

        self._is_unlocked = False
        logger.info("Vault LOCKED — all plaintext destroyed, all keys wiped")
        return True

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked

    def get_status(self) -> dict:
        """Return current engine status."""
        encrypted_files = self.vault.get_encrypted_files()
        return {
            "is_unlocked": self._is_unlocked,
            "encrypted_files": len(encrypted_files),
            "keys_in_memory": self.key_manager.key_count,
            "vault_dir": str(self.vault.vault_dir),
            "mount_point": str(self.vault.mount_point),
        }
