"""
SPAZE - File Encryption Engine

Orchestrates file encryption/decryption using:
- AES-256-GCM (crypto.py)
- Vault Manager (vault.py)  
- Ephemeral Key Manager (key_manager.py)

Production features:
- Delete tracking: files removed in RAM are removed from vault
- Temp file filtering: ignores LibreOffice .~lock, .swp, ~ files
- Safe write: uses temp→rename to prevent corruption
- Hash-based change detection for efficient re-encryption
"""

import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from .crypto import encrypt_file, decrypt_file_to_memory, secure_wipe_bytes
from .vault import VaultManager
from ..key_manager.key_manager import EphemeralKeyManager

logger = logging.getLogger("spaze-agent.engine")

# Patterns for temp/lock files that should be ignored during sync
TEMP_FILE_PATTERNS = {
    ".~lock.",      # LibreOffice lock files (.~lock.report.odt#)
    "~$",           # MS Office lock files (~$report.docx)
}
TEMP_FILE_SUFFIXES = {
    ".tmp", ".swp", ".swo", ".swn",   # Vim swap, generic temp
    ".bak", ".kate-swp",              # Editor backups
    ".crdownload", ".part",           # Partial downloads
}


def _is_temp_file(filename: str) -> bool:
    """Check if a filename matches known temp/lock file patterns."""
    # Check prefix patterns
    for pattern in TEMP_FILE_PATTERNS:
        if filename.startswith(pattern):
            return True
    # Check suffix patterns
    for suffix in TEMP_FILE_SUFFIXES:
        if filename.endswith(suffix):
            return True
    # Backup files ending with ~
    if filename.endswith("~"):
        return True
    return False


class FileEncryptionEngine:
    """
    High-level encryption engine that ties together crypto, vault, and keys.
    
    Lifecycle:
    1. User drops file into vault/ → auto-encrypt
    2. Badge comes in range → decrypt_vault() → files appear in tmpfs
    3. Badge leaves range → lock_vault() → files vanish, keys wiped

    Sync operations on lock:
    - Modified files → re-encrypted to vault
    - New files → encrypted and added to vault
    - Deleted files → .enc removed from vault
    - Temp files → ignored (not encrypted)
    """

    def __init__(
        self,
        vault_dir: str = os.path.expanduser("~/spaze-vault"),
        mount_point: str = os.path.expanduser("~/spaze"),
        server_url: Optional[str] = None,
        badge_mac: Optional[str] = None,
    ):
        self.vault = VaultManager(vault_dir=vault_dir, mount_point=mount_point)
        self.server_mode = bool(server_url and badge_mac)

        if self.server_mode:
            from ..key_manager.server_key_manager import ServerKeyManager
            self.key_manager = ServerKeyManager(
                server_url=server_url,
                badge_mac=badge_mac,
            )
            logger.info("Key management: SERVER mode")
        else:
            self.key_manager = EphemeralKeyManager(
                keystore_path=os.path.join(vault_dir, ".keys.json")
            )
            logger.info("Key management: LOCAL mode (.keys.json)")

        self._is_unlocked = False
        # SHA-256 hashes of decrypted files at time of decryption
        # Used to detect modifications before locking
        self._file_hashes: dict[str, str] = {}
        # Track which files were decrypted (for delete detection)
        self._decrypted_filenames: set[str] = set()

    def setup(self):
        """Initialize vault directory and mount point."""
        self.vault.setup()
        logger.info("File Encryption Engine initialized")
        logger.info(f"  Vault: {self.vault.vault_dir}")
        logger.info(f"  Decryption zone: {self.vault.mount_point}")
        logger.info(f"  tmpfs size: {self.vault.tmpfs_size_mb} MB")

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

        # Skip temp files
        if _is_temp_file(filename):
            logger.debug(f"Skipping temp file: {filename}")
            return None

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

        # Server mode: fetch keys from server first
        if self.server_mode:
            if not self.key_manager.fetch_keys():
                logger.error("Server denied access — vault stays LOCKED")
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
        self._decrypted_filenames.clear()
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

                # Track for delete detection
                self._decrypted_filenames.add(decrypted_path.name)

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
        Sync all changes from RAM back to the vault before locking.
        Handles: modified files, new files, deleted files.
        Ignores: temp/lock files created by applications.
        """
        if not self.vault.mount_point.exists():
            return

        # Collect current files in mount point
        current_files = set()

        for decrypted_file in self.vault.mount_point.iterdir():
            if not decrypted_file.is_file():
                continue

            # Skip temp/lock files
            if _is_temp_file(decrypted_file.name):
                logger.debug(f"Ignoring temp file: {decrypted_file.name}")
                # Clean up temp files — don't leave them around
                try:
                    decrypted_file.unlink()
                except Exception:
                    pass
                continue

            current_files.add(decrypted_file.name)
            filepath_str = str(decrypted_file)
            original_hash = self._file_hashes.get(filepath_str)

            if original_hash is None:
                # New file created in mount point — encrypt it
                logger.info(f"📄 New file detected: {decrypted_file.name}, encrypting...")
                self._re_encrypt_file(decrypted_file)
                continue

            # Compare current hash with original
            try:
                current_content = decrypted_file.read_bytes()
                current_hash = hashlib.sha256(current_content).hexdigest()

                if current_hash != original_hash:
                    logger.info(f"✏️  Modified file: {decrypted_file.name}, re-encrypting...")
                    self._re_encrypt_file(decrypted_file, current_content)
                else:
                    logger.debug(f"Unchanged: {decrypted_file.name}")
            except Exception as e:
                logger.error(f"Error checking {decrypted_file.name}: {e}")

        # Detect deleted files: were in vault but no longer in mount point
        deleted_files = self._decrypted_filenames - current_files
        for deleted_name in deleted_files:
            enc_name = deleted_name + ".enc"
            enc_path = self.vault.vault_dir / enc_name
            if enc_path.exists():
                logger.info(f"🗑️  Deleted file detected: {deleted_name}, removing .enc from vault...")
                try:
                    enc_path.unlink()
                    # Remove key from server (if server mode) and memory
                    if self.server_mode:
                        self.key_manager.delete_key(enc_name)
                    self.key_manager.wipe_key(enc_name)
                    logger.info(f"  Removed {enc_name} and its key")
                except Exception as e:
                    logger.error(f"  Failed to remove {enc_name}: {e}")

        self._file_hashes.clear()
        self._decrypted_filenames.clear()

    def _re_encrypt_file(self, decrypted_path: Path, content: bytes = None):
        """
        Re-encrypt a modified file back to the vault.
        Uses safe write: writes to temp file first, then renames.
        """
        try:
            enc_filename = decrypted_path.name + ".enc"
            key = self.key_manager.get_key(enc_filename)

            if key is None:
                # New file — generate a key (auto-uploads to server in server mode)
                key = self.key_manager.generate_key(enc_filename)
            elif self.server_mode:
                # Existing file re-encrypted — update key on server
                self.key_manager.store_key(enc_filename, key)

            if content is None:
                content = decrypted_path.read_bytes()

            # Encrypt using AES-256-GCM
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os as _os
            nonce = _os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, content, associated_data=None)

            # SAFE WRITE: write to temp file, then atomic rename
            # Prevents corruption if power fails or process crashes mid-write
            vault_enc_path = self.vault.vault_dir / enc_filename
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=str(self.vault.vault_dir),
                prefix=".spaze_tmp_",
                suffix=".enc",
            )
            try:
                with os.fdopen(tmp_fd, "wb") as f:
                    f.write(nonce)
                    f.write(ciphertext)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename (same filesystem = atomic on Linux)
                os.replace(tmp_path, str(vault_enc_path))
                logger.info(f"Re-encrypted → {enc_filename}")

            except Exception:
                # Clean up temp file on failure
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

        except Exception as e:
            logger.error(f"Failed to re-encrypt {decrypted_path.name}: {e}")

    def lock_vault(self) -> bool:
        """
        Lock the vault:
        1. Sync modified/new/deleted files back to vault
        2. Wipe all decrypted files from tmpfs
        3. Wipe all encryption keys from memory
        
        After this, files are ONLY available as .enc ciphertext on disk.
        """
        logger.info("LOCKING VAULT...")

        # Step 1: Re-encrypt any files the user modified + track deletes
        self._sync_modified_files()

        # Step 2: Log vault lock event to server
        if self.server_mode:
            self.key_manager.log_event(
                action="vault_lock",
                details=f"Vault locked on {self.key_manager.device_hostname}",
            )

        # Step 3: Wipe decrypted files from RAM + unmount
        self.vault.unmount_tmpfs()

        # Step 4: Wipe all keys from memory
        self.key_manager.wipe_all_keys()

        # Step 5: Clean up any leftover temp files in vault
        self._clean_vault_temp_files()

        self._is_unlocked = False
        logger.info("Vault LOCKED — all plaintext destroyed, all keys wiped")
        return True

    def _clean_vault_temp_files(self):
        """Remove any temporary .spaze_tmp_ files left in vault from crashed writes."""
        for f in self.vault.vault_dir.iterdir():
            if f.name.startswith(".spaze_tmp_"):
                try:
                    f.unlink()
                    logger.debug(f"Cleaned up temp file: {f.name}")
                except Exception:
                    pass

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
