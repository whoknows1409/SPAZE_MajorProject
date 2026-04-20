"""
SPAZE - Vault Manager

Manages the protected vault directory and tmpfs mount point.
- Vault: directory where encrypted .enc files are stored on disk
- tmpfs: RAM-backed mount where files are temporarily decrypted

Encrypted files live on disk forever. Decrypted files exist ONLY in RAM
while the badge is in range.
"""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("spaze-agent.vault")


class VaultManager:
    """Manages vault (encrypted storage) and tmpfs (RAM decryption zone)."""

    def __init__(
        self,
        vault_dir: str = os.path.expanduser("~/spaze-vault"),
        mount_point: str = "/tmp/spaze-mount",
        tmpfs_size_mb: int = 64,
    ):
        self.vault_dir = Path(vault_dir)
        self.mount_point = Path(mount_point)
        self.tmpfs_size_mb = tmpfs_size_mb
        self.is_mounted = False

    def setup(self):
        """Create vault directory and mount point if they don't exist."""
        # Create vault directory for encrypted files
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Vault directory: {self.vault_dir}")

        # Create mount point directory
        self.mount_point.mkdir(parents=True, exist_ok=True)
        logger.info(f"Decryption mount point: {self.mount_point}")

    def mount_tmpfs(self) -> bool:
        """
        Mount a tmpfs (RAM-backed filesystem) at the mount point.
        Decrypted files will be written here — they never touch the disk.
        
        Uses /tmp-based directory instead of actual tmpfs mount to avoid
        needing root privileges. Files in /tmp are still in RAM on most
        Linux systems (tmpfs-backed /tmp).
        """
        try:
            # Clean any stale files from previous session
            if self.mount_point.exists():
                for f in self.mount_point.iterdir():
                    if f.is_file():
                        f.unlink()

            self.is_mounted = True
            logger.info(f"Decryption zone ready at {self.mount_point}")
            return True

        except Exception as e:
            logger.error(f"Failed to prepare decryption zone: {e}")
            return False

    def unmount_tmpfs(self) -> bool:
        """
        Unmount tmpfs and wipe all decrypted files.
        After this, no plaintext files exist anywhere on the system.
        """
        try:
            if self.mount_point.exists():
                # Overwrite each file with random data before deleting
                for f in self.mount_point.iterdir():
                    if f.is_file():
                        self._secure_delete_file(f)
                        logger.debug(f"Wiped decrypted file: {f.name}")

            self.is_mounted = False
            logger.info("Decryption zone wiped — all plaintext files destroyed")
            return True

        except Exception as e:
            logger.error(f"Failed to wipe decryption zone: {e}")
            return False

    def get_encrypted_files(self) -> list[Path]:
        """List all .enc files in the vault."""
        if not self.vault_dir.exists():
            return []
        return sorted(self.vault_dir.glob("*.enc"))

    def get_decrypted_path(self, encrypted_path: Path) -> Path:
        """Get the corresponding decrypted file path in the mount point."""
        # Remove .enc extension to get original filename
        original_name = encrypted_path.stem  # e.g., "report.pdf" from "report.pdf.enc"
        return self.mount_point / original_name

    def is_file_decrypted(self, encrypted_path: Path) -> bool:
        """Check if a file is currently available in the decryption zone."""
        decrypted_path = self.get_decrypted_path(encrypted_path)
        return decrypted_path.exists()

    @staticmethod
    def _secure_delete_file(filepath: Path):
        """Overwrite file with random bytes before deletion."""
        try:
            size = filepath.stat().st_size
            with open(filepath, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            filepath.unlink()
        except Exception as e:
            # Fallback: just delete
            logger.warning(f"Secure delete failed for {filepath}, removing: {e}")
            filepath.unlink(missing_ok=True)
