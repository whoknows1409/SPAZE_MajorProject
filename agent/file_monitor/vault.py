"""
SPAZE - Vault Manager (Secure RAM Workspace)

Manages the protected vault directory and tmpfs mount point.
- Vault: directory where encrypted .enc files are stored on disk
- tmpfs: RAM-backed mount where files are temporarily decrypted

Security features:
- Real tmpfs mount (files never touch disk)
- Mount options: noexec, nosuid, nodev (hardened)
- Permissions: mode=700 (owner-only access)
- Swap disabled to prevent RAM leaks to disk
- Stale mount cleanup on startup
- Open file detection before unmount
- Secure delete: files overwritten with random data before removal

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
        mount_point: str = os.path.expanduser("~/spaze"),
        tmpfs_size_mb: int = 256,
    ):
        self.vault_dir = Path(vault_dir)
        self.mount_point = Path(mount_point)
        self.tmpfs_size_mb = tmpfs_size_mb
        self.is_mounted = False
        self._using_real_tmpfs = False
        self._swap_was_on = False

    def setup(self):
        """Create vault directory and mount point if they don't exist."""
        # Create vault directory for encrypted files
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Vault directory: {self.vault_dir}")

        # Create mount point directory
        self.mount_point.mkdir(parents=True, exist_ok=True)
        logger.info(f"Decryption mount point: {self.mount_point}")

        # Clean up stale mounts from previous crashes
        self._cleanup_stale_mount()

        # Remove any rogue files left in the bare directory
        # (e.g., files saved while vault was locked and directory was accessible)
        if not self._is_tmpfs_mounted():
            self._clean_rogue_files()
            # Lock the directory — no access until vault is unlocked
            self._lock_mount_point()

    # ===========================================================
    # MOUNT / UNMOUNT
    # ===========================================================

    def mount_tmpfs(self) -> bool:
        """
        Mount a tmpfs (RAM-backed filesystem) at the mount point.
        Decrypted files will be written here — they never touch the disk.

        Also disables swap to prevent RAM data leaking to disk.
        """
        # If already mounted, just clean stale files
        if self.is_mounted:
            self._clean_stale_files()
            return True

        # Disable swap before decryption
        self._disable_swap()

        # Unlock the directory so tmpfs can mount on it
        self._unlock_mount_point()

        # Try real tmpfs mount
        if self._mount_real_tmpfs():
            self._using_real_tmpfs = True
            self.is_mounted = True
            logger.info(f"✅ Secure tmpfs mounted at {self.mount_point}")
            logger.info(f"   Options: size={self.tmpfs_size_mb}m, noexec, nosuid, nodev, mode=700")
            logger.info(f"   Swap: {'disabled ✅' if self._swap_was_on else 'already off ✅'}")
            return True

        # Fallback: use directory as-is (with warnings)
        logger.warning("=" * 50)
        logger.warning("⚠️  Could not mount real tmpfs!")
        logger.warning("   Falling back to regular directory.")
        logger.warning("   Files may not be purely RAM-backed.")
        logger.warning("   Run: sudo bash scripts/setup_sudoers.sh")
        logger.warning("=" * 50)

        self._clean_stale_files()
        self._using_real_tmpfs = False
        self.is_mounted = True

        # At minimum, set restrictive permissions on the directory
        try:
            os.chmod(str(self.mount_point), 0o700)
        except Exception:
            pass

        return True

    def unmount_tmpfs(self) -> bool:
        """
        Unmount tmpfs and wipe all decrypted files.
        After this, no plaintext files exist anywhere on the system.

        Checks for open files first and warns if any are found.
        """
        try:
            # Check for processes using the mount point
            open_procs = self._get_open_file_processes()
            if open_procs:
                logger.warning(f"⚠️  {len(open_procs)} process(es) still using files in mount:")
                for pid, name, filepath in open_procs:
                    logger.warning(f"   PID {pid} ({name}): {filepath}")
                # Kill processes holding files open
                self._kill_open_file_processes(open_procs)

            if self.mount_point.exists():
                # Overwrite each file with random data before deleting
                for f in self.mount_point.iterdir():
                    if f.is_file():
                        self._secure_delete_file(f)
                        logger.debug(f"Wiped decrypted file: {f.name}")

            # Unmount real tmpfs if we mounted one
            if self._using_real_tmpfs and self._is_tmpfs_mounted():
                self._unmount_real_tmpfs()

            # Re-enable swap
            self._enable_swap()

            self.is_mounted = False
            self._using_real_tmpfs = False

            # SECURITY: Lock the directory so no files can be written
            # to the bare disk directory while vault is locked
            self._lock_mount_point()

            logger.info("Decryption zone wiped — all plaintext files destroyed")
            return True

        except Exception as e:
            logger.error(f"Failed to wipe decryption zone: {e}")
            # Always re-enable swap even on failure
            self._enable_swap()
            # Still try to lock the directory
            self._lock_mount_point()
            return False

    # ===========================================================
    # SWAP MANAGEMENT
    # ===========================================================

    def _disable_swap(self):
        """Disable swap to prevent decrypted data from leaking to disk."""
        try:
            # Check if swap is currently on
            result = subprocess.run(
                ["swapon", "--show", "--noheadings"],
                capture_output=True, text=True, timeout=3,
            )
            if result.stdout.strip():
                self._swap_was_on = True
                subprocess.run(
                    ["sudo", "-n", "swapoff", "-a"],
                    capture_output=True, timeout=5,
                )
                logger.info("🔒 Swap disabled (preventing RAM→disk leaks)")
            else:
                self._swap_was_on = False
                logger.debug("Swap already off")
        except Exception as e:
            logger.warning(f"Could not disable swap: {e}")
            self._swap_was_on = False

    def _enable_swap(self):
        """Re-enable swap after vault is locked."""
        if not self._swap_was_on:
            return
        try:
            subprocess.run(
                ["sudo", "-n", "swapon", "-a"],
                capture_output=True, timeout=5,
            )
            logger.info("Swap re-enabled")
            self._swap_was_on = False
        except Exception as e:
            logger.warning(f"Could not re-enable swap: {e}")

    # ===========================================================
    # OPEN FILE DETECTION
    # ===========================================================

    def _get_open_file_processes(self) -> list[tuple[int, str, str]]:
        """
        Check if any processes have files open in the mount point.
        Returns list of (pid, process_name, filepath).
        Uses lsof first, then fuser as fallback.
        """
        procs = []

        # Method 1: lsof (detailed — gives process name + file path)
        try:
            result = subprocess.run(
                ["lsof", "+D", str(self.mount_point)],
                capture_output=True, text=True, timeout=10,
            )
            # lsof returns exit code 1 even when it finds results (with warnings)
            # so we check stdout content, NOT the exit code
            if result.stdout.strip():
                for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 9:
                        name = parts[0]
                        try:
                            pid = int(parts[1])
                        except ValueError:
                            continue
                        filepath = parts[8] if len(parts) > 8 else "unknown"
                        procs.append((pid, name, filepath))

            if procs:
                return procs

        except Exception as e:
            logger.debug(f"lsof check failed: {e}")

        # Method 2: fuser (simpler — just gives PIDs)
        try:
            result = subprocess.run(
                ["fuser", "-m", str(self.mount_point)],
                capture_output=True, text=True, timeout=5,
            )
            # fuser outputs PIDs to stderr
            pid_str = result.stderr.strip() if result.stderr else result.stdout.strip()
            if pid_str:
                for token in pid_str.split():
                    token = token.strip("abcdefghijklmnopqrstuvwxyz")  # strip mode suffixes
                    try:
                        pid = int(token)
                        # Get process name from /proc
                        try:
                            with open(f"/proc/{pid}/comm") as f:
                                name = f.read().strip()
                        except Exception:
                            name = "unknown"
                        procs.append((pid, name, str(self.mount_point)))
                    except ValueError:
                        continue

        except Exception as e:
            logger.debug(f"fuser check failed: {e}")

        return procs

    def _kill_open_file_processes(self, procs: list[tuple[int, str, str]]):
        """Send SIGTERM to processes holding files open, then SIGKILL if needed."""
        import signal
        import time

        pids = set(pid for pid, _, _ in procs)
        my_pid = os.getpid()

        # Don't kill ourselves
        pids.discard(my_pid)

        if not pids:
            return

        logger.info(f"   Terminating {len(pids)} process(es) holding files open...")

        # First try SIGTERM (graceful)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                logger.info(f"   Sent SIGTERM to PID {pid}")
            except ProcessLookupError:
                pass
            except PermissionError:
                logger.warning(f"   Cannot kill PID {pid} (permission denied)")

        # Wait for processes to exit gracefully (LibreOffice needs time)
        time.sleep(3)

        # Force kill any remaining
        killed = 0
        for pid in pids:
            try:
                os.kill(pid, 0)  # Check if still alive
                os.kill(pid, signal.SIGKILL)
                killed += 1
                logger.warning(f"   Force-killed PID {pid}")
            except ProcessLookupError:
                pass  # Already dead
            except PermissionError:
                logger.warning(f"   Cannot force-kill PID {pid}")

        if killed:
            time.sleep(1)  # Brief wait for SIGKILL to take effect

        logger.info(f"   All file-holding processes terminated")

    # ===========================================================
    # STALE MOUNT CLEANUP
    # ===========================================================

    def _cleanup_stale_mount(self):
        """
        Clean up leftover mounts from previous crashes.
        Called during setup() to ensure a clean state on startup.
        """
        if self._is_tmpfs_mounted():
            logger.warning("⚠️  Found stale tmpfs mount from previous session")

            # Wipe any leftover files
            if self.mount_point.exists():
                for f in self.mount_point.iterdir():
                    if f.is_file():
                        self._secure_delete_file(f)

            # Unmount the stale mount
            self._unmount_real_tmpfs()
            logger.info("✅ Cleaned up stale mount")

    # ===========================================================
    # TMPFS INTERNAL OPERATIONS
    # ===========================================================

    def _mount_real_tmpfs(self) -> bool:
        """Attempt to mount a real tmpfs filesystem."""
        uid = os.getuid()
        mount_opts = (
            f"size={self.tmpfs_size_mb}m,"
            f"noexec,nosuid,nodev,"
            f"mode=700,"
            f"uid={uid}"
        )

        try:
            # Check if already mounted
            if self._is_tmpfs_mounted():
                logger.debug("tmpfs already mounted")
                return True

            result = subprocess.run(
                [
                    "sudo", "-n",  # non-interactive (no password prompt)
                    "mount", "-t", "tmpfs",
                    "-o", mount_opts,
                    "spaze-tmpfs",
                    str(self.mount_point),
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                return True
            else:
                logger.debug(f"Mount failed: {result.stderr.strip()}")
                return False

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"Mount attempt failed: {e}")
            return False

    def _is_tmpfs_mounted(self) -> bool:
        """Check if our tmpfs is currently mounted."""
        try:
            result = subprocess.run(
                ["mountpoint", "-q", str(self.mount_point)],
                capture_output=True,
                timeout=3,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _unmount_real_tmpfs(self):
        """Unmount the real tmpfs filesystem."""
        try:
            # First try normal umount
            result = subprocess.run(
                ["sudo", "-n", "umount", str(self.mount_point)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("tmpfs unmounted successfully")
                return

            # If busy, try lazy umount
            logger.warning("Normal umount failed, trying lazy umount...")
            subprocess.run(
                ["sudo", "-n", "umount", "-l", str(self.mount_point)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            logger.info("tmpfs lazy-unmounted")

        except Exception as e:
            logger.error(f"Failed to unmount tmpfs: {e}")

    def _clean_stale_files(self):
        """Remove any stale files from previous sessions."""
        if self.mount_point.exists():
            for f in self.mount_point.iterdir():
                if f.is_file():
                    f.unlink()

    def _clean_rogue_files(self):
        """
        Remove any files that were saved to the bare mount point directory
        while the vault was locked. These files sit on disk unencrypted —
        a security risk.
        """
        if not self.mount_point.exists():
            return
        try:
            # Temporarily make directory accessible to clean it
            os.chmod(str(self.mount_point), 0o700)
        except Exception:
            pass

        rogue_count = 0
        for f in self.mount_point.iterdir():
            if f.is_file():
                logger.warning(f"⚠️  Rogue file found in locked mount: {f.name} — removing")
                self._secure_delete_file(f)
                rogue_count += 1
        if rogue_count > 0:
            logger.warning(
                f"🗑️  Removed {rogue_count} rogue file(s) from mount point. "
                f"These were saved while the vault was locked."
            )

    def _lock_mount_point(self):
        """
        Make the mount point directory completely inaccessible.
        Prevents users/apps from saving plaintext files to the bare
        directory when tmpfs is not mounted.
        
        chmod 000 = no read, no write, no execute for anyone.
        """
        try:
            os.chmod(str(self.mount_point), 0o000)
            logger.info(f"🔒 Mount point locked (chmod 000): {self.mount_point}")
        except Exception as e:
            logger.warning(f"Could not lock mount point: {e}")

    def _unlock_mount_point(self):
        """
        Restore permissions on the mount point so tmpfs can be mounted
        and the user can access decrypted files.
        
        chmod 700 = owner read+write+execute only.
        """
        try:
            os.chmod(str(self.mount_point), 0o700)
            logger.debug(f"Mount point unlocked (chmod 700): {self.mount_point}")
        except Exception as e:
            logger.warning(f"Could not unlock mount point: {e}")

    # ===========================================================
    # FILE HELPERS
    # ===========================================================

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

    def get_mount_info(self) -> dict:
        """Return mount status info for diagnostics."""
        return {
            "mount_point": str(self.mount_point),
            "is_mounted": self.is_mounted,
            "real_tmpfs": self._using_real_tmpfs,
            "tmpfs_active": self._is_tmpfs_mounted(),
            "size_mb": self.tmpfs_size_mb,
            "swap_disabled": self._swap_was_on,
        }

    @staticmethod
    def _secure_delete_file(filepath: Path):
        """Overwrite file with random bytes before deletion."""
        try:
            size = filepath.stat().st_size
            if size > 0:
                with open(filepath, "wb") as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            filepath.unlink()
        except Exception as e:
            # Fallback: just delete
            logger.warning(f"Secure delete failed for {filepath}, removing: {e}")
            filepath.unlink(missing_ok=True)
