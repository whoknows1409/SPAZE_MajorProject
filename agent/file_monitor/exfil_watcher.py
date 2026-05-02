"""
SPAZE - Exfiltration Watcher

Monitors common user directories for files copied out of the vault.
When a file matching a vault filename is detected outside the vault,
the watcher:
  1. Logs a SECURITY ALERT to the server
  2. Deletes the exfiltrated copy immediately
  3. Emits a local warning

Watched directories:
  ~/Documents, ~/Downloads, ~/Desktop, /tmp, ~/Pictures, ~/Videos

This is a DLP (Data Loss Prevention) layer that prevents users from
copying decrypted files out of the protected tmpfs zone.
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional, Set, Callable

logger = logging.getLogger("spaze-agent.exfil-watcher")

# Directories where exfiltrated files might land
DEFAULT_WATCH_DIRS = [
    "~/Documents",
    "~/Downloads",
    "~/Desktop",
    "~/Pictures",
    "~/Videos",
    "~/Music",
    "/tmp",
]


class ExfiltrationWatcher:
    """
    Watches common directories for files that match vault contents.
    If a vault file appears outside the vault → alert + delete.
    """

    def __init__(
        self,
        vault_mount: str,
        watch_dirs: Optional[list[str]] = None,
        on_alert: Optional[Callable] = None,
        poll_interval: float = 2.0,
    ):
        self.vault_mount = Path(vault_mount)
        self.poll_interval = poll_interval
        self.on_alert = on_alert  # callback(filename, dest_path, action)

        # Resolve watch directories
        self._watch_dirs: list[Path] = []
        for d in (watch_dirs or DEFAULT_WATCH_DIRS):
            expanded = Path(os.path.expanduser(d))
            if expanded.exists() and expanded.is_dir():
                self._watch_dirs.append(expanded)

        self._vault_filenames: Set[str] = set()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Track files we've already alerted on (avoid duplicate alerts)
        self._alerted: Set[str] = set()

    def update_vault_files(self):
        """Refresh the set of filenames currently in the vault."""
        self._vault_filenames.clear()
        if self.vault_mount.exists():
            for f in self.vault_mount.iterdir():
                if f.is_file():
                    self._vault_filenames.add(f.name)

    def start(self):
        """Start the exfiltration watcher in a background thread."""
        if self._running:
            return

        self.update_vault_files()

        if not self._vault_filenames:
            logger.info("Exfil watcher: no vault files to protect")
            return

        if not self._watch_dirs:
            logger.warning("Exfil watcher: no valid directories to monitor")
            return

        self._running = True
        self._alerted.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

        dir_names = [str(d) for d in self._watch_dirs]
        logger.info(
            f"🛡️  Exfiltration watcher ACTIVE — protecting {len(self._vault_filenames)} file(s)"
        )
        logger.info(f"   Monitoring: {', '.join(dir_names)}")

    def stop(self):
        """Stop the exfiltration watcher."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._alerted.clear()
        logger.info("Exfiltration watcher stopped")

    def _poll_loop(self):
        """Main polling loop — scans watched directories for vault files."""
        while self._running:
            try:
                self._scan_directories()
            except Exception as e:
                logger.error(f"Exfil watcher scan error: {e}")
            time.sleep(self.poll_interval)

    def _scan_directories(self):
        """Scan all watched directories for files matching vault contents."""
        # Refresh vault file list (in case new files were created)
        self.update_vault_files()

        if not self._vault_filenames:
            return

        # Clean up alerted entries for files that no longer exist
        self._alerted = {p for p in self._alerted if Path(p).exists()}

        for watch_dir in self._watch_dirs:
            if not watch_dir.exists():
                continue

            try:
                for entry in watch_dir.iterdir():
                    if not entry.is_file():
                        continue

                    if entry.name in self._vault_filenames:
                        # EXFILTRATION DETECTED
                        self._handle_exfiltration(entry)

            except PermissionError:
                pass  # Can't read directory, skip

    def _handle_exfiltration(self, leaked_file: Path):
        """Handle a detected exfiltration attempt."""
        logger.warning("=" * 60)
        logger.warning("🚨 EXFILTRATION DETECTED!")
        logger.warning(f"   File: {leaked_file.name}")
        logger.warning(f"   Location: {leaked_file.parent}")
        logger.warning(f"   Action: DELETING leaked copy")
        logger.warning("=" * 60)

        # Delete the exfiltrated file immediately
        deleted = False
        try:
            # Overwrite with random data first (secure delete)
            size = leaked_file.stat().st_size
            if size > 0:
                with open(leaked_file, "wb") as f:
                    f.write(os.urandom(min(size, 1024 * 1024)))  # cap at 1MB overwrite
                    f.flush()
                    os.fsync(f.fileno())
            leaked_file.unlink()
            deleted = True
            logger.warning(f"   ✅ Leaked file securely deleted: {leaked_file}")
        except Exception as e:
            logger.error(f"   ❌ Failed to delete leaked file: {e}")

        # Fire callback (used to send audit event to server)
        if self.on_alert:
            try:
                self.on_alert(
                    filename=leaked_file.name,
                    dest_path=str(leaked_file),
                    deleted=deleted,
                )
            except Exception as e:
                logger.error(f"Exfil alert callback failed: {e}")
