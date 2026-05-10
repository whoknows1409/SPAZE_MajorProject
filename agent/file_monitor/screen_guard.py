"""
SPAZE - Screen Capture Guard (v2)

Two-layer protection against screen captures:

Layer 1: Process killer
  - Kills blacklisted screenshot/recording tools (flameshot, obs, scrot, etc.)

Layer 2: Screenshot file watcher
  - GNOME Shell's built-in screenshot (PrtSc on Ubuntu 22.04+) runs inside
    gnome-shell itself, which we CANNOT kill.
  - Instead, we monitor ~/Pictures/Screenshots/ and delete any new image
    files that appear while the vault is unlocked.
"""

import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Set

logger = logging.getLogger("spaze-agent.screen-guard")

# Blacklisted process names (all common Linux screenshot/recording tools)
BLOCKED_PROCESSES = {
    # Screenshot tools
    "gnome-screenshot",
    "flameshot",
    "scrot",
    "spectacle",       # KDE screenshot
    "xfce4-screenshooter",
    "shutter",
    "maim",
    "import",           # ImageMagick screenshot
    "deepin-screenshot",
    "ksnip",

    # Screen recording tools
    "obs",
    "obs-studio",
    "simplescreenrecorder",
    "kazam",
    "peek",             # GIF recorder
    "recordmydesktop",
    "vokoscreen",
    "green-recorder",
    "screencast",
}

# Directories where screenshots are saved
SCREENSHOT_DIRS = [
    os.path.expanduser("~/Pictures/Screenshots"),
    os.path.expanduser("~/Pictures"),
]

# Image extensions to watch for
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tiff"}


class ScreenCaptureGuard:
    """
    Process watchdog + screenshot file watcher that blocks
    screen captures while the vault is unlocked.
    """

    def __init__(
        self,
        poll_interval: float = 1.0,
        on_alert: Optional[Callable] = None,
    ):
        self.poll_interval = poll_interval
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._kill_count = 0
        self._my_pid = os.getpid()
        self._baseline_screenshots: Set[str] = set()

    def _get_process_name(self, pid: int) -> Optional[str]:
        """Get the full process name from /proc, handling 15-char truncation."""
        # Method 1: /proc/PID/cmdline (full binary path, no truncation)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read()
            if cmdline:
                argv0 = cmdline.split(b"\x00")[0].decode("utf-8", errors="ignore")
                return os.path.basename(argv0).lower()
        except Exception:
            pass

        # Method 2: /proc/PID/comm (truncated to 15 chars, but always readable)
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip().lower()
        except Exception:
            pass

        return None

    def _snapshot_screenshots(self) -> Set[str]:
        """Get current set of screenshot files."""
        files = set()
        for d in SCREENSHOT_DIRS:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    full_path = os.path.join(d, f)
                    if os.path.isfile(full_path):
                        ext = os.path.splitext(f)[1].lower()
                        if ext in IMAGE_EXTENSIONS:
                            files.add(full_path)
        return files

    def start(self):
        """Start the screen capture watchdog."""
        if self._running:
            return

        self._running = True
        self._kill_count = 0

        # Snapshot existing screenshots so we don't delete old ones
        self._baseline_screenshots = self._snapshot_screenshots()

        self._thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._thread.start()
        logger.info(
            f"🛡️  Screen capture guard ACTIVE — "
            f"blocking {len(BLOCKED_PROCESSES)} tools + monitoring screenshot dirs"
        )

    def stop(self):
        """Stop the watchdog."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        if self._kill_count > 0:
            logger.info(
                f"Screen capture guard stopped — blocked {self._kill_count} attempt(s)"
            )
        else:
            logger.info("Screen capture guard stopped")

    def _watchdog_loop(self):
        """Main watchdog loop — scan processes + check screenshot dirs."""
        while self._running:
            try:
                self._scan_and_kill()
                self._check_new_screenshots()
            except Exception as e:
                logger.debug(f"Screen guard scan error: {e}")
            time.sleep(self.poll_interval)

    def _scan_and_kill(self):
        """Scan /proc for blacklisted processes and kill them."""
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue

            pid = int(entry)
            if pid == self._my_pid:
                continue

            try:
                proc_name = self._get_process_name(pid)
                if not proc_name:
                    continue

                if proc_name in BLOCKED_PROCESSES:
                    os.kill(pid, signal.SIGKILL)
                    self._kill_count += 1

                    logger.warning(
                        f"🚫 SCREEN CAPTURE BLOCKED — killed '{proc_name}' (PID {pid})"
                    )

                    if self.on_alert:
                        try:
                            self.on_alert(process_name=proc_name, pid=pid)
                        except Exception:
                            pass

            except (FileNotFoundError, ProcessLookupError):
                pass
            except PermissionError:
                pass
            except Exception:
                pass

    def _check_new_screenshots(self):
        """Detect and delete new screenshot files (catches GNOME Shell PrtSc)."""
        current = self._snapshot_screenshots()
        new_files = current - self._baseline_screenshots

        for filepath in new_files:
            try:
                filename = os.path.basename(filepath)

                # Secure delete: overwrite with random bytes then unlink
                file_size = os.path.getsize(filepath)
                with open(filepath, "wb") as f:
                    f.write(os.urandom(file_size))
                os.unlink(filepath)

                self._kill_count += 1
                logger.warning(
                    f"🚫 SCREENSHOT DELETED — {filename} "
                    f"(GNOME Shell screenshot intercepted)"
                )

                if self.on_alert:
                    try:
                        self.on_alert(
                            process_name="gnome-shell-screenshot",
                            pid=0,
                        )
                    except Exception:
                        pass

            except Exception as e:
                logger.error(f"Failed to delete screenshot {filepath}: {e}")

            # Don't add to baseline — if user retakes, we catch it again
