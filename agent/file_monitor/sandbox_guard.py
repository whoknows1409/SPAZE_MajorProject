"""
SPAZE - Application Sandbox Guard (v4 — inotify + kill browsers)

Chrome reads and closes file descriptors in <5ms. No polling or fuser
can catch that. Instead, this guard uses a two-pronged approach:

1. inotify watches vault dir for IN_OPEN events (instant kernel notification)
2. When a file is opened, check which whitelisted processes have it open
3. If NO whitelisted process claims the open → kill all running browsers

This guarantees Chrome/Firefox/etc are killed before the upload completes,
because the network upload takes much longer than the file read.
"""

import ctypes
import ctypes.util
import logging
import os
import signal
import struct
import select
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Set

logger = logging.getLogger("spaze-agent.sandbox-guard")

IN_OPEN = 0x00000020
IN_ACCESS = 0x00000001
IN_CREATE = 0x00000100
IN_ISDIR = 0x40000000

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name, use_errno=True) if _libc_name else None

# Browsers and network apps to kill when unauthorized vault access detected
BROWSER_PROCESS_NAMES = {
    "chrome", "chromium", "chromium-browser",
    "google-chrome", "google-chrome-stable",
    "firefox", "firefox-esr", "firefox-bin",
    "brave", "brave-browser",
    "opera", "vivaldi", "vivaldi-bin",
    "microsoft-edge", "edge",
    "epiphany", "midori", "falkon",
    "thunderbird", "thunderbird-bin",
    "evolution", "geary", "kmail",
    "telegram-desktop", "discord", "slack",
    "signal-desktop", "element-desktop", "zoom",
    "curl", "wget", "scp", "sftp", "rsync",
    "ftp", "lftp", "nc", "ncat", "netcat", "socat",
    "dropbox", "nextcloud", "rclone", "gdrive", "megasync",
}

WHITELISTED_APPS = {
    "python", "python3", "python3.11", "python3.12", "python3.13",
    "soffice.bin", "soffice", "oosplash",
    "lowriter", "localc", "loimpress", "lodraw",
    "gedit", "gnome-text-editor", "xed",
    "vim", "nvim", "nano", "vi",
    "kate", "kwrite", "mousepad",
    "evince", "eog", "okular",
    "totem", "vlc", "mpv",
    "nautilus", "nemo", "thunar", "dolphin",
    "bash", "sh", "zsh", "fish",
    "cat", "less", "more", "head", "tail",
    "cp", "mv", "ls", "stat", "file", "find",
    "code", "codium",
    "fuser", "lsof",
}


class AppSandboxGuard:
    def __init__(
        self,
        vault_mount: str,
        poll_interval: float = 0.5,
        on_alert: Optional[Callable] = None,
    ):
        self.vault_mount = str(Path(vault_mount).resolve())
        self._vault_prefix = self.vault_mount.rstrip("/") + "/"
        self.poll_interval = poll_interval
        self.on_alert = on_alert
        self._running = False
        self._inotify_thread: Optional[threading.Thread] = None
        self._fallback_thread: Optional[threading.Thread] = None
        self._kill_count = 0
        self._my_pid = os.getpid()
        self._inotify_fd: int = -1
        self._watch_descriptors: dict = {}

    def start(self):
        if self._running:
            return
        self._running = True
        self._kill_count = 0

        if self._setup_inotify():
            self._inotify_thread = threading.Thread(
                target=self._inotify_loop, daemon=True
            )
            self._inotify_thread.start()
            logger.info(f"🔒 App sandbox guard ACTIVE (inotify) — watching {self.vault_mount}")
        else:
            logger.warning("inotify unavailable — using polling only")

        self._fallback_thread = threading.Thread(
            target=self._fallback_poll_loop, daemon=True
        )
        self._fallback_thread.start()

    def stop(self):
        self._running = False
        if self._inotify_thread:
            self._inotify_thread.join(timeout=5)
            self._inotify_thread = None
        if self._fallback_thread:
            self._fallback_thread.join(timeout=5)
            self._fallback_thread = None
        self._cleanup_inotify()

        if self._kill_count > 0:
            logger.info(f"App sandbox guard stopped — killed {self._kill_count} process(es)")
        else:
            logger.info("App sandbox guard stopped")

    # ── inotify ────────────────────────────────────────────────────

    def _setup_inotify(self) -> bool:
        if not _libc:
            return False
        try:
            self._inotify_fd = _libc.inotify_init()
            if self._inotify_fd < 0:
                return False
            mask = IN_OPEN | IN_ACCESS | IN_CREATE
            wd = _libc.inotify_add_watch(
                self._inotify_fd, self.vault_mount.encode("utf-8"), mask,
            )
            if wd >= 0:
                self._watch_descriptors[wd] = self.vault_mount

            if os.path.isdir(self.vault_mount):
                for fname in os.listdir(self.vault_mount):
                    fpath = os.path.join(self.vault_mount, fname)
                    if os.path.isfile(fpath):
                        wd = _libc.inotify_add_watch(
                            self._inotify_fd, fpath.encode("utf-8"),
                            IN_OPEN | IN_ACCESS,
                        )
                        if wd >= 0:
                            self._watch_descriptors[wd] = fpath
            return True
        except Exception as e:
            logger.debug(f"inotify setup failed: {e}")
            return False

    def _cleanup_inotify(self):
        if self._inotify_fd >= 0:
            try:
                os.close(self._inotify_fd)
            except Exception:
                pass
            self._inotify_fd = -1
        self._watch_descriptors.clear()

    def _inotify_loop(self):
        while self._running:
            try:
                ready, _, _ = select.select([self._inotify_fd], [], [], 1.0)
                if not ready:
                    continue

                data = os.read(self._inotify_fd, 4096)
                offset = 0
                while offset < len(data):
                    wd, mask, cookie, name_len = struct.unpack_from("iIII", data, offset)
                    offset += 16
                    name = data[offset:offset + name_len].rstrip(b"\x00")
                    offset += name_len

                    if mask & (IN_OPEN | IN_ACCESS) and not (mask & IN_ISDIR):
                        filename = name.decode("utf-8", errors="ignore")
                        watch_path = self._watch_descriptors.get(wd, "")
                        filepath = os.path.join(watch_path, filename) if filename else watch_path

                        # A vault file was just opened — respond immediately
                        self._on_vault_file_opened(filepath)

            except OSError:
                if not self._running:
                    break
                time.sleep(0.1)
            except Exception as e:
                logger.debug(f"inotify error: {e}")
                time.sleep(0.1)

    def _on_vault_file_opened(self, filepath: str):
        """
        Called instantly when a vault file is opened.
        Check if a whitelisted process opened it. If not, kill browsers.
        """
        if not self._running:
            return  # stop requested: the agent itself is wiping the vault

        # Check if any whitelisted process has this file open right now
        if self._whitelisted_process_has_file(filepath):
            return  # A whitelisted app (LibreOffice, etc.) opened it — OK

        # No whitelisted process claims this open — an unauthorized process did it
        # Kill all running browser/network processes
        self._kill_browsers(filepath)

    def _whitelisted_process_has_file(self, filepath: str) -> bool:
        """Check if any whitelisted process currently has filepath open."""
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == self._my_pid:
                continue
            try:
                proc_name = self._get_process_name(pid)
                if not proc_name or proc_name not in WHITELISTED_APPS:
                    continue
                # Check if this whitelisted process has the file open
                fd_dir = f"/proc/{pid}/fd"
                if not os.path.isdir(fd_dir):
                    continue
                for fd_entry in os.listdir(fd_dir):
                    try:
                        fd_path = os.readlink(os.path.join(fd_dir, fd_entry))
                        if fd_path == filepath:
                            return True
                    except (FileNotFoundError, OSError):
                        continue
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
        return False

    def _kill_browsers(self, accessed_file: str):
        """Kill all running browser/network processes."""
        filename = os.path.basename(accessed_file)
        killed_any = False

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
                if proc_name in BROWSER_PROCESS_NAMES:
                    os.kill(pid, signal.SIGKILL)
                    if not killed_any:
                        self._kill_count += 1
                        killed_any = True
                        logger.warning("=" * 60)
                        logger.warning(f"🚫 UPLOAD/TRANSFER BLOCKED!")
                        logger.warning(f"   Vault file accessed: {filename}")
                        logger.warning(f"   Killed: {proc_name} (PID {pid})")

                        if self.on_alert:
                            try:
                                self.on_alert(
                                    process_name=proc_name, pid=pid,
                                    filename=filename, file_path=accessed_file,
                                )
                            except Exception:
                                pass
                    else:
                        logger.warning(f"   Killed: {proc_name} (PID {pid})")

            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass

        if killed_any:
            logger.warning("=" * 60)

    # ── Fallback polling ───────────────────────────────────────────

    def _fallback_poll_loop(self):
        while self._running:
            try:
                self._scan_all_fds()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _scan_all_fds(self):
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == self._my_pid:
                continue
            try:
                fd_dir = f"/proc/{pid}/fd"
                if not os.path.isdir(fd_dir):
                    continue
                for fd_entry in os.listdir(fd_dir):
                    try:
                        fd_path = os.readlink(os.path.join(fd_dir, fd_entry))
                        if fd_path.startswith(self._vault_prefix):
                            proc_name = self._get_process_name(pid)
                            if proc_name and proc_name not in WHITELISTED_APPS:
                                self._handle_single_kill(pid, proc_name, fd_path)
                            break
                    except (FileNotFoundError, OSError):
                        continue
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass

    def _handle_single_kill(self, pid, proc_name, file_path):
        filename = os.path.basename(file_path)
        try:
            os.kill(pid, signal.SIGKILL)
            self._kill_count += 1
            logger.warning(f"🚫 BLOCKED — killed '{proc_name}' (PID {pid}) accessing {filename}")
            if self.on_alert:
                try:
                    self.on_alert(
                        process_name=proc_name, pid=pid,
                        filename=filename, file_path=file_path,
                    )
                except Exception:
                    pass
        except (ProcessLookupError, PermissionError):
            pass

    # ── Helpers ────────────────────────────────────────────────────

    def _get_process_name(self, pid: int) -> Optional[str]:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read()
            if cmdline:
                argv0 = cmdline.split(b"\x00")[0].decode("utf-8", errors="ignore")
                return os.path.basename(argv0).lower()
        except Exception:
            pass
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip().lower()
        except Exception:
            pass
        return None
