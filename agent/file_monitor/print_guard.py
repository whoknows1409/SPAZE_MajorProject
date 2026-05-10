"""
SPAZE - Print Guard

Prevents printing of vault files by monitoring the CUPS print queue
and killing print-related processes that access vault files.

Two-layer protection:
  1. Process monitor: kills print spooler processes with fd's to vault
  2. Queue monitor: cancels any CUPS print jobs while vault is unlocked
"""

import logging
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger("spaze-agent.print-guard")

# Print-related processes to monitor for vault file access
PRINT_PROCESSES = {
    "cupsd", "cups-browsed",
    "cups-lpd", "cups-pdf",
    "lp", "lpr", "lpq", "lprm",
    "cancel",
    "hp-systray", "hplip",
    "system-config-printer",
}


class PrintGuard:
    """
    Prevents printing of vault files by monitoring CUPS and
    killing print processes that access the vault mount.
    """

    def __init__(
        self,
        vault_mount: str,
        poll_interval: float = 2.0,
        on_alert: Optional[Callable] = None,
    ):
        self.vault_mount = str(Path(vault_mount).resolve())
        self._vault_prefix = self.vault_mount.rstrip("/") + "/"
        self.poll_interval = poll_interval
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._block_count = 0
        self._my_pid = os.getpid()

    def start(self):
        """Start print monitoring."""
        if self._running:
            return

        self._running = True
        self._block_count = 0
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("🖨️  Print guard ACTIVE — vault file printing blocked")

    def stop(self):
        """Stop print monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        if self._block_count > 0:
            logger.info(f"Print guard stopped — blocked {self._block_count} print attempt(s)")
        else:
            logger.info("Print guard stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._scan_print_processes()
                self._cancel_print_jobs()
            except Exception as e:
                logger.debug(f"Print guard error: {e}")
            time.sleep(self.poll_interval)

    def _scan_print_processes(self):
        """Scan for print processes with file descriptors to vault files."""
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue

            pid = int(entry)
            if pid == self._my_pid:
                continue

            try:
                comm_path = f"/proc/{pid}/comm"
                with open(comm_path, "r") as f:
                    proc_name = f.read().strip().lower()

                if proc_name not in PRINT_PROCESSES:
                    continue

                # Check file descriptors for vault access
                fd_dir = f"/proc/{pid}/fd"
                if not os.path.isdir(fd_dir):
                    continue

                for fd_entry in os.listdir(fd_dir):
                    try:
                        fd_path = os.readlink(os.path.join(fd_dir, fd_entry))
                        if fd_path.startswith(self._vault_prefix):
                            # Print process accessing vault file — kill it
                            os.kill(pid, signal.SIGKILL)
                            self._block_count += 1

                            logger.warning(
                                f"🖨️  PRINT BLOCKED — killed '{proc_name}' "
                                f"(PID {pid}) accessing {os.path.basename(fd_path)}"
                            )

                            if self.on_alert:
                                try:
                                    self.on_alert(
                                        process_name=proc_name,
                                        pid=pid,
                                        filename=os.path.basename(fd_path),
                                    )
                                except Exception:
                                    pass
                            break

                    except (FileNotFoundError, OSError):
                        continue

            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass

    def _cancel_print_jobs(self):
        """Cancel any active CUPS print jobs."""
        try:
            result = subprocess.run(
                ["lpstat", "-o"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return

            # Parse job IDs and cancel them
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if parts:
                    job_id = parts[0]
                    try:
                        subprocess.run(
                            ["cancel", job_id],
                            capture_output=True, timeout=3,
                        )
                        self._block_count += 1
                        logger.warning(f"🖨️  PRINT JOB CANCELLED — job {job_id}")

                        if self.on_alert:
                            try:
                                self.on_alert(
                                    process_name="cups",
                                    pid=0,
                                    filename=f"print job {job_id}",
                                )
                            except Exception:
                                pass
                    except Exception:
                        pass

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # lpstat not available or timed out
