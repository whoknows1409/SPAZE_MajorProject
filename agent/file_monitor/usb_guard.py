"""
SPAZE - USB Storage Guard

Prevents data theft via USB storage devices by monitoring for new
block devices while the vault is unlocked.

When a USB drive/stick is plugged in during an active vault session:
  1. Immediately unmounts the device
  2. Logs a security alert to the server
  3. Emits a local warning

Monitors /sys/block/ for new devices appearing (sdb, sdc, etc.).
"""

import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Set

logger = logging.getLogger("spaze-agent.usb-guard")

# Block devices to ignore (system disks, loop devices, etc.)
IGNORED_PREFIXES = {"loop", "sr", "ram", "dm-", "zram", "nbd", "md"}


def _get_removable_devices() -> Set[str]:
    """Get currently connected removable block devices."""
    devices = set()
    sys_block = Path("/sys/block")
    if not sys_block.exists():
        return devices

    for dev in sys_block.iterdir():
        name = dev.name

        # Skip non-physical devices
        if any(name.startswith(prefix) for prefix in IGNORED_PREFIXES):
            continue

        # Check if device is removable
        removable_path = dev / "removable"
        try:
            if removable_path.exists():
                val = removable_path.read_text().strip()
                if val == "1":
                    devices.add(name)
                    continue
        except Exception:
            pass

        # Also catch USB devices via the device path
        device_path = dev / "device"
        if device_path.is_symlink():
            real_path = str(device_path.resolve())
            if "usb" in real_path.lower():
                devices.add(name)

    return devices


class USBStorageGuard:
    """
    Monitors for new USB storage devices and unmounts them
    while the vault is unlocked.
    """

    def __init__(
        self,
        poll_interval: float = 2.0,
        on_alert: Optional[Callable] = None,
    ):
        self.poll_interval = poll_interval
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._baseline_devices: Set[str] = set()
        self._blocked_count = 0

    def start(self):
        """Start USB monitoring — snapshot current devices as baseline."""
        if self._running:
            return

        # Capture baseline: devices already plugged in are allowed
        self._baseline_devices = _get_removable_devices()
        self._running = True
        self._blocked_count = 0
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

        if self._baseline_devices:
            logger.info(
                f"🔌 USB guard ACTIVE — baseline devices: {', '.join(self._baseline_devices)}"
            )
        else:
            logger.info("🔌 USB guard ACTIVE — no removable devices present")

    def stop(self):
        """Stop USB monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        if self._blocked_count > 0:
            logger.info(f"USB guard stopped — blocked {self._blocked_count} device(s)")
        else:
            logger.info("USB guard stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._check_devices()
            except Exception as e:
                logger.debug(f"USB guard scan error: {e}")
            time.sleep(self.poll_interval)

    def _check_devices(self):
        """Check for new USB devices that weren't in the baseline."""
        current = _get_removable_devices()
        new_devices = current - self._baseline_devices

        for dev_name in new_devices:
            self._handle_new_device(dev_name)
            # Add to baseline so we don't alert repeatedly
            self._baseline_devices.add(dev_name)

    def _handle_new_device(self, dev_name: str):
        """Handle a newly detected USB storage device."""
        logger.warning("=" * 60)
        logger.warning(f"🚨 USB STORAGE DEVICE BLOCKED!")
        logger.warning(f"   Device: /dev/{dev_name}")
        logger.warning(f"   Action: Unmounting all partitions")
        logger.warning("=" * 60)

        self._blocked_count += 1

        # Unmount all partitions of this device
        self._unmount_device(dev_name)

        # Fire alert callback
        if self.on_alert:
            try:
                self.on_alert(device_name=dev_name)
            except Exception:
                pass

    def _unmount_device(self, dev_name: str):
        """Unmount all partitions of a block device."""
        # Find all mount points for this device
        try:
            result = subprocess.run(
                ["findmnt", "-rn", "-o", "TARGET", "-S", f"/dev/{dev_name}"],
                capture_output=True, text=True, timeout=5,
            )
            mount_points = result.stdout.strip().split("\n") if result.stdout.strip() else []

            # Also check partitions (sdb1, sdb2, etc.)
            for i in range(1, 10):
                part = f"/dev/{dev_name}{i}"
                if os.path.exists(part):
                    result = subprocess.run(
                        ["findmnt", "-rn", "-o", "TARGET", "-S", part],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.stdout.strip():
                        mount_points.extend(result.stdout.strip().split("\n"))

            # Unmount each mount point
            for mp in mount_points:
                mp = mp.strip()
                if not mp:
                    continue
                try:
                    subprocess.run(
                        ["sudo", "-n", "umount", "-f", mp],
                        capture_output=True, timeout=5,
                    )
                    logger.warning(f"   Unmounted: {mp}")
                except Exception as e:
                    logger.error(f"   Failed to unmount {mp}: {e}")

            if not mount_points:
                logger.info(f"   Device /dev/{dev_name} not mounted (blocked before mount)")

        except Exception as e:
            logger.error(f"   Error unmounting device: {e}")
