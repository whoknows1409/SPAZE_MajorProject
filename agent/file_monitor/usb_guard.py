"""
SPAZE - USB Storage Guard

Prevents data theft via USB storage devices by monitoring for new
block devices while the vault is unlocked.

Detection strategy:
  Rather than relying on the unreliable 'removable' flag, we monitor
  for ANY new block device that appears in /sys/block/ after baseline.
  If a new sd*, nvme*, or similar device appears → it's a USB/external
  device that was just plugged in.

When a USB drive is plugged in during an active vault session:
  1. Unmounts via udisksctl (no root needed on Ubuntu)
  2. Powers off the USB port to prevent GNOME re-mount
  3. Continuously enforces — re-unmounts if GNOME re-mounts
  4. Logs a security alert to the server
"""

import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Set

logger = logging.getLogger("spaze-agent.usb-guard")

# Virtual/system block devices to always ignore
IGNORED_PREFIXES = {"loop", "sr", "ram", "dm-", "zram", "nbd", "md"}


def _get_real_block_devices() -> Set[str]:
    """Get all real (non-virtual) block devices currently in /sys/block/."""
    devices = set()
    sys_block = Path("/sys/block")
    if not sys_block.exists():
        return devices

    for dev in sys_block.iterdir():
        name = dev.name
        if any(name.startswith(prefix) for prefix in IGNORED_PREFIXES):
            continue
        devices.add(name)

    return devices


class USBStorageGuard:
    """
    Monitors for new block devices and unmounts/powers-off them
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
        self._blocked_devices: Set[str] = set()
        self._blocked_count = 0

    def start(self):
        """Start USB monitoring — snapshot current devices as baseline."""
        if self._running:
            return

        # Baseline = only SYSTEM disks (non-removable, non-USB)
        # Any removable/USB device already plugged in gets blocked immediately
        all_devices = _get_real_block_devices()
        self._baseline_devices = set()
        self._blocked_devices = set()

        for dev_name in all_devices:
            if self._is_removable_or_usb(dev_name):
                # This is a USB/removable device already plugged in — block it
                logger.info(f"🔌 Found existing USB device: /dev/{dev_name}")
            else:
                # This is a system disk — add to baseline
                self._baseline_devices.add(dev_name)

        self._running = True
        self._blocked_count = 0
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

        # Block any existing USB devices immediately
        existing_usb = all_devices - self._baseline_devices
        for dev_name in existing_usb:
            self._handle_new_device(dev_name)

        logger.info(
            f"🔌 USB guard ACTIVE — system disks: {', '.join(sorted(self._baseline_devices))}"
        )

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

    def _is_removable_or_usb(self, dev_name: str) -> bool:
        """Check if a block device is removable or connected via USB."""
        dev_path = Path(f"/sys/block/{dev_name}")

        # Check 'removable' flag
        try:
            removable = (dev_path / "removable").read_text().strip()
            if removable == "1":
                return True
        except Exception:
            pass

        # Check if connected via USB bus
        device_link = dev_path / "device"
        if device_link.is_symlink():
            real_path = str(device_link.resolve()).lower()
            if "usb" in real_path:
                return True

        # Check transport type via /sys/block/*/device/transport (SATA vs USB)
        try:
            for parent in (dev_path / "device").resolve().parents:
                transport = parent / "removable"
                if transport.exists():
                    if transport.read_text().strip() == "1":
                        return True
        except Exception:
            pass

        return False

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._check_for_new_devices()
                self._enforce_blocked_devices()
            except Exception as e:
                logger.debug(f"USB guard scan error: {e}")
            time.sleep(self.poll_interval)

    def _check_for_new_devices(self):
        """Detect any NEW block device that wasn't present at baseline."""
        current = _get_real_block_devices()
        new_devices = current - self._baseline_devices - self._blocked_devices

        for dev_name in new_devices:
            self._handle_new_device(dev_name)

    def _handle_new_device(self, dev_name: str):
        """Handle a newly detected storage device."""
        logger.warning("=" * 60)
        logger.warning(f"🚨 USB/EXTERNAL STORAGE BLOCKED!")
        logger.warning(f"   Device: /dev/{dev_name}")
        logger.warning(f"   Action: Unmounting + powering off")
        logger.warning("=" * 60)

        self._blocked_count += 1
        self._blocked_devices.add(dev_name)

        # Unmount all partitions and power off
        self._unmount_and_poweroff(dev_name)

        # Fire alert callback
        if self.on_alert:
            try:
                self.on_alert(device_name=dev_name)
            except Exception:
                pass

    def _enforce_blocked_devices(self):
        """Re-unmount blocked devices if GNOME auto-remounted them."""
        for dev_name in list(self._blocked_devices):
            if not Path(f"/sys/block/{dev_name}").exists():
                continue
            if self._is_device_mounted(dev_name):
                logger.warning(f"🔌 Re-unmounting /dev/{dev_name} (auto-remount detected)")
                self._unmount_and_poweroff(dev_name)

    def _is_device_mounted(self, dev_name: str) -> bool:
        """Check if any partition of this device is currently mounted."""
        try:
            with open("/proc/mounts", "r") as f:
                mounts = f.read()
            if f"/dev/{dev_name} " in mounts or f"/dev/{dev_name}\t" in mounts:
                return True
            for i in range(1, 16):
                part = f"/dev/{dev_name}{i}"
                if f"{part} " in mounts or f"{part}\t" in mounts:
                    return True
        except Exception:
            pass
        return False

    def _unmount_and_poweroff(self, dev_name: str):
        """Unmount all partitions and power off the USB device."""
        partitions = self._find_partitions(dev_name)
        if not partitions:
            partitions = [dev_name]

        for part in partitions:
            self._unmount_partition(part)

        # Power off the drive to prevent GNOME from re-mounting
        self._poweroff_device(dev_name)

    def _find_partitions(self, dev_name: str) -> list:
        """Find all partitions of a block device."""
        partitions = []
        # Check /sys/block/sdX/sdX1, sdX2, etc.
        dev_dir = Path(f"/sys/block/{dev_name}")
        if dev_dir.exists():
            for child in dev_dir.iterdir():
                if child.name.startswith(dev_name) and child.name != dev_name:
                    partitions.append(child.name)
        return sorted(partitions)

    def _unmount_partition(self, part_name: str):
        """Unmount a partition using multiple methods."""
        dev_path = f"/dev/{part_name}"

        # Method 1: udisksctl (works without root on Ubuntu desktop)
        try:
            result = subprocess.run(
                ["udisksctl", "unmount", "-b", dev_path, "--no-user-interaction"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                logger.warning(f"   Unmounted {dev_path}")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Method 2: umount (may need sudo)
        try:
            result = subprocess.run(
                ["umount", "-f", dev_path],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                logger.warning(f"   Force-unmounted {dev_path}")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Method 3: sudo umount
        try:
            result = subprocess.run(
                ["sudo", "-n", "umount", "-f", dev_path],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                logger.warning(f"   Sudo-unmounted {dev_path}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _poweroff_device(self, dev_name: str):
        """Power off a USB drive to prevent re-mounting."""
        dev_path = f"/dev/{dev_name}"

        # udisksctl power-off
        try:
            result = subprocess.run(
                ["udisksctl", "power-off", "-b", dev_path, "--no-user-interaction"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                logger.warning(f"   ⚡ Powered off {dev_path}")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: eject
        try:
            subprocess.run(
                ["eject", dev_path],
                capture_output=True, timeout=5,
            )
            logger.warning(f"   ⚡ Ejected {dev_path}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
