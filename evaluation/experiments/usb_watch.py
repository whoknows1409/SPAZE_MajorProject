#!/usr/bin/env python3
"""
E5 (manual part) - timestamp USB block-device events from udev, so the time
from plugging a USB drive to the guard blocking it can be measured
(the guard's own 'dlp usb' events are in the agent trace).

  python evaluation/experiments/usb_watch.py
"""

import subprocess
import time

from common import CsvLog, data_path


def main():
    log = CsvLog(data_path("e5_dlp", "usb_udev.csv"), ["t", "action", "devpath"])
    p = subprocess.Popen(["udevadm", "monitor", "--kernel", "--subsystem-match=block"],
                         stdout=subprocess.PIPE, text=True)
    print("Plug a USB drive while the vault is unlocked (Ctrl+C to stop)")
    try:
        for line in p.stdout:
            parts = line.split()
            if line.startswith("KERNEL["):
                action = parts[1] if len(parts) > 1 else ""
                devpath = parts[2] if len(parts) > 2 else ""
                log.row(f"{time.time():.6f}", action, devpath)
                print(f"  {action} {devpath}")
    except KeyboardInterrupt:
        p.terminate()
        log.close()


if __name__ == "__main__":
    main()
