#!/usr/bin/env python3
"""
E6 (manual part) - log when files appear in / disappear from a directory.
Used for screenshots: press PrtSc while the vault is unlocked and see how
long the screenshot file survives.

  python evaluation/experiments/fs_watch.py --dir ~/Pictures/Screenshots --label screenshot
"""

import argparse
import os
import time

from common import CsvLog, data_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--interval", type=float, default=0.01)
    args = ap.parse_args()
    d = os.path.expanduser(args.dir)
    os.makedirs(d, exist_ok=True)
    log = CsvLog(data_path("e5_dlp", "fs_watch.csv"), ["t", "label", "event", "file", "lifetime_ms"])
    seen = {f: None for f in os.listdir(d)}
    print(f"Watching {d} (Ctrl+C to stop)")
    try:
        while True:
            now = time.time()
            cur = set(os.listdir(d))
            for f in cur - seen.keys():
                seen[f] = now
                log.row(f"{now:.6f}", args.label, "appear", f, "")
                print(f"  + {f}")
            for f in set(seen) - cur:
                born = seen.pop(f)
                life = f"{(now - born) * 1000:.1f}" if born else ""
                log.row(f"{now:.6f}", args.label, "disappear", f, life)
                print(f"  - {f}  lifetime {life} ms")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.close()


if __name__ == "__main__":
    main()
