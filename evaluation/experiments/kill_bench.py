#!/usr/bin/env python3
"""
E7 - What happens to plaintext when the agent is killed (one repetition per run).

With the vault UNLOCKED: sends SIGKILL to the agent, then measures
  * time until the guardian logs 'wipe_done' (if the guardian runs), and
  * whether the vault directory still lists readable files after 3 s.

  python evaluation/experiments/kill_bench.py --config guardian
  python evaluation/experiments/kill_bench.py --config no_guardian
Restart the agent afterwards (it cleans a stale mount on start).
"""

import argparse
import csv
import os
import signal
import subprocess
import time

from common import CsvLog, data_path


def agent_pids():
    out = subprocess.run(["pgrep", "-f", "python.* -m agent.main"], capture_output=True, text=True)
    return [int(p) for p in out.stdout.split()]


def guardian_wipe_after(log_path, t0):
    if not os.path.exists(log_path):
        return None
    with open(log_path, newline="") as f:
        for r in csv.DictReader(f):
            if r["event"] == "wipe_done" and float(r["t"]) > t0:
                return float(r["t"]), r["detail"]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, choices=["guardian", "no_guardian"])
    ap.add_argument("--mount", default=os.path.expanduser("~/spaze"))
    ap.add_argument("--guardian-log", default="/var/log/spaze-guardian.csv")
    args = ap.parse_args()

    pids = agent_pids()
    if not pids:
        raise SystemExit("agent is not running")
    files_before = os.listdir(args.mount) if os.access(args.mount, os.R_OK) else []
    if not files_before:
        raise SystemExit("vault looks locked/empty - unlock it first")

    t0 = time.time()
    for p in pids:
        os.kill(p, signal.SIGKILL)
    wipe = None
    while time.time() - t0 < 10 and wipe is None:
        wipe = guardian_wipe_after(args.guardian_log, t0)
        time.sleep(0.02)
    time.sleep(max(0.0, 3.0 - (time.time() - t0)))
    try:
        left = os.listdir(args.mount)
        readable = any(os.access(os.path.join(args.mount, f), os.R_OK) for f in left)
    except PermissionError:
        left, readable = [], False
    mounted = os.path.ismount(args.mount)

    log = CsvLog(data_path("e7_guardian", "kill_bench.csv"),
                 ["t_kill", "config", "wipe_ms", "files_before", "files_after_3s", "readable_after_3s",
                  "still_mounted", "guardian_detail"])
    log.row(f"{t0:.6f}", args.config, f"{(wipe[0] - t0) * 1000:.1f}" if wipe else "",
            len(files_before), len(left), int(readable), int(mounted), wipe[1] if wipe else "")
    log.close()
    print(f"{args.config}: wipe {'%.0f ms' % ((wipe[0] - t0) * 1000) if wipe else 'none'}; "
          f"after 3 s: {len(left)} files, readable={readable}, mounted={mounted}")


if __name__ == "__main__":
    main()
