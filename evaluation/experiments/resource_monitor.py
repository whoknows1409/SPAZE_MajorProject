#!/usr/bin/env python3
"""
E6 - Agent CPU and memory sampling (1 Hz) from /proc.

  python evaluation/experiments/resource_monitor.py --label pakl_unlocked --seconds 600
"""

import argparse
import os
import subprocess
import time

from common import CsvLog, data_path

CLK = os.sysconf("SC_CLK_TCK")


def agent_pid():
    out = subprocess.run(["pgrep", "-f", "python.* -m agent.main"], capture_output=True, text=True)
    pids = [int(p) for p in out.stdout.split()]
    return pids[0] if pids else None


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    return int(parts[11]) + int(parts[12])  # utime + stime


def rss_mb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--seconds", type=float, default=600)
    args = ap.parse_args()
    pid = agent_pid()
    if not pid:
        raise SystemExit("agent is not running")
    log = CsvLog(data_path("e6_overhead", "resources.csv"), ["t", "label", "pid", "cpu_pct", "rss_mb"])
    prev_t, prev_c = time.time(), cpu_ticks(pid)
    end = prev_t + args.seconds
    print(f"Sampling agent PID {pid} for {args.seconds:.0f}s ...")
    while time.time() < end:
        time.sleep(1.0)
        t, c = time.time(), cpu_ticks(pid)
        cpu = 100.0 * (c - prev_c) / CLK / (t - prev_t)
        log.row(f"{t:.3f}", args.label, pid, f"{cpu:.2f}", f"{rss_mb(pid):.1f}")
        prev_t, prev_c = t, c
    log.close()


if __name__ == "__main__":
    main()
