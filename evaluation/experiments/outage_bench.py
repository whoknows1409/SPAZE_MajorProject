#!/usr/bin/env python3
"""
A4 - Server outage / network partition (PAKL). Badge stays at the desk.

Freezes the server process with SIGSTOP (requests hang exactly like a
partitioned network), measures time until the agent locks because its
lease lapsed, then resumes the server with SIGCONT.

  python evaluation/experiments/outage_bench.py --trace evaluation/data/trace_pakl.csv -n 5
"""

import argparse
import os
import signal
import subprocess
import time

from common import CsvLog, data_path, read_trace, wait_for_trace_event


def server_pids():
    out = subprocess.run(["pgrep", "-f", "uvicorn server.main:app"], capture_output=True, text=True)
    return [int(p) for p in out.stdout.split()]


def vault_unlocked(trace):
    state = False
    for _, ev, _ in read_trace(trace):
        if ev == "unlock_done":
            state = True
        elif ev == "lock_done":
            state = False
    return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", required=True)
    ap.add_argument("-n", type=int, default=5)
    ap.add_argument("--tag", help="suffix for the output file, e.g. v2 -> outage_v2.csv")
    args = ap.parse_args()
    out = "outage_%s.csv" % args.tag if args.tag else "outage.csv"

    pids = server_pids()
    if not pids:
        raise SystemExit("uvicorn server.main:app is not running")
    log = CsvLog(data_path("e4_security", out),
                 ["rep", "t_freeze", "t_forced_lock", "t_lock_done", "latency_ms", "reason"])
    try:
        for i in range(1, args.n + 1):
            print(f"[rep {i}] waiting for vault to be unlocked ...")
            while not vault_unlocked(args.trace):
                time.sleep(0.5)
            time.sleep(4.0 + (i % 3))
            t0 = time.time()
            for p in pids:
                os.kill(p, signal.SIGSTOP)
            forced = wait_for_trace_event(args.trace, ["forced_lock"], t0, 60)
            done = wait_for_trace_event(args.trace, ["lock_done"], t0, 90)
            for p in pids:
                os.kill(p, signal.SIGCONT)
            lat = (done[0] - t0) * 1000 if done else ""
            log.row(i, f"{t0:.6f}", f"{forced[0]:.6f}" if forced else "",
                    f"{done[0]:.6f}" if done else "", f"{lat:.1f}" if lat != "" else "",
                    forced[2].get("reason", "") if forced else "")
            print(f"  freeze -> locked: {lat if lat == '' else round(lat)} ms")
            time.sleep(3.0)
    finally:
        for p in pids:
            try:
                os.kill(p, signal.SIGCONT)
            except ProcessLookupError:
                pass
        log.close()


if __name__ == "__main__":
    main()
