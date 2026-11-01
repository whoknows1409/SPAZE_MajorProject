#!/usr/bin/env python3
"""
A3 - Revocation latency (PAKL). Badge stays at the desk the whole time.

Loop: wait until the vault is unlocked -> admin revokes the badge (t0) ->
measure when the agent finishes locking (trace 'lock_done') -> re-activate
the badge -> wait for the next unlock.

  export SPAZE_ADMIN_EMAIL=... SPAZE_ADMIN_PASSWORD=...
  python evaluation/experiments/revoke_bench.py --trace evaluation/data/trace_pakl.csv \
      --server https://localhost:8443 --ca-cert secrets/tls/server.crt --badge-id 1 -n 10
"""

import argparse
import time

from common import CsvLog, data_path, read_trace, wait_for_trace_event
from server_admin import Admin


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
    ap.add_argument("--server", required=True)
    ap.add_argument("--ca-cert")
    ap.add_argument("--badge-id", type=int, required=True)
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("--tag", help="suffix for the output file, e.g. v2 -> revocation_v2.csv")
    args = ap.parse_args()
    out = "revocation_%s.csv" % args.tag if args.tag else "revocation.csv"

    admin = Admin(args.server, args.ca_cert)
    log = CsvLog(data_path("e4_security", out),
                 ["rep", "t_revoke", "t_lease_denied", "t_lock_start", "t_lock_done", "latency_ms"])
    try:
        for i in range(1, args.n + 1):
            print(f"[rep {i}] waiting for vault to be unlocked ...")
            while not vault_unlocked(args.trace):
                time.sleep(0.5)
            time.sleep(4.0 + (i % 3))  # desynchronise from the renewal phase
            t0 = time.time()
            admin.set_badge_status(args.badge_id, "revoked")
            denied = wait_for_trace_event(args.trace, ["lease_renew_denied"], t0, 30)
            start = wait_for_trace_event(args.trace, ["lock_start"], t0, 30)
            done = wait_for_trace_event(args.trace, ["lock_done"], t0, 60)
            lat = (done[0] - t0) * 1000 if done else ""
            log.row(i, f"{t0:.6f}", f"{denied[0]:.6f}" if denied else "",
                    f"{start[0]:.6f}" if start else "", f"{done[0]:.6f}" if done else "",
                    f"{lat:.1f}" if lat != "" else "")
            print(f"  revoke -> locked: {lat if lat == '' else round(lat)} ms")
            admin.set_badge_status(args.badge_id, "active")
            time.sleep(2.0)
    finally:
        admin.set_badge_status(args.badge_id, "active")
        log.close()


if __name__ == "__main__":
    main()
