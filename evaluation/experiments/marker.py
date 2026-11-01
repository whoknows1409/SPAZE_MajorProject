#!/usr/bin/env python3
"""
E2 - Ground-truth markers for walk-away / return trials.

Run in a terminal on the workstation while the agent runs with --trace-csv.
The helper presses a key at the exact moment the walker starts moving:
  l + Enter  = walker starts LEAVING the desk
  a + Enter  = walker starts walking BACK (APPROACH)
  n + Enter  = note / mark a bad trial (you will be asked for text)
  q + Enter  = quit

  python evaluation/experiments/marker.py --session pakl_default

Solo mode (no helper): the walker types l + Enter at the desk and stands up at
once; after --away seconds an alarm sounds and the approach marker is recorded
at that moment - the walker starts back as soon as they hear it.

  python evaluation/experiments/marker.py --session pakl --solo --away 45
"""

import argparse
import time

from common import CsvLog, beep, data_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True, help="e.g. pakl_default, baseline")
    ap.add_argument("--solo", action="store_true", help="no helper: alarm tells the walker when to return")
    ap.add_argument("--away", type=float, default=45.0, help="solo mode: seconds before the return alarm")
    args = ap.parse_args()
    out = data_path("e2_walk", f"markers_{args.session}.csv")
    log = CsvLog(out, ["t", "session", "marker", "trial", "note"])
    trial = 0
    print(f"Markers -> {out}")
    if args.solo:
        print(f"SOLO: type l + Enter and stand up immediately; walk to your spot; "
              f"come back when the alarm sounds ({args.away:.0f} s later).")
    print("l = leave, a = approach, n = note, q = quit")
    while True:
        cmd = input(f"[trial {trial + 1}] > ").strip().lower()
        t = time.time()
        if cmd == "l":
            trial += 1
            log.row(f"{t:.6f}", args.session, "leave", trial, "")
            print(f"  leave #{trial} @ {time.strftime('%H:%M:%S')}")
            if args.solo:
                t_back = t + args.away
                while time.time() < t_back:
                    print(f"  return alarm in {t_back - time.time():4.0f} s", end="\r", flush=True)
                    time.sleep(0.2)
                beep("return")
                ta = time.time()
                log.row(f"{ta:.6f}", args.session, "approach", trial, "solo_alarm")
                print(f"  approach #{trial} @ {time.strftime('%H:%M:%S')} (alarm) - walk back now   ")
        elif cmd == "a":
            log.row(f"{t:.6f}", args.session, "approach", trial, "")
            print(f"  approach #{trial} @ {time.strftime('%H:%M:%S')}")
        elif cmd == "n":
            note = input("  note: ")
            log.row(f"{t:.6f}", args.session, "note", trial, note)
        elif cmd == "q":
            break
    log.close()


if __name__ == "__main__":
    main()
