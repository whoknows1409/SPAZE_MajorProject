#!/usr/bin/env python3
"""
E1 - RSSI vs distance logger (agent must NOT be running: it owns the serial port).

Reads the anchor's JSON lines and appends them to data/e1_rssi/rssi.csv with
the host time and a label you choose (distance / posture).

  python evaluation/experiments/rssi_logger.py --label d1.0_front --seconds 120
"""

import argparse
import json
import sys
import time

import serial

from common import CsvLog, beep, data_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--label", required=True, help="e.g. d2.0_front, d2.0_back")
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--mac", help="record only this badge (other badge-like broadcasts are ignored)")
    ap.add_argument("--out", default=str(data_path("e1_rssi", "rssi.csv")))
    ap.add_argument("--wait", type=float, default=0,
                    help="seconds to wait before recording (time to walk to the mark when alone)")
    args = ap.parse_args()

    log = CsvLog(args.out, ["t_host", "label", "rssi", "badge_mac", "ts_anchor", "tok"])
    ser = serial.Serial(args.port, 115200, timeout=1)
    # Reset the ESP32 (same DTR toggle the agent uses) and drop boot output
    ser.dtr = False
    time.sleep(0.1)
    ser.dtr = True
    time.sleep(0.5)
    ser.reset_input_buffer()

    if args.wait > 0:
        print(f"Walk to your position now - recording starts in {args.wait:.0f} s ...")
        t_go = time.time() + args.wait
        while time.time() < t_go:
            ser.reset_input_buffer()      # discard readings taken while walking
            left = t_go - time.time()
            print(f"  {left:4.0f} s", end="\r", flush=True)
            time.sleep(min(1.0, max(0.0, left)))
        ser.reset_input_buffer()
        beep("start")
        print("Recording - stand still.          ")

    n, rssis, end = 0, [], time.time() + args.seconds
    print(f"Logging '{args.label}' for {args.seconds:.0f}s ... (Ctrl+C to stop early)")
    try:
        while time.time() < end:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "rssi" not in d:
                continue
            if args.mac and d.get("badge_mac", "").lower() != args.mac.lower():
                continue
            log.row(f"{time.time():.6f}", args.label, d["rssi"], d.get("badge_mac", ""),
                    d.get("ts", ""), d.get("tok", ""))
            n += 1
            rssis.append(d["rssi"])
            if n % 10 == 0:
                print(f"  {n} samples, last {d['rssi']} dBm, mean {sum(rssis)/len(rssis):.1f}")
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()
        log.close()
        if args.wait > 0:
            beep("done", times=2)
    if rssis:
        print(f"Done: {n} samples, mean {sum(rssis)/len(rssis):.1f} dBm -> {args.out}")
    else:
        print("No samples received - is the badge powered and the anchor flashed?")
        sys.exit(1)


if __name__ == "__main__":
    main()
