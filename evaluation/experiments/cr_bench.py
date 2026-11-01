#!/usr/bin/env python3
"""
E8 - Challenge-response round-trip times and emulated relays (agent must be stopped).

Sends challenges straight to the anchor over serial, with scanning paused,
in random order: legitimate ones (delay 0) and ones where the badge is asked
to hold its answer for d ms, emulating the extra latency a relay would add.
Every answer and anchor attestation is verified with the provisioned keys.

  python evaluation/experiments/cr_bench.py --port /dev/ttyACM0 --legit 300 --per-delay 100 --repeats 3

--repeats k asks the anchor (firmware v3.1) to run k exchanges per challenge and
report the fastest; k=1 results go to cr_bench.csv, k>1 to cr_bench_k<k>.csv.
"""

import argparse
import hashlib
import hmac
import json
import os
import random
import re
import struct
import time

import serial

from common import CsvLog, PROJECT, data_path


def load_key(header, name):
    text = (PROJECT / header).read_text()
    m = re.search(name + r"\[32\]\s*=\s*\{([^}]*)\}", text)
    return bytes(int(x, 16) for x in m.group(1).split(","))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--legit", type=int, default=300)
    ap.add_argument("--per-delay", type=int, default=100)
    ap.add_argument("--delays", type=int, nargs="+", default=[2, 5, 10, 20, 50])
    ap.add_argument("--label", default="desk", help="e.g. desk, 2m")
    ap.add_argument("--repeats", type=int, default=3, help="exchanges per challenge (fastest is used)")
    args = ap.parse_args()

    kb = load_key("firmware/badge/badge_secrets.h", "BADGE_KEY")
    ka = load_key("firmware/anchor/anchor_secrets.h", "ANCHOR_KEY")

    ser = serial.Serial(args.port, 115200, timeout=0.2)
    ser.dtr = False
    time.sleep(0.1)
    ser.dtr = True
    time.sleep(1.5)
    ser.reset_input_buffer()

    # Let the anchor see the badge (and connect) before pausing the scan
    print("Discovering badge (keep it near the anchor) ...")
    t_end = time.time() + 8
    while time.time() < t_end:
        ser.readline()
    ser.write(b"SCAN OFF\n")
    time.sleep(0.5)
    ser.reset_input_buffer()

    plan = [0] * args.legit + [d for d in args.delays for _ in range(args.per_delay)]
    random.shuffle(plan)
    name = "cr_bench.csv" if args.repeats == 1 else f"cr_bench_k{args.repeats}.csv"
    header = ["t", "label", "delay_ms", "rtt_us", "resp_ok", "att_ok", "err"]
    if args.repeats != 1:
        header.append("rtts_us")
    log = CsvLog(data_path("e8_relay", name), header)
    n_ok = 0
    for i, d in enumerate(plan, 1):
        nonce = os.urandom(16)
        ser.write(f"CHAL {nonce.hex()} {d} {args.repeats}\n".encode())
        res, deadline = None, time.time() + 5
        while time.time() < deadline:
            line = ser.readline().decode(errors="ignore").strip()
            if line.startswith("{") and '"cr"' in line:
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if j.get("n") == nonce.hex():
                    res = j
                    break
        if res is None or not res.get("cr"):
            err = (res or {}).get("err", "no_answer")
            log.row(f"{time.time():.6f}", args.label, d, "", "", "", err, *([""] if args.repeats != 1 else []))
            print(f"  [{i}/{len(plan)}] d={d}: {err}")
            continue
        resp, rtt, att = bytes.fromhex(res["r"]), int(res["rtt"]), bytes.fromhex(res["a"])
        resp_ok = hmac.compare_digest(resp, hmac.new(kb, b"CR" + nonce, hashlib.sha256).digest()[:8])
        att_ok = hmac.compare_digest(att, hmac.new(
            ka, b"AT" + nonce + resp + struct.pack(">I", rtt), hashlib.sha256).digest()[:16])
        extra = [res.get("rtts", "")] if args.repeats != 1 else []
        if args.repeats != 1 and int(res.get("k", 1)) != args.repeats:
            raise SystemExit("anchor did not honour the repeat count - flash anchor firmware v3.1")
        log.row(f"{time.time():.6f}", args.label, d, rtt, int(resp_ok), int(att_ok), "", *extra)
        n_ok += 1
        if i % 50 == 0:
            print(f"  [{i}/{len(plan)}] d={d} rtt={rtt / 1000:.1f} ms resp_ok={resp_ok} att_ok={att_ok}")
        time.sleep(0.05)
    ser.write(b"SCAN ON\n")
    ser.close()
    log.close()
    print(f"Done: {n_ok}/{len(plan)} answered -> data/e8_relay/{name}")


if __name__ == "__main__":
    main()
