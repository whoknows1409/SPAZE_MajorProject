#!/usr/bin/env python3
"""
A1/A2 - Key-release attacks against a running server.

A1 network attacker: knows the badge MAC (broadcast over BLE) and the
   workstation hostname, but has no device key and no badge.
A2 compromised agent: holds the device key (signs requests) but the badge is
   absent; tries (a) no token, (b) forged tokens, (c) tokens replayed from an
   earlier trace (recorded >= --min-age seconds ago).

  python evaluation/experiments/attack_bench.py --mode pakl --server https://localhost:8443 \
      --ca-cert secrets/tls/server.crt --badge-mac AA:BB:CC:DD:EE:FF --hostname HOST \
      --device-key-file secrets/device.key
Run once with the server in baseline mode (--mode baseline) and once in pakl mode.
"""

import argparse
import csv
import hashlib
import hmac
import json
import os
import sys
import time

import httpx

from common import CsvLog, data_path

sys.path.insert(0, str(__import__("common").PROJECT))
from server.security import pakl  # noqa: E402


def post(client, server, path, payload, device_key=None, hostname=None):
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    if device_key:
        ts = f"{time.time():.3f}"
        msg = "\n".join(["POST", path, ts, hashlib.sha256(body).hexdigest()]).encode()
        headers.update({"X-SPAZE-Device": hostname, "X-SPAZE-Timestamp": ts,
                        "X-SPAZE-Signature": hmac.new(device_key, msg, hashlib.sha256).hexdigest()})
    return client.post(f"{server}{path}", content=body, headers=headers)


def outcome(r):
    if r.status_code != 200:
        return "rejected", f"HTTP {r.status_code}", 0
    d = r.json()
    return ("KEYS_RELEASED" if d.get("authorized") else "denied"), d.get("message", ""), len(d.get("keys", {}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["baseline", "pakl"], required=True, help="server mode (for labelling)")
    ap.add_argument("--server", required=True)
    ap.add_argument("--ca-cert")
    ap.add_argument("--badge-mac", required=True)
    ap.add_argument("--hostname", required=True)
    ap.add_argument("--device-key-file")
    ap.add_argument("--min-age", type=float, default=60.0)
    ap.add_argument("-n", type=int, default=20)
    args = ap.parse_args()

    client = httpx.Client(timeout=10, verify=args.ca_cert if args.ca_cert else True)
    log = CsvLog(data_path("e4_security", "attacks.csv"),
                 ["t", "server_mode", "attack", "rep", "outcome", "message", "n_keys"])
    base = {"badge_mac": args.badge_mac, "device_hostname": args.hostname}

    def run(name, fn, n):
        counts = {}
        for i in range(1, n + 1):
            r = fn(i)
            res, msg, nk = outcome(r)
            counts[res] = counts.get(res, 0) + 1
            log.row(f"{time.time():.6f}", args.mode, name, i, res, msg, nk)
        print(f"  {name:32s} {counts}")

    print(f"[server mode: {args.mode}]")
    run("A1_unsigned_request", lambda i: post(client, args.server, "/api/keys/request", base), args.n)

    if args.device_key_file:
        dk = bytes.fromhex(open(args.device_key_file).read().strip())
        sign = lambda p: post(client, args.server, "/api/keys/request", p, dk, args.hostname)  # noqa: E731
        run("A2a_signed_no_token", lambda i: sign(base), args.n)
        run("A2b_signed_forged_token",
            lambda i: sign({**base, "presence_token": pakl.make_token(os.urandom(32), 1, int(time.time()))}),
            args.n)
        # Genuine badge broadcasts recorded earlier (E1 sniffing) and replayed now
        now = time.time()
        toks = []
        rec = data_path("e1_rssi", "rssi.csv")
        if rec.exists():
            with open(rec, newline="") as f:
                toks = [r["tok"] for r in csv.DictReader(f)
                        if r["tok"] and now - float(r["t_host"]) >= args.min_age]
        if toks:
            step = max(1, len(toks) // args.n)
            sample = toks[::step][:args.n]
            run("A2c_signed_replayed_token", lambda i: sign({**base, "presence_token": sample[i - 1]}),
                len(sample))
        else:
            print("  (no recorded tokens older than --min-age found - run E1 first)")


if __name__ == "__main__":
    main()
