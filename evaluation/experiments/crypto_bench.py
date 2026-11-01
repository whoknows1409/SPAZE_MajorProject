#!/usr/bin/env python3
"""
E8 - Micro-benchmarks on the workstation CPU:
  * AES-256-GCM encrypt/decrypt throughput vs file size (agent crypto path)
  * presence-token verification and request-signature cost (server path)
  * FEK wrap/unwrap cost

  python evaluation/experiments/crypto_bench.py
"""

import os
import platform
import statistics
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import CsvLog, PROJECT, data_path

sys.path.insert(0, str(PROJECT))
from server.security import pakl  # noqa: E402


def timeit(fn, reps):
    out = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t0)
    return out


def main():
    log = CsvLog(data_path("e6_overhead", "crypto_bench.csv"),
                 ["op", "size_bytes", "reps", "median_us", "p95_us", "throughput_MBps", "cpu"])
    cpu = platform.processor() or platform.machine()
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next(l.split(":", 1)[1].strip() for l in f if l.startswith("model name"))
    except Exception:
        pass
    print(f"CPU: {cpu}")

    key = AESGCM.generate_key(256)
    aes = AESGCM(key)
    for size in [4 << 10, 64 << 10, 1 << 20, 10 << 20, 100 << 20]:
        data = os.urandom(size)
        nonce = os.urandom(12)
        reps = max(5, min(200, (200 << 20) // size))
        enc = timeit(lambda: aes.encrypt(nonce, data, None), reps)
        ct = aes.encrypt(nonce, data, None)
        dec = timeit(lambda: aes.decrypt(nonce, ct, None), reps)
        for op, ts in (("aesgcm_encrypt", enc), ("aesgcm_decrypt", dec)):
            med = statistics.median(ts)
            p95 = sorted(ts)[int(0.95 * (len(ts) - 1))]
            log.row(op, size, reps, f"{med*1e6:.1f}", f"{p95*1e6:.1f}", f"{size/med/1e6:.1f}", cpu)
            print(f"  {op:16s} {size>>10:>7d} KiB  median {med*1e3:8.3f} ms  {size/med/1e6:8.1f} MB/s")

    bkey, dkey, mkey = os.urandom(32), os.urandom(32), os.urandom(32)
    tok = pakl.parse_token(pakl.make_token(bkey, 1, 123456))
    body = b'{"badge_mac":"AA:BB:CC:DD:EE:FF","device_hostname":"HOST","presence_token":"' + b"a" * 40 + b'"}'
    sig = pakl.sign_request(dkey, "POST", "/api/keys/request", "1.0", body)
    fek = os.urandom(32)
    blob = pakl.wrap_fek(mkey, fek, 1, "f.enc")
    state = pakl.FreshnessState(123000, 0.0, 0.0, 0.0)
    ops = {
        "token_parse_verify": lambda: pakl.verify_token_tag(pakl.parse_token(pakl.make_token(bkey, 1, 123456)), bkey),
        "token_verify_tag": lambda: pakl.verify_token_tag(tok, bkey),
        "freshness_check": lambda: pakl.check_freshness(123456, state, 1.0, 8.0, 5.0),
        "request_sig_verify": lambda: pakl.verify_request_signature(dkey, "POST", "/api/keys/request", "1.0", body, sig, 1.0, 30),
        "fek_wrap": lambda: pakl.wrap_fek(mkey, fek, 1, "f.enc"),
        "fek_unwrap": lambda: pakl.unwrap_fek(mkey, blob, 1, "f.enc"),
    }
    for op, fn in ops.items():
        ts = timeit(fn, 20000)
        med = statistics.median(ts)
        p95 = sorted(ts)[int(0.95 * (len(ts) - 1))]
        log.row(op, "", len(ts), f"{med*1e6:.2f}", f"{p95*1e6:.2f}", "", cpu)
        print(f"  {op:20s} median {med*1e6:7.2f} us  p95 {p95*1e6:7.2f} us")
    log.close()


if __name__ == "__main__":
    main()
