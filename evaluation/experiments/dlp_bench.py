#!/usr/bin/env python3
"""
E5 - Scripted DLP guard tests. Run while the vault is UNLOCKED (badge at desk).

CLOSE YOUR WEB BROWSERS FIRST: the sandbox guard kills every browser /
network tool when an unauthorised process opens a vault file.

Tests (each appends rows to data/e5_dlp/dlp.csv):
  clipboard   time until a copied string is wiped from the clipboard
  copy        time until a copy in ~/Documents (same name) is deleted
  copy_rename copy with a different name (expected: NOT caught)
  copy_hidden copy into ~/.cache (unwatched dir; expected: NOT caught)
  curl        curl uploads a vault file to a local sink at --rate (killed?)
  python      python uploads a vault file (python is whitelisted)
  pipe        cat file | curl (curl never opens the vault file itself)

  python evaluation/experiments/dlp_bench.py --file ~/spaze/test_1MB.bin --all
"""

import argparse
import http.server
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from common import CsvLog, data_path

HOME = Path.home()


# ------------------------------------------------------------------
# Local upload sink (stands in for a remote web server)
# ------------------------------------------------------------------

class Sink(http.server.BaseHTTPRequestHandler):
    received = {}

    def do_PUT(self):
        key = self.path
        total = 0
        remaining = int(self.headers.get("Content-Length", 0) or 0)
        chunked = self.headers.get("Transfer-Encoding", "") == "chunked"
        try:
            if chunked:
                while True:
                    size = int(self.rfile.readline().strip() or b"0", 16)
                    if size == 0:
                        break
                    total += len(self.rfile.read(size))
                    self.rfile.readline()
                    Sink.received[key] = total
            else:
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    total += len(chunk)
                    remaining -= len(chunk)
                    Sink.received[key] = total
        except Exception:
            pass
        Sink.received[key] = total
        self.send_response(200)
        self.end_headers()

    do_POST = do_PUT

    def log_message(self, *a):
        pass


def start_sink(port):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

def clip_set(text):
    p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
    p.communicate(text.encode(), timeout=2)


def clip_get():
    r = subprocess.run(["xclip", "-selection", "clipboard", "-o"], capture_output=True, timeout=2)
    return r.stdout.decode(errors="ignore")


CONFIG = "userspace"


def test_clipboard(log, n, timeout=5.0):
    for i in range(n):
        marker = f"SPAZE-{uuid.uuid4().hex}"
        t0 = time.time()
        clip_set(marker)
        cleared_at = None
        while time.time() - t0 < timeout:
            if marker not in clip_get():
                cleared_at = time.time()
                break
            time.sleep(0.02)
        outcome = "blocked" if cleared_at else "not_blocked"
        lat = (cleared_at - t0) * 1000 if cleared_at else ""
        log.row(f"{t0:.6f}", CONFIG, "clipboard", i + 1, outcome, f"{lat:.1f}" if lat != "" else "", "", "")
        print(f"  clipboard #{i+1}: {outcome} {lat if lat == '' else round(lat)} ms")
        time.sleep(1.0)


def test_copy(log, src, n, kind, timeout):
    dest_dir = {"copy": HOME / "Documents", "copy_rename": HOME / "Documents",
                "copy_hidden": HOME / ".cache"}[kind]
    dest_dir.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        name = src.name if kind == "copy" else f"renamed_{uuid.uuid4().hex[:8]}{src.suffix}"
        dest = dest_dir / name
        t0 = time.time()
        try:
            shutil.copyfile(src, dest)
        except PermissionError:
            # Kernel access gate refused to open the vault file: nothing left the vault
            log.row(f"{t0:.6f}", CONFIG, kind, i + 1, "blocked", "0.0", "open_denied", "")
            print(f"  {kind} #{i+1}: blocked at open (EPERM)")
            time.sleep(0.5)
            continue
        gone_at = None
        while time.time() - t0 < timeout:
            if not dest.exists():
                gone_at = time.time()
                break
            time.sleep(0.01)
        outcome = "blocked" if gone_at else "not_blocked"
        lat = f"{(gone_at - t0) * 1000:.1f}" if gone_at else ""
        log.row(f"{t0:.6f}", CONFIG, kind, i + 1, outcome, lat, str(dest), "")
        print(f"  {kind} #{i+1}: {outcome} {lat} ms")
        if dest.exists():
            dest.unlink()  # clean up the leaked copy ourselves
        time.sleep(1.0)


def run_upload(cmd, shell=False):
    t0 = time.time()
    p = subprocess.Popen(cmd, shell=shell, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = p.wait(timeout=120)
    return t0, time.time(), rc


def test_upload(log, src, n, kind, port, rate):
    size = src.stat().st_size
    for i in range(n):
        path = f"/{kind}-{uuid.uuid4().hex[:8]}"
        url = f"http://127.0.0.1:{port}{path}"
        if kind == "curl":
            cmd = ["curl", "-s", "--limit-rate", rate, "-T", str(src), url]
            t0, t1, rc = run_upload(cmd)
        elif kind == "python":
            code = (
                "import urllib.request,sys;"
                f"d=open({str(src)!r},'rb').read();"
                f"urllib.request.urlopen(urllib.request.Request({url!r},data=d,method='PUT'))"
            )
            t0, t1, rc = run_upload(["python3", "-c", code])
        elif kind == "pipe":
            t0, t1, rc = run_upload(f"cat '{src}' | curl -s --limit-rate {rate} -T - '{url}'", shell=True)
        time.sleep(0.3)
        got = Sink.received.get(path, 0)
        killed = rc in (-9, 137) or (kind == "pipe" and rc != 0)
        outcome = "blocked" if got < size else "not_blocked"
        log.row(f"{t0:.6f}", CONFIG, f"upload_{kind}", i + 1, outcome, f"{(t1 - t0) * 1000:.1f}",
                f"rc={rc} killed={killed}", f"{got}/{size}")
        print(f"  upload_{kind} #{i+1}: {outcome} rc={rc} received {got}/{size} bytes in {(t1-t0)*1000:.0f} ms")
        time.sleep(1.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="a decrypted file inside the vault mount (~/spaze/...)")
    ap.add_argument("--tests", nargs="+",
                    default=["clipboard", "copy", "copy_rename", "copy_hidden", "curl", "python", "pipe"])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("-n", type=int, default=10, help="repetitions per test")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--rate", default="1M", help="curl upload rate limit (emulates WAN uplink)")
    ap.add_argument("--config", default="userspace", choices=["userspace", "guardian"],
                    help="label: user-space guards only, or with the vault guardian running")
    args = ap.parse_args()
    global CONFIG
    CONFIG = args.config

    src = Path(os.path.expanduser(args.file))
    if not src.exists():
        raise SystemExit(f"{src} not found - is the vault unlocked?")

    log = CsvLog(data_path("e5_dlp", "dlp.csv"),
                 ["t0", "config", "test", "rep", "outcome", "latency_ms", "detail", "bytes"])
    start_sink(args.port)
    for t in args.tests:
        print(f"[{t}]")
        if t == "clipboard":
            test_clipboard(log, args.n)
        elif t in ("copy", "copy_rename", "copy_hidden"):
            test_copy(log, src, args.n if t == "copy" else max(3, args.n // 3), t, timeout=6.0)
        elif t in ("curl", "python", "pipe"):
            test_upload(log, src, args.n if t == "curl" else max(3, args.n // 3), t, args.port, args.rate)
    log.close()
    print("Results appended to data/e5_dlp/dlp.csv")


if __name__ == "__main__":
    main()
