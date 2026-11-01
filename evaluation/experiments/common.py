"""Shared helpers for SPAZE experiment scripts."""

import csv
import json
import os
import time
from pathlib import Path

RP = Path(__file__).resolve().parent.parent          # evaluation/
PROJECT = RP.parent                                   # MajorProject/
DATA = RP / "data"


def data_path(*parts) -> Path:
    p = DATA.joinpath(*parts)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class CsvLog:
    """Append-only CSV writer that flushes every row (safe against Ctrl+C)."""

    def __init__(self, path, header):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists() or self.path.stat().st_size == 0
        self.f = open(self.path, "a", newline="", buffering=1)
        self.w = csv.writer(self.f)
        if new:
            self.w.writerow(header)

    def row(self, *values):
        self.w.writerow(values)

    def close(self):
        self.f.close()


def read_trace(path):
    """Yield (t, event, data_dict) from an agent --trace-csv file."""
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            yield float(r["t"]), r["event"], json.loads(r["data"] or "{}")


def wait_for_trace_event(path, names, since, timeout):
    """Block until an event in `names` with t > since appears; return (t, data) or None."""
    deadline = time.time() + timeout
    names = set(names)
    while time.time() < deadline:
        if os.path.exists(path):
            for t, ev, d in read_trace(path):
                if t > since and ev in names:
                    return t, ev, d
        time.sleep(0.2)
    return None


SOUNDS = {
    "start": "/usr/share/sounds/freedesktop/stereo/complete.oga",
    "done": "/usr/share/sounds/freedesktop/stereo/bell.oga",
    "return": "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga",
}


def beep(kind="done", times=1):
    """Play an audible cue (for solo experiments). Never blocks the caller for long."""
    import shutil
    import subprocess
    path = SOUNDS.get(kind)
    player = shutil.which("paplay") or shutil.which("pw-play")
    for _ in range(times):
        if player and path and os.path.exists(path):
            subprocess.Popen([player, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print("\a", end="", flush=True)
        if times > 1:
            time.sleep(0.6)
