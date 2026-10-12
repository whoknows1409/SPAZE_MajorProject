"""
SPAZE - Experiment trace logger

Writes timestamped agent events (raw RSSI, filter outputs, state changes,
vault lock/unlock, lease renewals, DLP alerts) to a CSV file so that
latencies and false-lock rates can be measured offline.

Disabled unless configure() is called (agent --trace-csv).
"""

import csv
import json
import threading
import time
from typing import Optional

_lock = threading.Lock()
_writer = None
_file = None


def configure(path: Optional[str]):
    """Open the trace file (append mode). Call once at agent start."""
    global _writer, _file
    if not path:
        return
    _file = open(path, "a", newline="", buffering=1)
    _writer = csv.writer(_file)
    if _file.tell() == 0:
        _writer.writerow(["t", "event", "data"])


def event(name: str, **data):
    """Record one event. No-op when tracing is disabled."""
    if _writer is None:
        return
    t = time.time()
    with _lock:
        _writer.writerow([f"{t:.6f}", name, json.dumps(data, separators=(",", ":"))])


def close():
    global _writer, _file
    with _lock:
        if _file is not None:
            _file.close()
        _writer = None
        _file = None
