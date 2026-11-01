#!/usr/bin/env python3
"""
Record the outcome of a manual test in data/manual_results.csv.

  python evaluation/experiments/note.py usb_block blocked "drive unmounted after ~2 s"
  python evaluation/experiments/note.py agent_sigkill plaintext_remained "ls ~/spaze still listed files"
"""

import sys
import time

from common import CsvLog, data_path

if len(sys.argv) < 3:
    raise SystemExit(__doc__)
log = CsvLog(data_path("manual_results.csv"), ["t", "test", "outcome", "details"])
log.row(f"{time.time():.6f}", sys.argv[1], sys.argv[2], " ".join(sys.argv[3:]))
log.close()
print("recorded")
