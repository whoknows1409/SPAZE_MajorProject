#!/usr/bin/env python3
"""
Export the server audit log (field-usage data) to data/field_logs/audit_logs.csv.
Identifiers are pseudonymised (badge_N / device_N) and home paths are redacted
so the file can be published with the paper.

  python evaluation/experiments/export_audit_logs.py
"""

import asyncio
import re
import socket
import sys

from common import CsvLog, PROJECT, data_path

sys.path.insert(0, str(PROJECT))
import os  # noqa: E402
os.chdir(PROJECT)

from sqlalchemy import text  # noqa: E402
from server.db.database import engine  # noqa: E402

HOME_RE = re.compile(r"/home/[^/\s]+")


async def main():
    out = data_path("field_logs", "audit_logs.csv")
    if out.exists():
        out.unlink()
    log = CsvLog(out, ["id", "timestamp_utc", "action", "badge", "device", "rssi_value", "details"])
    async with engine.connect() as conn:
        rows = (await conn.execute(text(
            "select id, timestamp, action, badge_id, device_id, rssi_value, details "
            "from audit_logs order by timestamp"))).all()
    for r in rows:
        details = HOME_RE.sub("~", r.details or "")
        details = re.sub(r"(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", "<mac>", details)
        details = details.replace(socket.gethostname(), "<host>")
        log.row(r.id, r.timestamp.isoformat(), r.action,
                f"badge_{r.badge_id}" if r.badge_id else "",
                f"device_{r.device_id}" if r.device_id else "",
                r.rssi_value if r.rssi_value is not None else "", details)
    log.close()
    await engine.dispose()
    print(f"{len(rows)} audit rows -> {out}")


if __name__ == "__main__":
    asyncio.run(main())
