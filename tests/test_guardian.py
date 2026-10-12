#!/usr/bin/env python3
"""
Vault guardian dead-man logic, runnable without root: a plain temporary
directory stands in for the tmpfs and the kernel access gate is disabled.

Run: python -m unittest tests/test_guardian.py -v
"""

import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AGENT = """
import sys, time; sys.path.insert(0, {root!r})
from agent.file_monitor.guardian_client import GuardianClient
c = GuardianClient("g.sock"); assert c.connect(); assert c.unlocked({vault!r})
open({vault!r} + "/secret.txt", "w").write("TOP SECRET")
print("ready", flush=True); time.sleep(120)
"""


class GuardianDeadMan(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sg")      # short path for the UNIX socket
        self.vault = os.path.join(self.dir, "vault")
        os.makedirs(self.vault)
        self.log = os.path.join(self.dir, "g.csv")
        cfg = {"user": os.environ.get("USER") or os.getlogin(), "mount_point": self.vault,
               "socket": "g.sock", "enforce": False, "strict": False, "lock_screen": False,
               "require_mount": False, "heartbeat_timeout_s": 2.0, "log_csv": self.log}
        with open(os.path.join(self.dir, "cfg.json"), "w") as f:
            json.dump(cfg, f)
        self.guardian = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "guardian", "spaze_guardian.py"), "--config", "cfg.json"],
            cwd=self.dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)

    def tearDown(self):
        self.guardian.kill()
        os.chmod(self.vault, 0o700)
        shutil.rmtree(self.dir, ignore_errors=True)

    def _start_agent(self):
        a = subprocess.Popen([sys.executable, "-c", AGENT.format(root=ROOT, vault=self.vault)],
                             cwd=self.dir, stdout=subprocess.PIPE, text=True)
        self.assertEqual(a.stdout.readline().strip(), "ready")
        return a

    def _wipe_after(self, t0, timeout):
        end = time.time() + timeout
        while time.time() < end:
            with open(self.log, newline="") as f:
                for r in csv.DictReader(f):
                    if r["event"] == "wipe_done" and float(r["t"]) > t0:
                        return float(r["t"]) - t0
            time.sleep(0.02)
        return None

    def test_sigkill_wipes_immediately(self):
        holder = subprocess.Popen(["sleep", "60"], cwd=self.vault)
        a = self._start_agent()
        t0 = time.time()
        a.kill()
        dt = self._wipe_after(t0, 5)
        self.assertIsNotNone(dt)
        self.assertLess(dt, 1.0)
        time.sleep(0.2)
        self.assertIsNotNone(holder.poll(), "process inside the vault must be killed")
        self.assertFalse(os.access(self.vault, os.R_OK), "mount point must be locked (mode 000)")

    def test_frozen_agent_wiped_after_timeout(self):
        a = self._start_agent()
        t0 = time.time()
        os.kill(a.pid, signal.SIGSTOP)
        try:
            dt = self._wipe_after(t0, 6)
            self.assertIsNotNone(dt)
            self.assertGreater(dt, 1.5)
        finally:
            a.kill()

    def test_normal_lock_does_not_wipe(self):
        code = AGENT.replace('print("ready", flush=True); time.sleep(120)',
                             'assert c.locked(); print("ready", flush=True); time.sleep(120)')
        a = subprocess.Popen([sys.executable, "-c", code.format(root=ROOT, vault=self.vault)],
                             cwd=self.dir, stdout=subprocess.PIPE, text=True)
        self.assertEqual(a.stdout.readline().strip(), "ready")
        t0 = time.time()
        a.kill()
        self.assertIsNone(self._wipe_after(t0, 1.5), "no wipe after a clean LOCKED")


class WriteDownScope(unittest.TestCase):
    """Which locations count as 'outside the vault' for the write-down rule."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "guardian"))
        import spaze_guardian as g
        self.g = g
        self.args = ("/home/u", "/home/u/spaze", "/var/lib/spaze-guardian/quarantine")

    def scope(self, path):
        return self.g.in_writedown_scope(path, *self.args)

    def test_user_folders_in_scope(self):
        for p in ["/home/u/Documents/demo.pdf", "/home/u/Desktop/x.odt", "/home/u/report.pdf",
                  "/home/u/Downloads/a/b/c.txt", "/tmp/leak.pdf"]:
            self.assertTrue(self.scope(p), p)

    def test_libreoffice_recovery_copies_in_scope(self):
        self.assertTrue(self.scope("/home/u/snap/libreoffice/377/.config/libreoffice/4/user/backup/demo_0.odt"))
        self.assertTrue(self.scope("/home/u/.config/libreoffice/4/user/backup/demo_0.odt"))

    def test_not_in_scope(self):
        for p in ["/home/u/spaze/demo.odt", "/home/u/spaze", "/var/lib/spaze-guardian/quarantine/x",
                  "/home/u/.config/libreoffice/4/user/registrymodifications.xcu",
                  "/home/u/snap/libreoffice/377/.config/libreoffice/4/user/registrymodifications.xcu",
                  "/home/u/.cache/thumbnails/x.png", "/home/u/.bash_history",
                  "/tmp/snap-private-tmp/snap.libreoffice/tmp/lu123.tmp", "/tmp/lu12ab.tmp",
                  "/tmp/.~lock.demo.odt#", "/var/log/syslog", "/etc/passwd",
                  "/home/u/Documents/x.pdf (deleted)", "", "relative/path"]:
            self.assertFalse(self.scope(p), p)

    def test_taint_survives_only_same_process(self):
        wd = self.g.WriteDownGuard("/home/u", "/home/u/spaze", lambda *a: None, "/tmp/q-unused")
        child = subprocess.Popen(["sleep", "30"])
        try:
            wd.taint(child.pid, "/usr/bin/sleep")
            self.assertTrue(wd._is_tainted(child.pid))
            self.assertFalse(wd._is_tainted(os.getpid()))
            wd.tainted[child.pid] = (wd.tainted[child.pid][0] + 1, "x")   # simulate a reused PID
            self.assertFalse(wd._is_tainted(child.pid))
        finally:
            child.kill()

    def test_quarantine_moves_file_out_of_reach(self):
        d = tempfile.mkdtemp(prefix="sgq")
        try:
            src = os.path.join(d, "leak.pdf")
            with open(src, "w") as f:
                f.write("plaintext")
            q = os.path.join(d, "quarantine")
            events = []
            wd = self.g.WriteDownGuard("/home/u", "/home/u/spaze", lambda *a: events.append(a), q)
            wd._quarantine(src, os.getpid())
            self.assertFalse(os.path.exists(src))
            moved = os.listdir(q)
            self.assertEqual(len(moved), 1)
            self.assertTrue(moved[0].endswith("_leak.pdf"))
            self.assertEqual(oct(os.stat(q).st_mode & 0o777), "0o700")
            self.assertEqual(events[-1][0], "write_out_quarantined")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
