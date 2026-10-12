#!/usr/bin/env python3
"""
SPAZE Vault Guardian (runs as root, e.g. via systemd)

Two jobs the unprivileged agent cannot do for itself:

1. Dead-man wipe. The agent keeps a UNIX-socket session open and sends
   heartbeats while the vault is unlocked. If the agent dies (the kernel
   closes its socket immediately, even on SIGKILL), stops responding, or the
   tmpfs is mounted without a live session (strict mode), the guardian kills
   processes holding vault files, overwrites them, unmounts the tmpfs, locks
   the mount point (chmod 000) and locks the desktop sessions.

2. Mandatory access control on plaintext. While the vault is unlocked, a
   fanotify FAN_OPEN_PERM mark on the tmpfs mount makes the kernel ask the
   guardian before any process opens a file there. Opens are allowed only for
   the agent itself and for allow-listed executables (e.g. LibreOffice,
   document viewers); everything else -- shells, cp/cat, interpreters,
   browsers, upload tools -- gets EPERM before reading a byte.

3. Write-down control. A process that has been allowed to read vault plaintext
   (e.g. LibreOffice) is marked as tainted. While the vault is unlocked, files
   that a tainted process writes outside the vault -- in the user's folders,
   /tmp, or LibreOffice's auto-recovery folder (Print to File, Save As, Export,
   recovery copies) -- are moved on close into a root-only quarantine folder
   (fanotify FAN_CLOSE_WRITE on the home filesystem). This is detect-and-
   quarantine on close, not in-kernel prevention.

An unprivileged user cannot signal a root process, so killing the agent no
longer leaves plaintext behind. Root attackers remain out of scope.

  sudo python3 guardian/spaze_guardian.py --config /etc/spaze/guardian.json
"""

import argparse
import ctypes
import ctypes.util
import csv
import fnmatch
import json
import logging
import os
import pwd
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

log = logging.getLogger("spaze-guardian")

# ---------------------------------------------------------------- fanotify
FAN_CLOEXEC, FAN_NONBLOCK, FAN_CLASS_CONTENT = 0x1, 0x2, 0x4
FAN_MARK_ADD, FAN_MARK_MOUNT = 0x1, 0x10
FAN_OPEN_PERM = 0x00010000
FAN_ALLOW, FAN_DENY = 0x01, 0x02
FAN_CLASS_NOTIF, FAN_MARK_FILESYSTEM = 0x0, 0x00000100
FAN_CLOSE_WRITE, FAN_Q_OVERFLOW = 0x00000008, 0x00004000
FANOTIFY_METADATA_VERSION = 3
O_LARGEFILE, O_CLOEXEC = 0o100000, 0o2000000
AT_FDCWD = -100
EVENT_FMT = "=IBBHQii"           # struct fanotify_event_metadata (24 bytes)
EVENT_SIZE = struct.calcsize(EVENT_FMT)
RESPONSE_FMT = "=iI"             # struct fanotify_response

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
_libc.fanotify_init.restype = ctypes.c_int
_libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
_libc.fanotify_mark.restype = ctypes.c_int


class EventLog:
    """CSV log with host timestamps (used by the experiments)."""

    def __init__(self, path):
        self.lock = threading.Lock()
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        self.f = open(path, "a", newline="", buffering=1)
        os.chmod(path, 0o644)
        self.w = csv.writer(self.f)
        if new:
            self.w.writerow(["t", "event", "detail"])

    def __call__(self, event, detail=""):
        with self.lock:
            self.w.writerow([f"{time.time():.6f}", event, detail])
        log.info(f"{event} {detail}")


class Enforcer:
    """fanotify permission gate on the vault mount."""

    def __init__(self, mount, allowed_exes, evlog):
        self.mount = mount
        self.allowed_exes = list(allowed_exes)   # exact paths or fnmatch patterns
        self.evlog = evlog
        self.allowed_pids = {os.getpid()}
        self.wiping = False
        self.fd = -1
        self._stop_r, self._stop_w = os.pipe()
        self._thread = None
        self.counts = {"allow": 0, "deny": 0}
        self._last_deny = {}
        self.on_allow = None   # callback(pid, exe) when an allow-listed program reads a vault file

    def start(self, agent_pid):
        # Safety: a mark on a non-mount path would gate the parent filesystem
        if not os.path.ismount(self.mount):
            raise OSError(22, f"{self.mount} is not a mount point; refusing to mark it")
        self.allowed_pids = {os.getpid(), agent_pid}
        self.wiping = False
        fd = _libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                                 os.O_RDONLY | O_LARGEFILE | O_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init failed (needs CAP_SYS_ADMIN)")
        # Filesystem (superblock) mark, not a mount mark: snap applications see the
        # vault through a propagated copy of the mount in their own mount namespace,
        # which a mount mark does not cover. The vault is its own tmpfs, so the
        # filesystem mark covers exactly the vault.
        if _libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_PERM,
                               AT_FDCWD, self.mount.encode()) < 0:
            err = ctypes.get_errno()
            os.close(fd)
            raise OSError(err, f"fanotify_mark failed on {self.mount}")
        self.fd = fd
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.evlog("enforce_on", f"agent_pid={agent_pid}")

    def stop(self):
        if self.fd < 0:
            return
        os.write(self._stop_w, b"x")
        if self._thread:
            self._thread.join(timeout=3)
        try:
            os.close(self.fd)   # closing the group releases the mark
        except OSError:
            pass
        self.fd = -1
        try:
            while select.select([self._stop_r], [], [], 0)[0]:
                os.read(self._stop_r, 64)
        except OSError:
            pass
        self.evlog("enforce_off", json.dumps(self.counts))

    def _decide(self, pid, efd):
        if pid in self.allowed_pids:
            return FAN_ALLOW, "trusted_pid"
        if self.wiping:
            return FAN_DENY, "wiping"
        try:
            if stat.S_ISDIR(os.fstat(efd).st_mode):
                return FAN_ALLOW, "directory"        # listing names is not content
        except OSError:
            pass
        try:
            exe = os.readlink(f"/proc/{pid}/exe").replace(" (deleted)", "")
        except OSError:
            return FAN_DENY, "unknown_exe"
        if any(fnmatch.fnmatchcase(exe, pat) for pat in self.allowed_exes):
            if self.on_allow is not None:
                self.on_allow(pid, exe)          # this process has now seen plaintext
            return FAN_ALLOW, exe
        return FAN_DENY, exe

    def _loop(self):
        while True:
            r, _, _ = select.select([self.fd, self._stop_r], [], [], 1.0)
            if self._stop_r in r:
                return
            if self.fd not in r:
                continue
            try:
                buf = os.read(self.fd, 8192)
            except BlockingIOError:
                continue
            except OSError:
                return
            off = 0
            while off + EVENT_SIZE <= len(buf):
                ev_len, vers, _, _, mask, efd, pid = struct.unpack_from(EVENT_FMT, buf, off)
                off += ev_len if ev_len else EVENT_SIZE
                if vers != FANOTIFY_METADATA_VERSION or efd < 0:
                    continue
                try:
                    decision, why = self._decide(pid, efd)
                except Exception:
                    decision, why = FAN_DENY, "error"
                try:
                    os.write(self.fd, struct.pack(RESPONSE_FMT, efd, decision))
                finally:
                    if decision == FAN_DENY:
                        try:
                            path = os.readlink(f"/proc/self/fd/{efd}")
                        except OSError:
                            path = "?"
                        key = (pid, path)
                        now = time.time()
                        if now - self._last_deny.get(key, 0) > 1.0:
                            self._last_deny[key] = now
                            self.evlog("open_denied", f"pid={pid} exe={why} path={path}")
                    os.close(efd)
                self.counts["allow" if decision == FAN_ALLOW else "deny"] += 1


def in_writedown_scope(path, home, vault, quarantine):
    """
    Is `path` a place where a copy of vault plaintext would leak to?
    In scope: the user's own folders under $HOME (not hidden/application
    state), LibreOffice auto-recovery copies, and /tmp (except LibreOffice's
    own temp/lock files and snaps' private /tmp). Never: the vault itself, the
    quarantine, or any system path.
    """
    if not path or not path.startswith("/") or path.endswith(" (deleted)"):
        return False
    norm = os.path.normpath(path)
    for root in (vault, quarantine):
        root = root.rstrip("/")
        if norm == root or norm.startswith(root + "/"):
            return False
    name = os.path.basename(norm)
    home = home.rstrip("/")
    if norm.startswith(home + "/"):
        first = norm[len(home) + 1:].split("/", 1)[0]
        if first.startswith(".") or first == "snap":
            # application state: only LibreOffice auto-recovery/backup copies
            return "/libreoffice/" in norm and "/user/backup/" in norm
        return True
    if norm.startswith("/tmp/"):
        if norm.startswith("/tmp/snap-private-tmp/"):
            return False
        if name.startswith(".~lock.") or (name.startswith("lu") and name.endswith(".tmp")):
            return False
        return True
    return False


def proc_start_time(pid):
    """Process start time (clock ticks since boot); distinguishes reused PIDs."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return int(f.read().rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None


class WriteDownGuard:
    """
    Quarantines files written outside the vault by processes that have read
    vault plaintext (a 'no write-down' rule), using fanotify FAN_CLOSE_WRITE
    notifications on the filesystem that holds the user's home directory.
    """

    def __init__(self, home, vault, evlog, quarantine="/var/lib/spaze-guardian/quarantine"):
        self.home = home
        self.vault = vault
        self.quarantine = quarantine
        self.evlog = evlog
        self.tainted = {}          # pid -> (start_time, exe)
        self.fd = -1
        self._stop_r, self._stop_w = os.pipe()
        self._thread = None
        self.counts = {"quarantined": 0, "overflow": 0}

    def taint(self, pid, exe):
        st = proc_start_time(pid)
        if self.tainted.get(pid, (None,))[0] == st:
            return
        self.tainted[pid] = (st, exe)
        self.evlog("tainted", f"pid={pid} exe={exe}")

    def _is_tainted(self, pid):
        t = self.tainted.get(pid)
        return t is not None and t[0] == proc_start_time(pid)

    def start(self):
        fd = _libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                                 os.O_RDONLY | O_LARGEFILE | O_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init (notification) failed")
        if _libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CLOSE_WRITE,
                               AT_FDCWD, self.home.encode()) < 0:
            err = ctypes.get_errno()
            os.close(fd)
            raise OSError(err, f"fanotify filesystem mark failed on {self.home}")
        self.fd = fd
        self.counts = {"quarantined": 0, "overflow": 0}
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.evlog("writedown_on", f"home={self.home}")

    def stop(self):
        if self.fd >= 0:
            os.write(self._stop_w, b"x")
            if self._thread:
                self._thread.join(timeout=3)
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1
            try:
                while select.select([self._stop_r], [], [], 0)[0]:
                    os.read(self._stop_r, 64)
            except OSError:
                pass
            self.evlog("writedown_off", json.dumps(self.counts))
        self.tainted.clear()

    def _loop(self):
        while True:
            r, _, _ = select.select([self.fd, self._stop_r], [], [], 1.0)
            if self._stop_r in r:
                return
            if self.fd not in r:
                continue
            try:
                buf = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                return
            off = 0
            while off + EVENT_SIZE <= len(buf):
                ev_len, vers, _, _, mask, efd, pid = struct.unpack_from(EVENT_FMT, buf, off)
                off += ev_len if ev_len else EVENT_SIZE
                if mask & FAN_Q_OVERFLOW:
                    self.counts["overflow"] += 1
                if efd < 0:
                    continue
                try:
                    if self.tainted and self._is_tainted(pid):
                        path = os.readlink(f"/proc/self/fd/{efd}")
                        if in_writedown_scope(path, self.home, self.vault, self.quarantine):
                            self._quarantine(path, pid)
                except Exception as e:
                    log.warning(f"write-down check failed: {e}")
                finally:
                    os.close(efd)

    def _quarantine(self, path, pid):
        os.makedirs(self.quarantine, mode=0o700, exist_ok=True)
        os.chmod(self.quarantine, 0o700)
        dest = os.path.join(self.quarantine, f"{time.time():.6f}_{pid}_{os.path.basename(path)}")
        try:
            os.rename(path, dest)
        except OSError:
            shutil.copy2(path, dest)          # different filesystem
            os.unlink(path)
        try:
            os.chmod(dest, 0o600)
            os.chown(dest, 0, 0)
        except OSError:
            pass
        self.counts["quarantined"] += 1
        exe = self.tainted.get(pid, (None, "?"))[1]
        self.evlog("write_out_quarantined", f"pid={pid} exe={exe} path={path}")


class Guardian:
    def __init__(self, cfg):
        self.cfg = cfg
        self.mount = os.path.realpath(cfg["mount_point"])
        self.user = pwd.getpwnam(cfg["user"])
        self.evlog = EventLog(cfg.get("log_csv", "/var/log/spaze-guardian.csv"))
        self.enforce = cfg.get("enforce", True)
        self.enforcer = Enforcer(self.mount, cfg.get("allowed_executables", []), self.evlog)
        self.write_down = cfg.get("write_down", True)
        self.writedown = WriteDownGuard(self.user.pw_dir, self.mount, self.evlog,
                                        cfg.get("quarantine_dir", "/var/lib/spaze-guardian/quarantine"))
        self.enforcer.on_allow = self.writedown.taint if self.write_down else None
        self.hb_timeout = float(cfg.get("heartbeat_timeout_s", 3.0))
        self.strict = cfg.get("strict", True)
        self.session_unlocked = False
        self.lock = threading.Lock()

    # ------------------------------------------------------------ wipe
    def _is_mounted(self):
        return os.path.ismount(self.mount)

    def emergency_wipe(self, reason):
        with self.lock:
            t0 = time.time()
            self.evlog("wipe_start", reason)
            self.enforcer.wiping = True
            killed = 0
            prefix = self.mount.rstrip("/") + "/"
            for entry in os.listdir("/proc"):
                if not entry.isdigit() or int(entry) == os.getpid():
                    continue
                pid = int(entry)
                try:
                    hit = False
                    for fd in os.listdir(f"/proc/{pid}/fd"):
                        try:
                            if os.readlink(f"/proc/{pid}/fd/{fd}").startswith(prefix):
                                hit = True
                                break
                        except OSError:
                            continue
                    if not hit:
                        cwd = os.readlink(f"/proc/{pid}/cwd")
                        hit = cwd == self.mount or cwd.startswith(prefix)
                    if hit:
                        os.kill(pid, signal.SIGKILL)
                        killed += 1
                except (OSError, ProcessLookupError):
                    continue
            wiped = 0
            if os.path.isdir(self.mount):
                for root, _, files in os.walk(self.mount):
                    for name in files:
                        p = os.path.join(root, name)
                        try:
                            size = os.path.getsize(p)
                            with open(p, "r+b") as f:
                                f.write(os.urandom(size))
                                f.flush()
                                os.fsync(f.fileno())
                            os.unlink(p)
                            wiped += 1
                        except OSError:
                            try:
                                os.unlink(p)
                            except OSError:
                                pass
            if self._is_mounted():
                if subprocess.run(["umount", self.mount], capture_output=True).returncode != 0:
                    subprocess.run(["umount", "-l", self.mount], capture_output=True)
            try:
                os.chmod(self.mount, 0o000)
            except OSError:
                pass
            self.enforcer.stop()
            self.writedown.stop()
            self.enforcer.wiping = False
            self.session_unlocked = False
            if self.cfg.get("lock_screen", True):
                subprocess.run(["loginctl", "lock-sessions"], capture_output=True)
            ms = (time.time() - t0) * 1000
            self.evlog("wipe_done", f"reason={reason} killed={killed} files={wiped} ms={ms:.1f}")

    # ------------------------------------------------------------ sessions
    def serve(self):
        path = self.cfg.get("socket", "/run/spaze-guardian.sock")
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        os.chown(path, self.user.pw_uid, self.user.pw_gid)
        os.chmod(path, 0o600)
        srv.listen(1)
        self.evlog("guardian_start", f"mount={self.mount} enforce={self.enforce} strict={self.strict}")
        if self.strict:
            threading.Thread(target=self._strict_loop, daemon=True).start()
        while True:
            conn, _ = srv.accept()
            pid, uid, _ = struct.unpack("3i", conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid not in (0, self.user.pw_uid):
                self.evlog("reject_peer", f"uid={uid}")
                conn.close()
                continue
            self._session(conn, pid)

    def _session(self, conn, agent_pid):
        self.evlog("agent_connected", f"pid={agent_pid}")
        conn.setblocking(False)
        buf, last_hb = b"", time.time()
        while True:
            r, _, _ = select.select([conn], [], [], 0.25)
            now = time.time()
            if r:
                try:
                    data = conn.recv(4096)
                except OSError:
                    data = b""
                if not data:   # agent exited or was killed: the kernel closed its socket
                    if self.session_unlocked:
                        self.emergency_wipe(f"agent_lost(pid={agent_pid})")
                    self.evlog("agent_disconnected", f"pid={agent_pid}")
                    conn.close()
                    return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    cmd = line.decode(errors="ignore").strip()
                    last_hb = now
                    if cmd.startswith("UNLOCKED"):
                        ok = self._on_unlocked(agent_pid)
                        conn.sendall(b"OK\n" if ok else b"ERR\n")
                    elif cmd == "LOCKED":
                        self.enforcer.stop()
                        self.writedown.stop()
                        self.session_unlocked = False
                        self.evlog("session_locked", f"pid={agent_pid}")
                        conn.sendall(b"OK\n")
            if self.session_unlocked and now - last_hb > self.hb_timeout:
                self.emergency_wipe(f"agent_unresponsive(pid={agent_pid})")

    def _on_unlocked(self, agent_pid):
        if self.cfg.get("require_mount", True) and not self._is_mounted():
            self.evlog("unlock_refused", "vault not mounted")
            return False
        if self.enforce:
            try:
                self.enforcer.start(agent_pid)
            except OSError as e:
                self.evlog("enforce_failed", str(e))
                return False
        if self.write_down:
            try:
                self.writedown.start()
            except OSError as e:
                # keep the vault usable; the file gate and dead-man wipe still apply
                self.evlog("writedown_failed", str(e))
        self.session_unlocked = True
        self.evlog("session_unlocked", f"pid={agent_pid}")
        return True

    def _strict_loop(self):
        """A mounted vault without a live, unlocked session is wiped."""
        first_seen = None
        while True:
            time.sleep(1.0)
            if self._is_mounted() and not self.session_unlocked:
                first_seen = first_seen or time.time()
                if time.time() - first_seen > 15.0:   # allow time for agent to report
                    self.emergency_wipe("mounted_without_session")
                    first_seen = None
            else:
                first_seen = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/spaze/guardian.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    with open(args.config) as f:
        cfg = json.load(f)
    Guardian(cfg).serve()


if __name__ == "__main__":
    main()
