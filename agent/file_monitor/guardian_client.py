"""
SPAZE - client for the privileged Vault Guardian (guardian/spaze_guardian.py).

The agent keeps one UNIX-socket session open and sends a heartbeat every
0.5 s. Before plaintext is written into the tmpfs it reports UNLOCKED and waits
for the guardian to confirm that the kernel access gate is active; after the
tmpfs is gone it reports LOCKED. If this process dies, the kernel closes the
socket and the guardian wipes the vault.
"""

import logging
import socket
import threading
import time

from .. import trace

logger = logging.getLogger("spaze-agent.guardian")


class GuardianClient:
    def __init__(self, path: str = "/run/spaze-guardian.sock", heartbeat_s: float = 0.5):
        self.path = path
        self.heartbeat_s = heartbeat_s
        self._sock = None
        self._lock = threading.Lock()
        self._alive = False
        self._thread = None

    def connect(self) -> bool:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.path)
            s.settimeout(5.0)
            self._sock = s
            self._alive = True
        except OSError as e:
            logger.error(f"Cannot reach vault guardian at {self.path}: {e}")
            return False
        self._thread = threading.Thread(target=self._heartbeat, daemon=True)
        self._thread.start()
        logger.info(f"🛡️  Connected to vault guardian ({self.path})")
        return True

    @property
    def alive(self) -> bool:
        return self._alive

    def _send(self, line: str) -> bool:
        with self._lock:
            try:
                self._sock.sendall((line + "\n").encode())
                return True
            except OSError:
                self._alive = False
                return False

    def _request(self, line: str) -> bool:
        """Send a command and wait for the guardian's OK/ERR."""
        with self._lock:
            try:
                self._sock.sendall((line + "\n").encode())
                reply = b""
                while not reply.endswith(b"\n"):
                    chunk = self._sock.recv(64)
                    if not chunk:
                        raise OSError("guardian closed the session")
                    reply += chunk
                return reply.strip() == b"OK"
            except OSError as e:
                logger.error(f"Guardian request '{line}' failed: {e}")
                self._alive = False
                return False

    def _heartbeat(self):
        while self._alive:
            if not self._send("HB"):
                logger.error("Lost vault guardian session")
                return
            time.sleep(self.heartbeat_s)

    def unlocked(self, mount_point: str) -> bool:
        ok = self._request(f"UNLOCKED {mount_point}")
        trace.event("guardian_unlocked", ok=ok)
        return ok

    def locked(self) -> bool:
        ok = self._request("LOCKED")
        trace.event("guardian_locked", ok=ok)
        return ok
