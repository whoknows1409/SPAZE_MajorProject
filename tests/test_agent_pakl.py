#!/usr/bin/env python3
"""
Agent-side PAKL logic with the vault and network mocked out
(no tmpfs mount, no DLP guards, no server).

Run: python -m unittest tests/test_agent_pakl.py -v
"""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.main import SPAZEAgent  # noqa: E402
from agent.ble_scanner.filters import FilterConfig, ProximityState  # noqa: E402
from server.security import pakl  # noqa: E402

KEY = bytes(range(32))


def make_agent(**kw):
    agent = SPAZEAgent(
        port="/dev/null", baud=115200,
        vault_dir="/tmp/spaze-unit-vault", mount_point="/tmp/spaze-unit-mount",
        config=FilterConfig(), server_url="http://127.0.0.1:9", badge_mac="aa:bb:cc:dd:ee:ff",
        security_mode="pakl", device_key=b"k" * 32, badge_id=1, screen_lock=False, **kw,
    )
    eng = agent.engine
    eng._is_unlocked = False

    def fake_unlock():
        eng._is_unlocked = True
        return 1

    def fake_lock():
        eng._is_unlocked = False
        return True

    eng.decrypt_vault = mock.Mock(side_effect=fake_unlock)
    eng.lock_vault = mock.Mock(side_effect=fake_lock)
    return agent


def feed(a, r):
    a._on_badge_detected(r)
    a.wait_transitions()


def reading(rssi, counter, badge_id=1, mac="11:22:33:44:55:66"):
    return {"badge_mac": mac, "badge_name": "x", "rssi": rssi,
            "tok": pakl.make_token(KEY, badge_id, counter)}


class AgentPakl(unittest.TestCase):
    def test_unlock_after_grace_and_token_forwarded(self):
        a = make_agent()
        for i in range(4):
            feed(a, reading(-55, 100 + i))
        a.engine.decrypt_vault.assert_not_called()
        feed(a, reading(-55, 104))
        a.engine.decrypt_vault.assert_called_once()
        self.assertEqual(pakl.parse_token(a.current_token()).counter, 104)

    def test_mac_is_not_identity_in_pakl_mode(self):
        a = make_agent()
        # Tokens for another badge id are ignored even with a matching MAC
        for i in range(10):
            feed(a, reading(-50, 100 + i, badge_id=2, mac="aa:bb:cc:dd:ee:ff"))
        a.engine.decrypt_vault.assert_not_called()
        self.assertEqual(a.readings_count, 0)

    def test_older_token_never_displaces_newer(self):
        a = make_agent()
        feed(a, reading(-55, 500))
        feed(a, reading(-55, 200))  # replayed old broadcast
        self.assertEqual(pakl.parse_token(a.current_token()).counter, 500)

    def test_lease_denied_locks_and_rearms(self):
        a = make_agent()
        for i in range(5):
            feed(a, reading(-55, 100 + i))
        self.assertTrue(a.engine.is_unlocked)
        a.engine.key_manager.renew_lease = mock.Mock(return_value=False)
        a._last_renew_attempt = 0
        a._lease_tick()
        a.engine.lock_vault.assert_called_once()
        self.assertEqual(a.pipeline.state, ProximityState.OUT_OF_RANGE)
        # Badge still present -> retries unlock after another grace period
        for i in range(5):
            feed(a, reading(-55, 200 + i))
        self.assertEqual(a.engine.decrypt_vault.call_count, 2)

    def test_lease_lapse_without_server_answer_locks(self):
        a = make_agent()
        for i in range(5):
            feed(a, reading(-55, 100 + i))
        km = a.engine.key_manager
        km.lease_id, km.lease_ttl, km.last_lease_ok = "L", 10.0, time.time() - 11
        km.renew_lease = mock.Mock(return_value=None)  # server unreachable
        a._last_renew_attempt = 0
        a._lease_tick()
        a.engine.lock_vault.assert_called_once()

    def test_departure_locks(self):
        a = make_agent()
        for i in range(5):
            feed(a, reading(-55, 100 + i))
        for i in range(30):
            feed(a, reading(-95, 105 + i))
            if a.engine.lock_vault.called:
                break
        a.engine.lock_vault.assert_called_once()

    def test_no_reading_timeout_locks(self):
        a = make_agent()
        for i in range(5):
            feed(a, reading(-55, 100 + i))
        a.pipeline.last_reading_time = time.time() - 60
        a.pipeline.check_timeout()
        a.wait_transitions()
        a.engine.lock_vault.assert_called_once()


class LeaseExpiryNotDelayed(unittest.TestCase):
    def test_hanging_renewal_does_not_outlive_the_lease(self):
        """A frozen server must not delay the lease-expiry lock by the HTTP timeout."""
        a = make_agent()
        for i in range(5):
            feed(a, reading(-55, 100 + i))
        km = a.engine.key_manager
        km.lease_id, km.lease_ttl, km.last_lease_ok = "L", 10.0, time.time() - 9.7
        seen = {}

        def hanging_post(path, body, timeout=None):     # server frozen: wait out the timeout
            seen["timeout"] = timeout
            time.sleep(timeout)
            raise TimeoutError("frozen")

        km._post = hanging_post
        a._last_renew_attempt = 0
        t0 = time.time()
        a._lease_tick()
        self.assertLess(seen["timeout"], 0.5)
        self.assertLess(time.time() - t0, 0.6)
        a.engine.lock_vault.assert_called_once()


class LeaseRenewRetry(unittest.TestCase):
    def _km(self, *replies):
        a = make_agent(challenge_response=True)
        km = a.engine.key_manager
        km.lease_id, km.lease_ttl, km.last_lease_ok = "L", 10.0, time.time()
        km.cr_enabled, km.pending_challenge = True, "00" * 16
        km._answer_challenge = lambda n: {"nonce": n, "resp": "ab" * 8, "rtt_us": 22000, "att": "cd" * 16}
        km._current_token = lambda: "tok"
        resp = []
        for j in replies:
            r = mock.Mock(status_code=200)
            r.json.return_value = j
            resp.append(r)
        km._post = mock.Mock(side_effect=resp)
        return km

    def test_slow_answer_retried_once_with_fresh_challenge(self):
        km = self._km({"renewed": False, "retry": True, "challenge": "11" * 16, "message": "slow"},
                      {"renewed": True, "challenge": "22" * 16})
        self.assertTrue(km.renew_lease())
        self.assertEqual(km._post.call_count, 2)
        self.assertEqual(km._post.call_args_list[1][0][1]["cr"]["nonce"], "11" * 16)
        self.assertEqual(km.pending_challenge, "22" * 16)

    def test_never_more_than_one_retry(self):
        km = self._km({"renewed": False, "retry": True, "challenge": "11" * 16, "message": "slow"},
                      {"renewed": False, "retry": True, "challenge": "33" * 16, "message": "slow"})
        self.assertFalse(km.renew_lease())
        self.assertEqual(km._post.call_count, 2)

    def test_plain_denial_not_retried(self):
        km = self._km({"renewed": False, "message": "Badge is revoked"})
        self.assertFalse(km.renew_lease())
        self.assertEqual(km._post.call_count, 1)


class AgentChallengeResponse(unittest.TestCase):
    def _agent_with_anchor(self, reply):
        a = make_agent(challenge_response=True)
        import threading

        def fake_write(line):
            _, nonce, delay = line.split()
            threading.Timer(0.01, lambda: a._on_cr_result(reply(nonce, int(delay)))).start()
            return True

        a.serial_reader.write_line = fake_write
        return a

    def test_answer_returned_to_server_format(self):
        a = self._agent_with_anchor(lambda n, d: {"cr": 1, "n": n, "r": "ab" * 8, "rtt": 9500, "d": d, "a": "cd" * 16})
        res = a.answer_challenge("00" * 16)
        self.assertEqual(res, {"nonce": "00" * 16, "resp": "ab" * 8, "rtt_us": 9500, "att": "cd" * 16})
        self.assertTrue(a.engine.key_manager.cr_enabled)

    def test_anchor_failure_gives_none(self):
        a = self._agent_with_anchor(lambda n, d: {"cr": 0, "n": n, "err": "timeout"})
        self.assertIsNone(a.answer_challenge("11" * 16))

    def test_no_answer_times_out(self):
        a = make_agent(challenge_response=True)
        a.serial_reader.write_line = lambda line: True
        self.assertIsNone(a.answer_challenge("22" * 16, timeout=0.2))


class SerialThreadNotBlocked(unittest.TestCase):
    def test_unlock_with_cr_when_answer_arrives_on_serial_thread(self):
        """Regression: an unlock must not block the thread that delivers the anchor's answer."""
        import queue, threading
        a = make_agent(challenge_response=True)
        inbox = queue.Queue()          # what the anchor would send over serial

        def fake_write(line):           # agent -> anchor
            _, nonce, delay = line.split()
            inbox.put({"cr": 1, "n": nonce, "r": "ab" * 8, "rtt": 14200, "k": 3, "a": "cd" * 16})
            return True

        a.serial_reader.write_line = fake_write
        km = a.engine.key_manager
        got = {}

        def fake_unlock():              # what fetch_keys does: ask for a CR answer, then unlock
            got["cr"] = km._answer_challenge("00" * 16)
            a.engine._is_unlocked = got["cr"] is not None
            return 1 if got["cr"] else 0

        a.engine.decrypt_vault = mock.Mock(side_effect=fake_unlock)

        def serial_thread():            # single reader thread, like SerialReader._read_loop
            for i in range(5):
                a._on_badge_detected(reading(-50, 100 + i))
            end = time.time() + 3
            while time.time() < end:
                try:
                    a._on_cr_result(inbox.get(timeout=0.05))
                except queue.Empty:
                    pass

        t = threading.Thread(target=serial_thread)
        t.start()
        self.assertTrue(a.wait_transitions(timeout=6))
        t.join()
        self.assertIsNotNone(got.get("cr"), "challenge answer must reach the unlock")
        self.assertEqual(got["cr"]["rtt_us"], 14200)
        self.assertTrue(a.engine.is_unlocked)


class LockOrdering(unittest.TestCase):
    def test_wipe_before_guard_shutdown_and_parallel_stop(self):
        import tempfile
        from agent.file_monitor.engine import FileEncryptionEngine
        d = tempfile.mkdtemp(prefix="sl")
        os.makedirs(os.path.join(d, "v"))
        eng = FileEncryptionEngine(vault_dir=os.path.join(d, "v"), mount_point=os.path.join(d, "m"))
        events = []

        class SlowGuard:
            def __init__(self, name):
                self.name = name
                self._running = True

            def stop(self):
                events.append(("stop_begin", self.name, time.time()))
                time.sleep(0.5)               # like a guard waiting for its next poll
                events.append(("stop_end", self.name, time.time()))

        for attr in ("_exfil_watcher", "_clipboard_guard", "_screen_guard",
                     "_sandbox_guard", "_usb_guard", "_print_guard"):
            setattr(eng, attr, SlowGuard(attr))
        eng.vault._get_open_file_processes = lambda: []
        guards = eng._guards()

        def fake_unmount():
            events.append(("wiped", "", time.time()))
            self.assertFalse(any(g._running for g in guards), "guards must be told to stop before the wipe")
            return True

        eng.vault.unmount_tmpfs = fake_unmount
        eng._is_unlocked = True
        t0 = time.time()
        eng.lock_vault()
        total = time.time() - t0
        wiped = next(t for e, _, t in events if e == "wiped")
        first_stop = min(t for e, _, t in events if e == "stop_begin")
        self.assertLess(wiped, first_stop, "plaintext must be destroyed before guards stop")
        self.assertLess(wiped - t0, 0.3)
        self.assertLess(total, 1.5, "six 0.5 s guard stops must run in parallel, not 3 s in a row")
        self.assertFalse(eng.is_unlocked)

    def test_sandbox_guard_ignores_agent_wipe_after_stop_request(self):
        from agent.file_monitor.sandbox_guard import AppSandboxGuard
        g = AppSandboxGuard.__new__(AppSandboxGuard)
        g._running = False
        g._kill_browsers = mock.Mock()
        g._whitelisted_process_has_file = mock.Mock(return_value=False)
        g._on_vault_file_opened("/mnt/vault/demo.odt")
        g._kill_browsers.assert_not_called()
        g._running = True
        g._on_vault_file_opened("/mnt/vault/demo.odt")
        g._kill_browsers.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
