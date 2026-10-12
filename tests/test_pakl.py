#!/usr/bin/env python3
"""
Unit tests for PAKL primitives (server/security/pakl.py).

Run: python -m unittest tests/test_pakl.py -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.security import pakl  # noqa: E402

KEY = bytes(range(32))
SLACK = 8.0
REUSE = 5.0


def accept(counter, state, now):
    return pakl.check_freshness(counter, state, now, SLACK, REUSE)


class TokenFormat(unittest.TestCase):
    def test_roundtrip(self):
        tok = pakl.make_token(KEY, 7, 123456)
        parsed = pakl.parse_token(tok)
        self.assertEqual((parsed.badge_id, parsed.counter), (7, 123456))
        self.assertTrue(pakl.verify_token_tag(parsed, KEY))

    def test_wrong_key_rejected(self):
        parsed = pakl.parse_token(pakl.make_token(KEY, 7, 1))
        self.assertFalse(pakl.verify_token_tag(parsed, bytes(32)))

    def test_bit_flip_rejected(self):
        raw = bytearray.fromhex(pakl.make_token(KEY, 7, 1))
        raw[11] ^= 0x01  # change the counter
        self.assertFalse(pakl.verify_token_tag(pakl.parse_token(raw.hex()), KEY))

    def test_malformed(self):
        for bad in ["", "zz", "ffff5a01", "00" * 20, pakl.make_token(KEY, 1, 1)[:-2]]:
            self.assertIsNone(pakl.parse_token(bad))

    def test_firmware_layout(self):
        # [FF FF][5A][01][badge_id BE][counter BE][tag:8]
        raw = bytes.fromhex(pakl.make_token(KEY, 1, 0x01020304))
        self.assertEqual(raw[:4], b"\xff\xff\x5a\x01")
        self.assertEqual(raw[4:8], b"\x00\x00\x00\x01")
        self.assertEqual(raw[8:12], b"\x01\x02\x03\x04")
        self.assertEqual(len(raw), 20)


class Freshness(unittest.TestCase):
    def setUp(self):
        # Badge booted with epoch 3 at server time 1000
        self.c0 = (3 << 20) + 100
        ok, _, self.state = accept(self.c0, pakl.FreshnessState(), 1000.0)
        self.assertTrue(ok)

    def test_live_badge_accepted(self):
        state = self.state
        for i in range(1, 600, 3):  # renewals every 3 s for 10 min
            ok, reason, state = accept(self.c0 + i, state, 1000.0 + i + 0.4)
            self.assertTrue(ok, reason)

    def test_counter_regression_rejected(self):
        ok, reason, _ = accept(self.c0 - 1, self.state, 1001.0)
        self.assertFalse(ok)
        self.assertEqual(reason, "counter_regressed")

    def test_same_counter_short_reuse_only(self):
        self.assertTrue(accept(self.c0, self.state, 1003.0)[0])
        self.assertFalse(accept(self.c0, self.state, 1000.0 + REUSE + 1)[0])

    def test_old_recording_replayed_later_rejected(self):
        # Attacker records token at t=1060 (counter c0+60) while badge is away
        # from the workstation, replays it at t=1200.
        ok, reason, _ = accept(self.c0 + 60, self.state, 1200.0)
        self.assertFalse(ok)
        self.assertEqual(reason, "stale_token")

    def test_replay_within_slack_accepted(self):
        # A replay within TOKEN_SLACK_S of capture is indistinguishable from
        # a relay; this is the documented residual window.
        self.assertTrue(accept(self.c0 + 60, self.state, 1060.0 + SLACK - 1)[0])

    def test_slow_replay_chain_cannot_walk_reference_down(self):
        # Replaying a recording at 1/3 real-time speed must fail quickly
        state, accepted = self.state, 0
        t, c = 1000.0, self.c0
        for _ in range(50):
            t += 3.0
            c += 1
            ok, _, state = accept(c, state, t)
            accepted += ok
        self.assertLess(accepted, 6)

    def test_reboot_jump_accepted(self):
        ok, _, _ = accept((4 << 20) + 2, self.state, 5000.0)
        self.assertTrue(ok)

    def test_slow_badge_clock_drift_tolerated(self):
        # Badge clock 15 ppm slow over 24 h of continuous renewals
        state, t, c_float = self.state, 1000.0, float(self.c0)
        for _ in range(int(86400 / 3)):
            t += 3.0
            c_float += 3.0 * (1 - 15e-6)
            ok, reason, state = accept(int(c_float), state, t)
            self.assertTrue(ok, reason)


    def test_replay_after_long_idle_bounded(self):
        # Badge last seen at t=1000; attacker records at t=1000+86400 (badge still
        # running, not used at this workstation) and replays 30 s later.
        cap = 1000.0 + 86400
        c_cap = self.c0 + 86400
        self.assertFalse(accept(c_cap, self.state, cap + 30)[0])
        # within slack + 2*rho*idle (+1 s quantisation) it is still accepted
        self.assertTrue(accept(c_cap, self.state, cap + SLACK - 1)[0])


class RequestSignatures(unittest.TestCase):
    def test_valid(self):
        sig = pakl.sign_request(KEY, "POST", "/api/keys/request", "1000.0", b"{}")
        self.assertEqual(pakl.verify_request_signature(
            KEY, "POST", "/api/keys/request", "1000.0", b"{}", sig, 1001.0, 30), (True, "ok"))

    def test_body_tamper(self):
        sig = pakl.sign_request(KEY, "POST", "/p", "1000.0", b'{"a":1}')
        self.assertFalse(pakl.verify_request_signature(
            KEY, "POST", "/p", "1000.0", b'{"a":2}', sig, 1000.0, 30)[0])

    def test_skew(self):
        sig = pakl.sign_request(KEY, "POST", "/p", "1000.0", b"")
        self.assertEqual(pakl.verify_request_signature(
            KEY, "POST", "/p", "1000.0", b"", sig, 1100.0, 30)[1], "timestamp_skew")

    def test_missing_signature(self):
        self.assertFalse(pakl.verify_request_signature(
            KEY, "POST", "/p", "1000.0", b"", "", 1000.0, 30)[0])


class FekWrapping(unittest.TestCase):
    def test_roundtrip_and_binding(self):
        fek = os.urandom(32)
        blob = pakl.wrap_fek(KEY, fek, 1, "a.pdf.enc")
        self.assertTrue(pakl.is_wrapped(blob))
        self.assertEqual(pakl.unwrap_fek(KEY, blob, 1, "a.pdf.enc"), fek)
        with self.assertRaises(Exception):
            pakl.unwrap_fek(KEY, blob, 1, "b.pdf.enc")  # AAD binds the file path
        with self.assertRaises(Exception):
            pakl.unwrap_fek(KEY, blob, 2, "a.pdf.enc")  # ... and the device

    def test_legacy_passthrough(self):
        fek = os.urandom(32)
        self.assertEqual(pakl.unwrap_fek(None, fek, 1, "x"), fek)


if __name__ == "__main__":
    unittest.main(verbosity=2)
