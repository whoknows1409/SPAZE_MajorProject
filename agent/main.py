"""
SPAZE Agent - Host Workstation Daemon
Spatially Constrained Zero-Trust File Encryption

Reads BLE proximity data from the ESP32 anchor node via USB serial,
runs a 4-stage RSSI filter pipeline, and manages file encryption/decryption
based on badge proximity.

v2.5: Secure tmpfs mount + Firejail sandbox integration.
"""

import argparse
import logging
import queue
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from .ble_scanner.serial_reader import SerialReader
from .ble_scanner.filters import (
    RSSIFilterPipeline,
    FilterConfig,
    ProximityState,
)
from .file_monitor.engine import FileEncryptionEngine
from . import trace

# Presence token layout (see server/security/pakl.py):
# [FF FF][5A][ver][badge_id:4][counter:4][tag:8]
TOKEN_HEX_LEN = 40
TOKEN_MAX_AGE_S = 5.0     # only forward tokens heard within this window
LEASE_RENEW_S = 3.0       # renew the key lease this often

# ===== Logging Setup =====
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("spaze-agent")


class SPAZEAgent:
    """
    Main SPAZE agent — orchestrates BLE proximity detection
    and file encryption/decryption.
    
    Lifecycle:
    1. Badge IN_RANGE  → decrypt vault files to RAM
    2. Badge OUT_OF_RANGE → wipe keys + destroy plaintext
    """

    def __init__(
        self,
        port: str,
        baud: int,
        vault_dir: str,
        mount_point: str,
        config: Optional[FilterConfig] = None,
        server_url: Optional[str] = None,
        badge_mac: Optional[str] = None,
        security_mode: str = "baseline",
        device_key: Optional[bytes] = None,
        ca_cert: Optional[str] = None,
        badge_id: Optional[int] = None,
        screen_lock: bool = True,
        challenge_response: bool = False,
        cr_emulate_delay_ms: int = 0,
        guardian=None,
    ):
        self.running = False
        self.guardian = guardian
        self.port = port
        self.baud = baud
        self.server_url = server_url
        self.badge_mac = badge_mac

        # Filter pipeline with calibrated thresholds
        self.pipeline = RSSIFilterPipeline(
            config=config or FilterConfig(),
            on_state_change=self._on_state_change,
        )

        # Serial reader
        self.serial_reader = SerialReader(
            port=port,
            baud_rate=baud,
            on_badge_detected=self._on_badge_detected,
            on_cr_result=self._on_cr_result,
        )

        # File encryption engine
        self.engine = FileEncryptionEngine(
            vault_dir=vault_dir,
            mount_point=mount_point,
            server_url=server_url,
            badge_mac=badge_mac,
            security_mode=security_mode,
            device_key=device_key,
            ca_cert=ca_cert,
            guardian=guardian,
        )

        # PAKL: freshest presence token heard from the badge.
        # In PAKL mode the badge is identified by the badge_id inside its
        # signed token, not by its (spoofable) MAC address.
        self.security_mode = security_mode
        self.badge_id = badge_id
        self.screen_lock = screen_lock
        self._token_lock = threading.Lock()
        self._best_token: Optional[str] = None
        self._best_counter: int = -1
        self._best_token_time: float = 0.0
        self._last_renew_attempt: float = 0.0
        if self.engine.server_mode:
            self.engine.key_manager.token_provider = self.current_token

        # PAKL-CR: challenges are relayed to the badge by the anchor, which
        # times and signs the answer
        self.cr_emulate_delay_ms = cr_emulate_delay_ms
        self._cr_cond = threading.Condition()
        self._cr_results: dict = {}
        if self.engine.server_mode and challenge_response:
            self.engine.key_manager.cr_enabled = True
            self.engine.key_manager.cr_provider = self.answer_challenge

        # Serialises vault unlock/lock between the worker thread and main loop
        self._transition_lock = threading.Lock()

        # Unlock/lock run on their own worker thread. They must never run on the
        # serial reader thread: an unlock waits for the anchor's challenge answer,
        # which only the serial reader can deliver.
        self._transitions: "queue.Queue" = queue.Queue()
        self._worker = threading.Thread(target=self._transition_worker, daemon=True)
        self._worker.start()

        # Stats
        self.readings_count = 0
        self.start_time: float = 0

    def start(self):
        """Start the SPAZE agent."""
        self.running = True
        self.start_time = time.time()

        logger.info("=" * 50)
        logger.info("  SPAZE Agent v2.5")
        logger.info("  Spatially Constrained Zero-Trust File Encryption")
        logger.info("=" * 50)
        logger.info(f"Serial port: {self.port}")
        logger.info(f"Filter config:")
        logger.info(f"  EMA α = {self.pipeline.config.ema_alpha}")
        logger.info(f"  Authorize threshold:   {self.pipeline.config.authorize_threshold} dBm")
        logger.info(f"  Deauthorize threshold: {self.pipeline.config.deauthorize_threshold} dBm")
        logger.info(f"  Grace period: {self.pipeline.config.grace_count} readings")
        logger.info(f"  No-reading timeout: {self.pipeline.config.no_reading_timeout}s")
        logger.info(f"Security mode: {self.security_mode}")
        logger.info("")
        trace.event(
            "agent_start",
            security=self.security_mode,
            ema_alpha=self.pipeline.config.ema_alpha,
            kalman_q=self.pipeline.config.kalman_process_noise,
            kalman_r=self.pipeline.config.kalman_measurement_noise,
            authorize=self.pipeline.config.authorize_threshold,
            deauthorize=self.pipeline.config.deauthorize_threshold,
            grace=self.pipeline.config.grace_count,
            timeout=self.pipeline.config.no_reading_timeout,
        )

        # Initialize encryption engine
        self.engine.setup()

        # Show vault status
        status = self.engine.get_status()
        logger.info(f"Vault: {status['encrypted_files']} encrypted files")
        logger.info("")

        # Start reading from serial
        self.serial_reader.start()

        logger.info("Agent running. Waiting for badge detections...")
        logger.info("Press Ctrl+C to stop.\n")

        try:
            while self.running:
                # Check for reading timeout
                self.pipeline.check_timeout()

                # PAKL: keep the key lease alive (or lock if it lapses)
                self._lease_tick()

                # Guardian session lost while unlocked: no kernel gate -> lock
                if self.guardian is not None and not self.guardian.alive and self.engine.is_unlocked:
                    self._lock_for("guardian_lost")

                # Print periodic status
                if self.readings_count > 0 and self.readings_count % 20 == 0:
                    status = self.pipeline.get_status()
                    engine_status = self.engine.get_status()
                    logger.info(
                        f"[Status] proximity={status['state']} | "
                        f"filtered={status['filtered_rssi']} dBm | "
                        f"vault={'UNLOCKED' if engine_status['is_unlocked'] else 'LOCKED'} | "
                        f"keys={engine_status['keys_in_memory']} | "
                        f"readings={self.readings_count}"
                    )

                time.sleep(0.5)

        except KeyboardInterrupt:
            logger.info("\nShutdown requested (Ctrl+C)...")
        finally:
            self.stop()

    def _on_badge_detected(self, data: dict):
        """Callback from SerialReader when a badge scan arrives."""
        rssi = data.get("rssi")
        badge_mac = data.get("badge_mac", "unknown")
        badge_name = data.get("badge_name", "unknown")

        if rssi is None:
            return

        # SECURITY: Only process the authorized badge
        # Ignore any other badges the anchor picks up
        if self.security_mode == "pakl" and self.badge_id is not None:
            if self._token_badge_id(data.get("tok")) != self.badge_id:
                logger.debug(f"Ignoring {badge_name} ({badge_mac}) — no token for badge {self.badge_id}")
                return
        elif self.badge_mac and badge_mac.lower() != self.badge_mac.lower():
            logger.debug(
                f"Ignoring badge {badge_name} ({badge_mac}) — "
                f"not the authorized badge ({self.badge_mac})"
            )
            return

        self.readings_count += 1
        self._remember_token(data.get("tok"))

        # Run through the filter pipeline
        state = self.pipeline.process(rssi)
        trace.event(
            "rssi",
            raw=rssi,
            ema=round(self.pipeline.ema.value, 2),
            kalman=round(self.pipeline.last_filtered_rssi, 2),
            state=state.value,
            grace=self.pipeline.grace.consecutive_count,
            ts=data.get("ts"),
            ctr=self._token_counter(data.get("tok")),
        )

        # Log every reading (debug level)
        logger.debug(
            f"[{badge_name}] raw={rssi} dBm | "
            f"filtered={self.pipeline.last_filtered_rssi:.1f} dBm | "
            f"state={state.value}"
        )

        # Log first detection
        if self.readings_count == 1:
            logger.info(
                f"First badge detected! name={badge_name} mac={badge_mac} rssi={rssi}"
            )

    # ---------------------------------------------------------
    # PAKL: presence tokens and leases
    # ---------------------------------------------------------

    @staticmethod
    def _token_badge_id(tok: Optional[str]) -> Optional[int]:
        if not tok or len(tok) != TOKEN_HEX_LEN:
            return None
        try:
            return int(tok[8:16], 16)
        except ValueError:
            return None

    @staticmethod
    def _token_counter(tok: Optional[str]) -> Optional[int]:
        if not tok or len(tok) != TOKEN_HEX_LEN:
            return None
        try:
            return int(tok[16:24], 16)
        except ValueError:
            return None

    def _remember_token(self, tok: Optional[str]):
        """Keep the token with the highest counter so stale replays cannot displace it."""
        counter = self._token_counter(tok)
        if counter is None:
            return
        with self._token_lock:
            if counter >= self._best_counter:
                self._best_token = tok
                self._best_counter = counter
                self._best_token_time = time.time()

    def current_token(self) -> Optional[str]:
        """Freshest token heard within TOKEN_MAX_AGE_S, else None."""
        with self._token_lock:
            if self._best_token and time.time() - self._best_token_time <= TOKEN_MAX_AGE_S:
                return self._best_token
        return None

    def _lease_tick(self):
        """Renew the key lease periodically; lock the vault if it is denied or lapses."""
        if not self.engine.server_mode or self.security_mode != "pakl":
            return
        if not self.engine.is_unlocked:
            return
        km = self.engine.key_manager
        now = time.time()
        if now - self._last_renew_attempt >= LEASE_RENEW_S:
            self._last_renew_attempt = now
            result = km.renew_lease()
            if result is False:
                self._lock_for("lease_denied")
                return
        if km.lease_expired():
            self._lock_for("lease_expired")

    def _on_cr_result(self, data: dict):
        """Anchor output for a challenge: {"cr":1,"n":..,"r":..,"rtt":..,"a":..} or {"cr":0,...}."""
        with self._cr_cond:
            self._cr_results[data.get("n", "")] = data
            self._cr_cond.notify_all()

    def answer_challenge(self, nonce: str, timeout: float = 5.0) -> Optional[dict]:
        """Send a server challenge to the anchor and wait for the timed, attested answer."""
        delay = max(0, min(255, int(self.cr_emulate_delay_ms)))
        if not self.serial_reader.write_line(f"CHAL {nonce} {delay}"):
            return None
        deadline = time.time() + timeout
        with self._cr_cond:
            while nonce not in self._cr_results:
                left = deadline - time.time()
                if left <= 0:
                    logger.warning("Challenge not answered by anchor in time")
                    return None
                self._cr_cond.wait(left)
            res = self._cr_results.pop(nonce)
        trace.event("cr_anchor", ok=int(bool(res.get("cr"))), rtts=res.get("rtts", ""),
                    err=res.get("err", ""))
        if not res.get("cr"):
            logger.warning(f"Challenge failed at anchor: {res.get('err')}")
            return None
        return {"nonce": nonce, "resp": res["r"], "rtt_us": int(res["rtt"]), "att": res["a"]}

    def _lock_for(self, reason: str):
        """Lock the vault for a server-side reason and re-arm the proximity pipeline."""
        with self._transition_lock:
            if not self.engine.is_unlocked:
                return
            logger.warning(f"🔴 LOCKING VAULT — {reason}")
            trace.event("forced_lock", reason=reason)
            self.engine.lock_vault()
            self._lock_screen()
        # Require a fresh IN_RANGE transition (grace period) before retrying
        self.pipeline.state = ProximityState.OUT_OF_RANGE
        self.pipeline.grace.reset()

    def _on_state_change(
        self,
        old_state: ProximityState,
        new_state: ProximityState,
        filtered_rssi: float,
    ):
        """Callback when proximity state changes — queues the unlock/lock for the worker."""
        trace.event("state_change", old=old_state.value, new=new_state.value,
                    rssi=round(filtered_rssi, 2))
        self._transitions.put((new_state, filtered_rssi))

    def _transition_worker(self):
        while True:
            new_state, filtered_rssi = self._transitions.get()
            try:
                with self._transition_lock:
                    self._handle_state_change(new_state, filtered_rssi)
            except Exception as e:
                logger.error(f"State transition failed: {e}")
            finally:
                self._transitions.task_done()

    def wait_transitions(self, timeout: float = 10.0) -> bool:
        """Block until queued unlock/lock work is done (used by tests)."""
        end = time.time() + timeout
        while self._transitions.unfinished_tasks and time.time() < end:
            time.sleep(0.01)
        return not self._transitions.unfinished_tasks

    def _handle_state_change(self, new_state: ProximityState, filtered_rssi: float):
        if new_state == ProximityState.IN_RANGE:
            logger.info("=" * 50)
            logger.info("🟢 BADGE IN RANGE — UNLOCKING VAULT")
            logger.info(f"   Filtered RSSI: {filtered_rssi:.1f} dBm")
            logger.info("=" * 50)

            # Decrypt all vault files to RAM
            count = self.engine.decrypt_vault()
            if count > 0:
                logger.info(f"📂 {count} files now available at: {self.engine.vault.mount_point}")
            elif count == 0 and self.engine.is_unlocked:
                logger.info("📂 Vault unlocked (no files or already decrypted)")
            else:
                logger.info("🚫 Vault unlock DENIED by server")
                # Re-arm so a later IN_RANGE transition retries the request
                self.pipeline.state = ProximityState.OUT_OF_RANGE
                self.pipeline.grace.reset()
                return

            # Log unlock event to server
            if self.engine.server_mode:
                self.engine.key_manager.log_event(
                    action="vault_unlock",
                    details=f"Vault unlocked, {count} files decrypted",
                    rssi_value=int(filtered_rssi),
                )

            # Show mount info
            mount_info = self.engine.vault.get_mount_info()
            if mount_info['real_tmpfs']:
                logger.info("🛡️  Secure tmpfs active (RAM-only, noexec, mode=700)")
            else:
                logger.info("⚠️  Using fallback directory (run setup_sudoers.sh for real tmpfs)")

        elif new_state == ProximityState.OUT_OF_RANGE:
            logger.info("=" * 50)
            logger.info("🔴 BADGE OUT OF RANGE — LOCKING VAULT")
            logger.info(f"   Filtered RSSI: {filtered_rssi:.1f} dBm")
            logger.info("=" * 50)

            # Lock vault: wipe plaintext + wipe keys
            if not self.engine.is_unlocked:
                return
            self.engine.lock_vault()
            logger.info("🔒 All files locked. Plaintext destroyed. Keys wiped.")

            # Lock the Linux session (screen lock)
            self._lock_screen()

    def _lock_screen(self):
        """Lock the Linux desktop session when badge leaves range."""
        if not self.screen_lock:
            return
        import subprocess
        methods = [
            ["loginctl", "lock-session"],
            ["gnome-screensaver-command", "-l"],
            ["xdg-screensaver", "lock"],
        ]
        for cmd in methods:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=3)
                if result.returncode == 0:
                    logger.info("🖥️  Screen LOCKED — session secured")
                    return
            except Exception:
                continue
        logger.warning("Could not lock screen (no supported lock command found)")

    def encrypt_file(self, filepath: str) -> Optional[str]:
        """Encrypt a file and add it to the vault (CLI utility)."""
        return self.engine.encrypt_new_file(filepath)

    def stop(self):
        """Stop the agent gracefully — always lock vault on exit."""
        self.running = False
        self.serial_reader.stop()

        # Always lock vault on shutdown (fail-closed)
        with self._transition_lock:
            if self.engine.is_unlocked:
                logger.info("Shutdown: locking vault before exit...")
                self.engine.lock_vault()
        trace.event("agent_stop")
        trace.close()

        logger.info("SPAZE Agent stopped.")
        logger.info(
            f"Session: {self.readings_count} readings in "
            f"{int(time.time() - self.start_time)}s"
        )


def main():
    parser = argparse.ArgumentParser(
        description="SPAZE Agent — Proximity-Based Zero-Trust File Encryption"
    )
    parser.add_argument(
        "--port", type=str, default="/dev/ttyACM0",
        help="Serial port of ESP32 anchor (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "--baud", type=int, default=115200,
        help="Baud rate (default: 115200)",
    )
    parser.add_argument(
        "--vault", type=str, default=os.path.expanduser("~/spaze-vault"),
        help="Vault directory for encrypted files (default: ~/spaze-vault)",
    )
    parser.add_argument(
        "--mount", type=str, default=os.path.expanduser("~/spaze"),
        help="Decryption mount point (default: ~/spaze)",
    )
    parser.add_argument(
        "--authorize", type=float, default=-75.0,
        help="RSSI authorize threshold in dBm (default: -75.0)",
    )
    parser.add_argument(
        "--deauthorize", type=float, default=-82.0,
        help="RSSI deauthorize threshold in dBm (default: -82.0)",
    )
    parser.add_argument(
        "--grace", type=int, default=5,
        help="Grace period — consecutive readings needed (default: 5)",
    )
    parser.add_argument(
        "--encrypt", type=str, metavar="FILE",
        help="Encrypt a file and add it to the vault, then exit",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    parser.add_argument(
        "--server", type=str, default=None,
        help="SPAZE server URL (e.g. http://localhost:8000). Enables server mode.",
    )
    parser.add_argument(
        "--badge-mac", type=str, default=None,
        help="Badge MAC address for server authentication (e.g. 5c:01:3b:4b:e3:2a)",
    )
    parser.add_argument(
        "--list-ports", action="store_true",
        help="List available serial ports and exit",
    )
    parser.add_argument(
        "--security", choices=["baseline", "pakl"], default="baseline",
        help="baseline = original protocol; pakl = signed requests + presence tokens + key leases",
    )
    parser.add_argument(
        "--device-key-file", type=str, default=None,
        help="File holding this device's hex HMAC key (required for --security pakl)",
    )
    parser.add_argument(
        "--ca-cert", type=str, default=None,
        help="CA/server certificate used to verify an https:// server URL",
    )
    parser.add_argument(
        "--badge-id", type=int, default=None,
        help="PAKL: accept readings only from tokens carrying this badge id",
    )
    parser.add_argument(
        "--challenge-response", action="store_true",
        help="PAKL-CR: answer server challenges via the anchor (timed + attested)",
    )
    parser.add_argument(
        "--cr-emulate-delay-ms", type=int, default=0,
        help="EXPERIMENT ONLY: ask the badge to delay its answer (relay emulation)",
    )
    parser.add_argument(
        "--guardian", nargs="?", const="/run/spaze-guardian.sock", default=None,
        help="Require the privileged vault guardian (default socket /run/spaze-guardian.sock)",
    )
    parser.add_argument(
        "--no-screen-lock", action="store_true",
        help="Do not lock the desktop on vault lock (for timed experiments)",
    )
    parser.add_argument(
        "--trace-csv", type=str, default=None,
        help="Append timestamped agent events to this CSV (for experiments)",
    )

    args = parser.parse_args()

    # List ports mode
    if args.list_ports:
        ports = SerialReader.list_ports()
        if ports:
            print("Available serial ports:")
            for device, desc in ports:
                print(f"  {device} — {desc}")
        else:
            print("No serial ports found.")
        sys.exit(0)

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate server mode args
    if args.server and not args.badge_mac:
        print("❌ --badge-mac is required when using --server")
        sys.exit(1)

    device_key = None
    if args.security == "pakl":
        if not (args.server and args.device_key_file):
            print("❌ --security pakl needs --server and --device-key-file")
            sys.exit(1)
        with open(args.device_key_file) as f:
            device_key = bytes.fromhex(f.read().strip())

    trace.configure(args.trace_csv)

    guardian = None
    if args.guardian:
        from .file_monitor.guardian_client import GuardianClient
        guardian = GuardianClient(args.guardian)
        if not guardian.connect():
            print("❌ --guardian given but the vault guardian is not reachable (fail-closed)")
            sys.exit(1)

    # Build filter config
    config = FilterConfig(
        authorize_threshold=args.authorize,
        deauthorize_threshold=args.deauthorize,
        grace_count=args.grace,
    )

    # Create agent
    agent = SPAZEAgent(
        port=args.port,
        baud=args.baud,
        vault_dir=args.vault,
        mount_point=args.mount,
        config=config,
        server_url=args.server,
        badge_mac=args.badge_mac,
        security_mode=args.security,
        device_key=device_key,
        ca_cert=args.ca_cert,
        badge_id=args.badge_id,
        screen_lock=not args.no_screen_lock,
        challenge_response=args.challenge_response,
        cr_emulate_delay_ms=args.cr_emulate_delay_ms,
        guardian=guardian,
    )

    # Encrypt mode: encrypt a file and exit
    if args.encrypt:
        agent.engine.setup()
        result = agent.encrypt_file(args.encrypt)
        if result:
            print(f"✅ Encrypted: {result}")
        else:
            print(f"❌ Failed to encrypt: {args.encrypt}")
            sys.exit(1)
        sys.exit(0)

    # Handle signals
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        agent.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    agent.start()


import os  # noqa: E402 — needed at top but kept here for import order clarity

if __name__ == "__main__":
    main()
