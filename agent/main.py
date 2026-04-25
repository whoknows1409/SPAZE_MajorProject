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
import signal
import sys
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
    ):
        self.running = False
        self.port = port
        self.baud = baud

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
        )

        # File encryption engine
        self.engine = FileEncryptionEngine(
            vault_dir=vault_dir,
            mount_point=mount_point,
        )

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
        logger.info("")

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

        self.readings_count += 1

        # Run through the filter pipeline
        state = self.pipeline.process(rssi)

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

    def _on_state_change(
        self,
        old_state: ProximityState,
        new_state: ProximityState,
        filtered_rssi: float,
    ):
        """Callback when proximity state changes — triggers encrypt/decrypt."""
        if new_state == ProximityState.IN_RANGE:
            logger.info("=" * 50)
            logger.info("🟢 BADGE IN RANGE — UNLOCKING VAULT")
            logger.info(f"   Filtered RSSI: {filtered_rssi:.1f} dBm")
            logger.info("=" * 50)

            # Decrypt all vault files to RAM
            count = self.engine.decrypt_vault()
            if count > 0:
                logger.info(f"📂 {count} files now available at: {self.engine.vault.mount_point}")
            else:
                logger.info("📂 Vault unlocked (no files or already decrypted)")

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
            self.engine.lock_vault()
            logger.info("🔒 All files locked. Plaintext destroyed. Keys wiped.")

    def encrypt_file(self, filepath: str) -> Optional[str]:
        """Encrypt a file and add it to the vault (CLI utility)."""
        return self.engine.encrypt_new_file(filepath)

    def stop(self):
        """Stop the agent gracefully — always lock vault on exit."""
        self.running = False
        self.serial_reader.stop()

        # Always lock vault on shutdown (fail-closed)
        if self.engine.is_unlocked:
            logger.info("Shutdown: locking vault before exit...")
            self.engine.lock_vault()

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
        "--list-ports", action="store_true",
        help="List available serial ports and exit",
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
