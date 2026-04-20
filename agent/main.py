"""
SPAZE Agent - Host Workstation Daemon
Spatially Constrained Zero-Trust File Encryption

Reads BLE proximity data from the ESP32 anchor node via USB serial,
runs a 4-stage RSSI filter pipeline, and manages file access
based on badge proximity.
"""

import argparse
import logging
import signal
import sys
import time
from typing import Optional

from .ble_scanner.serial_reader import SerialReader
from .ble_scanner.filters import (
    RSSIFilterPipeline,
    FilterConfig,
    ProximityState,
)

# ===== Logging Setup =====
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("spaze-agent")


class SPAZEAgent:
    """
    Main SPAZE agent — orchestrates BLE proximity detection.
    
    Phase 1: Reads serial → filters RSSI → logs proximity state changes.
    Phase 2 will add: file encryption/decryption on state changes.
    """

    def __init__(self, port: str, baud: int, config: Optional[FilterConfig] = None):
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

        # Stats
        self.readings_count = 0
        self.start_time = 0

    def start(self):
        """Start the SPAZE agent."""
        self.running = True
        self.start_time = time.time()

        logger.info("=" * 50)
        logger.info("  SPAZE Agent v1.0")
        logger.info("  Spatially Constrained Zero-Trust File Encryption")
        logger.info("=" * 50)
        logger.info(f"Serial port: {self.port}")
        logger.info(f"Filter config:")
        logger.info(f"  EMA α = {self.pipeline.config.ema_alpha}")
        logger.info(f"  Kalman Q={self.pipeline.config.kalman_process_noise}, R={self.pipeline.config.kalman_measurement_noise}")
        logger.info(f"  Authorize threshold:   {self.pipeline.config.authorize_threshold} dBm")
        logger.info(f"  Deauthorize threshold: {self.pipeline.config.deauthorize_threshold} dBm")
        logger.info(f"  Grace period: {self.pipeline.config.grace_count} readings")
        logger.info(f"  No-reading timeout: {self.pipeline.config.no_reading_timeout}s")
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
                    logger.info(
                        f"[Status] state={status['state']} | "
                        f"filtered={status['filtered_rssi']} dBm | "
                        f"readings={self.readings_count} | "
                        f"uptime={int(time.time() - self.start_time)}s"
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

        # Log every reading (debug level to avoid spam)
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
        """Callback when proximity state changes."""
        if new_state == ProximityState.IN_RANGE:
            logger.info("🟢 BADGE IN RANGE — Files would be DECRYPTED")
            logger.info(f"   Filtered RSSI: {filtered_rssi:.1f} dBm")
            # TODO Phase 2: Request FEK from server → decrypt files to tmpfs

        elif new_state == ProximityState.OUT_OF_RANGE:
            logger.info("🔴 BADGE OUT OF RANGE — Files would be LOCKED")
            logger.info(f"   Filtered RSSI: {filtered_rssi:.1f} dBm")
            # TODO Phase 2: Wipe FEK → unmount tmpfs → lock files

    def stop(self):
        """Stop the agent gracefully."""
        self.running = False
        self.serial_reader.stop()
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
        "--port",
        type=str,
        default="/dev/ttyACM0",
        help="Serial port of the ESP32 anchor node (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=115200,
        help="Baud rate (default: 115200)",
    )
    parser.add_argument(
        "--authorize",
        type=float,
        default=-75.0,
        help="RSSI authorize threshold in dBm (default: -75.0)",
    )
    parser.add_argument(
        "--deauthorize",
        type=float,
        default=-82.0,
        help="RSSI deauthorize threshold in dBm (default: -82.0)",
    )
    parser.add_argument(
        "--grace",
        type=int,
        default=5,
        help="Grace period — consecutive readings before state change (default: 5)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging — shows every RSSI reading",
    )
    parser.add_argument(
        "--list-ports",
        action="store_true",
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

    # Build filter config from CLI args
    config = FilterConfig(
        authorize_threshold=args.authorize,
        deauthorize_threshold=args.deauthorize,
        grace_count=args.grace,
    )

    # Create and start agent
    agent = SPAZEAgent(port=args.port, baud=args.baud, config=config)

    # Handle signals
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        agent.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    agent.start()


if __name__ == "__main__":
    main()
