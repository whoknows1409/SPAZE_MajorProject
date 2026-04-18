"""
SecureZone Agent - Host Workstation Daemon
Manages BLE proximity detection, file encryption/decryption, and ephemeral keys.
"""

import asyncio
import logging
import signal
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("securezone-agent")


class SecureZoneAgent:
    """Main agent orchestrating BLE scanning, key management, and file protection."""

    def __init__(self):
        self.running = False
        self.authorized_badge = None
        self.active_keys = {}  # file_path -> decryption_key

    async def start(self):
        """Start the agent daemon."""
        self.running = True
        logger.info("SecureZone Agent starting...")
        logger.info("Watching for authorized BLE badges...")

        # TODO: Initialize components
        # 1. BLE Scanner (bleak) — detect badges in range
        # 2. Key Manager — request/cache/wipe ephemeral keys
        # 3. File Monitor (watchdog) — watch protected directories

        try:
            while self.running:
                # Main loop: scan → authenticate → manage keys
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            logger.info("Agent shutting down...")
        finally:
            await self.cleanup()

    async def cleanup(self):
        """Securely wipe all keys and shut down."""
        logger.info("Wiping all ephemeral keys from memory...")
        for path, key in self.active_keys.items():
            # Secure memory wipe
            if isinstance(key, bytearray):
                for i in range(len(key)):
                    key[i] = 0
        self.active_keys.clear()
        logger.info("Agent stopped. All keys wiped.")

    def stop(self):
        self.running = False


def main():
    agent = SecureZoneAgent()

    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, initiating shutdown...")
        agent.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    asyncio.run(agent.start())


if __name__ == "__main__":
    main()
