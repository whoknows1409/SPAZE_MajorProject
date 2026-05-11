"""
SPAZE - Serial Reader Module

Reads JSON data from the ESP32 Anchor node connected via USB Serial.
Each line from the anchor is a JSON object:
  {"anchor":"ANCHOR_WS_01","badge_name":"SZ-BADGE-001","badge_mac":"xx:xx:xx:xx:xx:xx","rssi":-58,"ts":1234}
"""

import json
import logging
import threading
import time
from typing import Callable, Optional

import serial
import serial.tools.list_ports

logger = logging.getLogger("spaze-agent.serial")


class SerialReader:
    """Reads BLE scan results from the ESP32 anchor via USB serial."""

    def __init__(
        self,
        port: str = "/dev/ttyACM0",
        baud_rate: int = 115200,
        on_badge_detected: Optional[Callable] = None,
    ):
        self.port = port
        self.baud_rate = baud_rate
        self.on_badge_detected = on_badge_detected
        self.serial_conn: Optional[serial.Serial] = None
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Open serial connection and start reading in a background thread."""
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baud_rate,
                timeout=1,  # 1 second read timeout
            )

            # Auto-reset ESP32 via DTR toggle (replaces manual EN button press)
            self.serial_conn.dtr = False
            time.sleep(0.1)
            self.serial_conn.dtr = True
            time.sleep(0.5)  # Wait for ESP32 to boot
            self.serial_conn.reset_input_buffer()  # Flush stale boot messages

            self.running = True
            self._thread = threading.Thread(target=self._read_loop, daemon=True)
            self._thread.start()
            logger.info(f"Serial reader started on {self.port} @ {self.baud_rate} baud")
        except serial.SerialException as e:
            logger.error(f"Failed to open serial port {self.port}: {e}")
            raise

    def _read_loop(self):
        """Continuously read lines from serial and parse JSON."""
        while self.running and self.serial_conn and self.serial_conn.is_open:
            try:
                line = self.serial_conn.readline().decode("utf-8", errors="ignore").strip()
                
                if not line:
                    continue

                # Only parse lines that look like JSON (start with '{')
                if not line.startswith("{"):
                    # Boot messages, status lines — skip
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug(f"Non-JSON line: {line}")
                    continue

                # Validate required fields
                if "rssi" in data and "badge_mac" in data:
                    if self.on_badge_detected:
                        self.on_badge_detected(data)
                else:
                    logger.debug(f"Incomplete scan data: {data}")

            except serial.SerialException as e:
                logger.error(f"Serial read error: {e}")
                if self.running:
                    logger.info("Attempting to reconnect in 2 seconds...")
                    time.sleep(2)
                    self._reconnect()

            except Exception as e:
                logger.error(f"Unexpected error in serial read: {e}")

    def _reconnect(self):
        """Try to reconnect to the serial port."""
        try:
            if self.serial_conn:
                self.serial_conn.close()
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baud_rate,
                timeout=1,
            )

            # Auto-reset ESP32 on reconnect too
            self.serial_conn.dtr = False
            time.sleep(0.1)
            self.serial_conn.dtr = True
            time.sleep(0.5)
            self.serial_conn.reset_input_buffer()

            logger.info(f"Reconnected to {self.port}")
        except serial.SerialException:
            logger.warning(f"Reconnect failed, will retry...")

    def stop(self):
        """Stop the reader and close the serial connection."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
            logger.info("Serial connection closed.")

    @staticmethod
    def list_ports():
        """List all available serial ports (useful for auto-detection)."""
        ports = serial.tools.list_ports.comports()
        return [(p.device, p.description) for p in ports]
