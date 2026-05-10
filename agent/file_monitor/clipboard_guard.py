"""
SPAZE - Clipboard Guard

Prevents data exfiltration via copy-paste by monitoring and clearing
the system clipboard while the vault is unlocked.

When a user copies text/content from a vault file, the clipboard is
detected and wiped within 2 seconds, preventing paste into external
apps, email, chat, etc.

Works on X11 (xclip) with Wayland fallback (wl-copy/wl-paste).
"""

import logging
import os
import subprocess
import threading
import time
from typing import Optional, Callable

logger = logging.getLogger("spaze-agent.clipboard-guard")


class ClipboardGuard:
    """
    Monitors the system clipboard and clears it periodically
    while the vault is unlocked to prevent copy-paste leaks.
    """

    def __init__(
        self,
        poll_interval: float = 0.5,
        on_alert: Optional[Callable] = None,
    ):
        self.poll_interval = poll_interval
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._clipboard_tool = self._detect_clipboard_tool()
        self._clear_count = 0

    def _detect_clipboard_tool(self) -> str:
        """Detect which clipboard tool is available."""
        # Check for X11 display
        display = os.environ.get("DISPLAY")
        wayland = os.environ.get("WAYLAND_DISPLAY")

        if display:
            # Try xclip first (most common)
            try:
                subprocess.run(
                    ["which", "xclip"],
                    capture_output=True, timeout=2,
                )
                return "xclip"
            except Exception:
                pass

            # Try xsel
            try:
                subprocess.run(
                    ["which", "xsel"],
                    capture_output=True, timeout=2,
                )
                return "xsel"
            except Exception:
                pass

        if wayland:
            try:
                subprocess.run(
                    ["which", "wl-copy"],
                    capture_output=True, timeout=2,
                )
                return "wl-clipboard"
            except Exception:
                pass

        return "none"

    def _get_clipboard_content(self) -> str:
        """Read current clipboard content."""
        try:
            if self._clipboard_tool == "xclip":
                result = subprocess.run(
                    ["xclip", "-selection", "clipboard", "-o"],
                    capture_output=True, text=True, timeout=2,
                )
                return result.stdout if result.returncode == 0 else ""
            elif self._clipboard_tool == "xsel":
                result = subprocess.run(
                    ["xsel", "--clipboard", "--output"],
                    capture_output=True, text=True, timeout=2,
                )
                return result.stdout if result.returncode == 0 else ""
            elif self._clipboard_tool == "wl-clipboard":
                result = subprocess.run(
                    ["wl-paste", "--no-newline"],
                    capture_output=True, text=True, timeout=2,
                )
                return result.stdout if result.returncode == 0 else ""
        except Exception:
            pass
        return ""

    def _clear_clipboard(self):
        """Overwrite the clipboard with empty content."""
        try:
            if self._clipboard_tool == "xclip":
                proc = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                )
                proc.communicate(input=b"", timeout=2)
            elif self._clipboard_tool == "xsel":
                proc = subprocess.Popen(
                    ["xsel", "--clipboard", "--input"],
                    stdin=subprocess.PIPE,
                )
                proc.communicate(input=b"", timeout=2)
            elif self._clipboard_tool == "wl-clipboard":
                subprocess.run(
                    ["wl-copy", "--clear"],
                    capture_output=True, timeout=2,
                )
        except Exception as e:
            logger.debug(f"Clipboard clear failed: {e}")

    def start(self):
        """Start clipboard monitoring."""
        if self._running:
            return

        if self._clipboard_tool == "none":
            logger.warning("Clipboard guard: no clipboard tool found (install xclip)")
            return

        self._running = True
        self._clear_count = 0
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"📋 Clipboard guard ACTIVE (using {self._clipboard_tool})")

    def stop(self):
        """Stop clipboard monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        if self._clear_count > 0:
            logger.info(f"Clipboard guard stopped — cleared {self._clear_count} time(s)")
        else:
            logger.info("Clipboard guard stopped")

    def _monitor_loop(self):
        """Main monitoring loop — check and clear clipboard."""
        while self._running:
            try:
                content = self._get_clipboard_content()
                if content.strip():
                    # Clipboard has content — clear it
                    self._clear_clipboard()
                    self._clear_count += 1
                    logger.warning(
                        f"📋 Clipboard CLEARED — prevented potential data leak "
                        f"({len(content)} chars wiped)"
                    )

                    # Fire alert callback
                    if self.on_alert:
                        try:
                            self.on_alert(
                                chars_wiped=len(content),
                                preview=content[:50].replace("\n", " "),
                            )
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"Clipboard monitor error: {e}")

            time.sleep(self.poll_interval)
