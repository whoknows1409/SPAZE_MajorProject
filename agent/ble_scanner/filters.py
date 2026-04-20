"""
SPAZE - RSSI Signal Processing Pipeline

4-stage filter pipeline for reliable BLE proximity detection:
  Stage 1: EMA (Exponential Moving Average) — smooths raw RSSI
  Stage 2: Kalman Filter — rejects transient noise
  Stage 3: Hysteresis Thresholding — dual thresholds prevent flicker
  Stage 4: Grace Period — requires N consecutive readings before state change

Calibrated thresholds (from real-world ESP32-WROOM-32 testing):
  Authorize:   -75 dBm  (badge enters 2m range)
  Deauthorize: -82 dBm  (badge exits 2m range)
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("spaze-agent.filters")


class ProximityState(Enum):
    """Badge proximity status."""
    UNKNOWN = "unknown"
    IN_RANGE = "in_range"
    OUT_OF_RANGE = "out_of_range"


@dataclass
class FilterConfig:
    """Configuration for the RSSI filter pipeline."""
    # EMA parameters
    ema_alpha: float = 0.3  # Smoothing factor (0-1, higher = more responsive)

    # Kalman filter parameters
    kalman_process_noise: float = 1.0     # Q: how much we expect RSSI to change
    kalman_measurement_noise: float = 5.0  # R: how noisy the RSSI measurements are

    # Hysteresis thresholds (calibrated from real RSSI test data)
    authorize_threshold: float = -75.0    # RSSI must go ABOVE this to authorize
    deauthorize_threshold: float = -82.0  # RSSI must go BELOW this to deauthorize

    # Grace period
    grace_count: int = 5  # Consecutive readings needed before state change

    # Timeout: if no reading for this many seconds, consider badge gone
    no_reading_timeout: float = 5.0


class EMAFilter:
    """Stage 1: Exponential Moving Average filter."""

    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self.value: Optional[float] = None

    def update(self, raw_rssi: float) -> float:
        if self.value is None:
            self.value = raw_rssi
        else:
            self.value = self.alpha * raw_rssi + (1 - self.alpha) * self.value
        return self.value

    def reset(self):
        self.value = None


class KalmanFilter:
    """Stage 2: 1D Kalman filter for RSSI noise rejection."""

    def __init__(self, process_noise: float = 1.0, measurement_noise: float = 5.0):
        self.Q = process_noise      # Process noise covariance
        self.R = measurement_noise  # Measurement noise covariance
        self.x: Optional[float] = None  # Estimated state (filtered RSSI)
        self.P: float = 1.0             # Estimate error covariance

    def update(self, measurement: float) -> float:
        if self.x is None:
            # First measurement — initialize
            self.x = measurement
            self.P = 1.0
            return self.x

        # Predict step
        # State doesn't change (RSSI is roughly constant when standing still)
        self.P = self.P + self.Q

        # Update step
        K = self.P / (self.P + self.R)  # Kalman gain
        self.x = self.x + K * (measurement - self.x)
        self.P = (1 - K) * self.P

        return self.x

    def reset(self):
        self.x = None
        self.P = 1.0


class HysteresisFilter:
    """Stage 3: Dual-threshold hysteresis to prevent state flickering."""

    def __init__(self, authorize_threshold: float, deauthorize_threshold: float):
        self.authorize_threshold = authorize_threshold
        self.deauthorize_threshold = deauthorize_threshold

    def evaluate(self, filtered_rssi: float, current_state: ProximityState) -> ProximityState:
        """
        Returns the RAW hysteresis decision (before grace period).
        
        Authorize:   filtered_rssi >= authorize_threshold   → IN_RANGE
        Deauthorize: filtered_rssi <= deauthorize_threshold → OUT_OF_RANGE
        In between:  keep current state (the "dead zone")
        """
        if filtered_rssi >= self.authorize_threshold:
            return ProximityState.IN_RANGE
        elif filtered_rssi <= self.deauthorize_threshold:
            return ProximityState.OUT_OF_RANGE
        else:
            # In the hysteresis dead zone — maintain current state
            return current_state


class GracePeriod:
    """Stage 4: Requires N consecutive same-state readings before changing state."""

    def __init__(self, count: int = 5):
        self.required_count = count
        self.pending_state: Optional[ProximityState] = None
        self.consecutive_count: int = 0

    def evaluate(
        self, hysteresis_state: ProximityState, current_state: ProximityState
    ) -> ProximityState:
        """
        Only transitions state after `required_count` consecutive readings
        of the new state.
        """
        if hysteresis_state == current_state:
            # State matches — reset any pending transition
            self.pending_state = None
            self.consecutive_count = 0
            return current_state

        # State differs from current — count consecutive readings
        if hysteresis_state == self.pending_state:
            self.consecutive_count += 1
        else:
            # New pending state — start counting
            self.pending_state = hysteresis_state
            self.consecutive_count = 1

        # Have we reached the threshold?
        if self.consecutive_count >= self.required_count:
            logger.info(
                f"Grace period met: {self.consecutive_count}/{self.required_count} "
                f"→ transitioning to {hysteresis_state.value}"
            )
            self.pending_state = None
            self.consecutive_count = 0
            return hysteresis_state

        logger.debug(
            f"Grace: {self.consecutive_count}/{self.required_count} "
            f"for {hysteresis_state.value}"
        )
        return current_state

    def reset(self):
        self.pending_state = None
        self.consecutive_count = 0


class RSSIFilterPipeline:
    """
    Complete 4-stage RSSI filter pipeline.
    
    Processes raw RSSI readings and outputs a stable ProximityState:
      Raw RSSI → EMA → Kalman → Hysteresis → Grace → Final State
    """

    def __init__(
        self,
        config: Optional[FilterConfig] = None,
        on_state_change: Optional[Callable] = None,
    ):
        self.config = config or FilterConfig()
        self.on_state_change = on_state_change

        # Initialize filter stages
        self.ema = EMAFilter(alpha=self.config.ema_alpha)
        self.kalman = KalmanFilter(
            process_noise=self.config.kalman_process_noise,
            measurement_noise=self.config.kalman_measurement_noise,
        )
        self.hysteresis = HysteresisFilter(
            authorize_threshold=self.config.authorize_threshold,
            deauthorize_threshold=self.config.deauthorize_threshold,
        )
        self.grace = GracePeriod(count=self.config.grace_count)

        # Current state
        self.state = ProximityState.UNKNOWN
        self.last_reading_time: float = 0
        self.last_raw_rssi: float = 0
        self.last_filtered_rssi: float = 0

    def process(self, raw_rssi: float) -> ProximityState:
        """
        Run a single RSSI reading through the full pipeline.
        Returns the current ProximityState after processing.
        """
        self.last_reading_time = time.time()
        self.last_raw_rssi = raw_rssi

        # Stage 1: EMA smoothing
        ema_value = self.ema.update(raw_rssi)

        # Stage 2: Kalman filtering
        kalman_value = self.kalman.update(ema_value)
        self.last_filtered_rssi = kalman_value

        # Stage 3: Hysteresis thresholding
        hysteresis_state = self.hysteresis.evaluate(kalman_value, self.state)

        # Stage 4: Grace period
        new_state = self.grace.evaluate(hysteresis_state, self.state)

        # Check for state change
        if new_state != self.state:
            old_state = self.state
            self.state = new_state
            logger.info(
                f"STATE CHANGE: {old_state.value} → {new_state.value} "
                f"(filtered RSSI: {kalman_value:.1f} dBm)"
            )
            if self.on_state_change:
                self.on_state_change(old_state, new_state, kalman_value)

        return self.state

    def check_timeout(self) -> bool:
        """
        Check if we've timed out waiting for a reading.
        Returns True if timed out (badge likely gone).
        """
        if self.last_reading_time == 0:
            return False

        elapsed = time.time() - self.last_reading_time
        if elapsed > self.config.no_reading_timeout:
            if self.state == ProximityState.IN_RANGE:
                logger.warning(
                    f"No reading for {elapsed:.1f}s — badge likely out of range"
                )
                old_state = self.state
                self.state = ProximityState.OUT_OF_RANGE
                if self.on_state_change:
                    self.on_state_change(old_state, self.state, self.last_filtered_rssi)
                return True
        return False

    def reset(self):
        """Reset all filters to initial state."""
        self.ema.reset()
        self.kalman.reset()
        self.grace.reset()
        self.state = ProximityState.UNKNOWN
        self.last_reading_time = 0

    def get_status(self) -> dict:
        """Return current pipeline status for debugging/logging."""
        return {
            "state": self.state.value,
            "raw_rssi": self.last_raw_rssi,
            "filtered_rssi": round(self.last_filtered_rssi, 1),
            "ema_value": round(self.ema.value, 1) if self.ema.value else None,
            "kalman_value": round(self.kalman.x, 1) if self.kalman.x else None,
            "grace_pending": self.grace.consecutive_count,
            "last_reading_age": round(time.time() - self.last_reading_time, 1)
            if self.last_reading_time
            else None,
        }
