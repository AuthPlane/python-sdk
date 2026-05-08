"""Circuit breaker for AS resilience."""

import time
from enum import Enum


class _State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Protects against cascading failures when the AS is unavailable."""

    def __init__(
        self,
        threshold: int = 5,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self._threshold = threshold
        self._cooldown_seconds = cooldown_seconds
        self._state = _State.CLOSED
        self._failure_count = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    @property
    def state(self) -> str:
        """Return the current circuit state ('closed', 'open', or 'half_open')."""
        return self._effective_state().value

    def _effective_state(self) -> _State:
        # OPEN transitions to a logical HALF_OPEN view after the cooldown
        # window expires. We delay mutating the stored state until a caller
        # actually attempts the probe so repeated state checks remain cheap.
        if (
            self._state == _State.OPEN
            and time.monotonic() - self._opened_at >= self._cooldown_seconds
        ):
            return _State.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        """Return True if a request should be attempted, False if shed."""
        state = self._effective_state()
        if state == _State.CLOSED:
            return True
        if state == _State.OPEN:
            return False

        # HALF_OPEN allows exactly one in-flight probe. Everybody else keeps
        # seeing the circuit as unavailable until that probe succeeds or fails.
        if self._state != _State.HALF_OPEN:
            self._state = _State.HALF_OPEN
        if self._probe_in_flight:
            return False
        self._probe_in_flight = True
        return True

    def record_success(self) -> None:
        """Record a successful request, closing the circuit if it was half-open."""
        # Any success, including the half-open probe, fully restores traffic.
        self._failure_count = 0
        self._state = _State.CLOSED
        self._probe_in_flight = False

    def record_failure(self) -> None:
        """Record a failed request, opening the circuit when the threshold is reached."""
        effective_state = self._effective_state()
        # A failed half-open probe immediately re-opens the circuit instead of
        # walking failure_count up again.
        if self._probe_in_flight and (
            effective_state == _State.HALF_OPEN or self._state == _State.HALF_OPEN
        ):
            self._state = _State.OPEN
            self._opened_at = time.monotonic()
            self._probe_in_flight = False
            self._failure_count = self._threshold
            return
        if effective_state == _State.HALF_OPEN and self._state == _State.OPEN:
            # Ignore failures that arrive after cooldown but before a probe was
            # actually admitted; they should not reset the cooldown timer.
            return

        self._failure_count += 1
        if self._failure_count >= self._threshold:
            self._state = _State.OPEN
            self._opened_at = time.monotonic()
        self._probe_in_flight = False
