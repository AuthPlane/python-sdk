"""Tests for CircuitBreaker."""

import time

from authplane.circuit_breaker import CircuitBreaker


def test_initial_state_is_closed():
    cb = CircuitBreaker()
    assert cb.state == "closed"
    assert cb.allow() is True


def test_stays_closed_under_threshold():
    cb = CircuitBreaker(threshold=3)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "closed"
    assert cb.allow() is True


def test_opens_at_threshold():
    cb = CircuitBreaker(threshold=3)
    for _ in range(3):
        cb.record_failure()
    assert cb.state == "open"
    assert cb.allow() is False


def test_success_resets_failure_count():
    cb = CircuitBreaker(threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.record_success()
    assert cb.state == "closed"
    cb.record_failure()
    cb.record_failure()
    assert cb.allow() is True


def test_half_open_after_cooldown():
    cb = CircuitBreaker(threshold=1, cooldown_seconds=0.1)
    cb.record_failure()
    assert cb.state == "open"
    time.sleep(0.15)
    assert cb.state == "half_open"
    assert cb.allow() is True


def test_half_open_success_closes():
    cb = CircuitBreaker(threshold=1, cooldown_seconds=0.1)
    cb.record_failure()
    time.sleep(0.15)
    assert cb.state == "half_open"
    cb.record_success()
    assert cb.state == "closed"


def test_half_open_failure_reopens():
    cb = CircuitBreaker(threshold=1, cooldown_seconds=0.1)
    cb.record_failure()
    time.sleep(0.15)
    assert cb.allow() is True
    cb.record_failure()
    assert cb.state == "open"


def test_failure_at_cooldown_boundary_without_probe_does_not_reset_timer():
    cb = CircuitBreaker(threshold=1, cooldown_seconds=0.1)
    cb.record_failure()
    opened_at = cb._opened_at  # pyright: ignore[reportPrivateUsage]
    time.sleep(0.15)
    cb.record_failure()
    assert cb.state == "half_open"
    assert cb._opened_at == opened_at  # pyright: ignore[reportPrivateUsage]
