"""Tests for JWKSCache."""

import asyncio
import time
from typing import Any

import pytest

from authplane.errors import JWKSFetchError
from authplane.internal.document_cache import JWKSCache
from authplane.internal.fetch_result import FetchResult

SAMPLE_JWKS: dict[str, Any] = {
    "keys": [{"kid": "key-1", "kty": "EC"}, {"kid": "key-2", "kty": "RSA"}]
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TrackingFetcher:
    """A fetcher that records how many times it was called."""

    def __init__(
        self,
        jwks: dict[str, Any] = SAMPLE_JWKS,
        *,
        raises: Exception | None = None,
        expires_at: float | None = None,
    ) -> None:
        self.calls: dict[str, int] = {"count": 0}
        self._jwks = jwks
        self._raises = raises
        self._expires_at = expires_at

    async def __call__(self) -> FetchResult:
        self.calls["count"] += 1
        if self._raises is not None:
            raise self._raises
        return FetchResult(document=self._jwks, expires_at=self._expires_at)


# ---------------------------------------------------------------------------
# Basic fetch and cache behaviour
# ---------------------------------------------------------------------------


async def test_first_call_invokes_fetcher() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks")

    result = await cache.get()

    assert result == SAMPLE_JWKS
    assert fetcher.calls["count"] == 1


async def test_second_call_within_ttl_uses_cache() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    await cache.get()

    assert fetcher.calls["count"] == 1


async def test_expired_cache_triggers_refetch() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    # Wind cache time back past TTL
    cache._cache_time = time.time() - 301  # pyright: ignore[reportPrivateUsage]

    await cache.get()

    assert fetcher.calls["count"] == 2


async def test_force_refresh_bypasses_valid_cache() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    await cache.get(force_refresh=True)

    assert fetcher.calls["count"] == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


async def test_fetch_failure_with_no_cache_raises() -> None:
    fetcher = TrackingFetcher(raises=RuntimeError("network error"))
    cache = JWKSCache(fetcher, document_type="jwks")

    with pytest.raises(JWKSFetchError, match="network error"):
        await cache.get()


async def test_fetch_failure_falls_back_to_stale_cache() -> None:
    good_fetcher = TrackingFetcher(SAMPLE_JWKS)
    cache = JWKSCache(good_fetcher, document_type="jwks", refresh_seconds=300)

    # Populate cache
    await cache.get()

    # Now swap to a failing fetcher and expire the cache
    cache._fetcher = TrackingFetcher(raises=RuntimeError("network gone"))  # pyright: ignore[reportPrivateUsage]
    cache._cache_time = time.time() - 301  # pyright: ignore[reportPrivateUsage]

    result = await cache.get()

    # Stale cache is returned instead of raising
    assert result == SAMPLE_JWKS


async def test_force_refresh_failure_falls_back_to_stale_cache() -> None:
    good_fetcher = TrackingFetcher(SAMPLE_JWKS)
    cache = JWKSCache(good_fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()

    cache._fetcher = TrackingFetcher(raises=RuntimeError("oops"))  # pyright: ignore[reportPrivateUsage]

    result = await cache.get(force_refresh=True)

    assert result == SAMPLE_JWKS


# ---------------------------------------------------------------------------
# Double-checked locking: concurrent callers fetch only once
# ---------------------------------------------------------------------------


async def test_concurrent_get_fetches_once() -> None:
    """Two coroutines that race to populate an empty cache call the fetcher once."""
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    results = await asyncio.gather(cache.get(), cache.get())

    assert all(r == SAMPLE_JWKS for r in results)
    assert fetcher.calls["count"] == 1


# ---------------------------------------------------------------------------
# Background refresh
# ---------------------------------------------------------------------------


async def test_background_refresh_triggered_at_80_percent_ttl() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=10)

    # Populate cache
    await cache.get()
    assert fetcher.calls["count"] == 1

    # Move cache time to 85% of TTL (past the 80% threshold)
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    # This call should return cached value AND kick off background refresh
    result = await cache.get()
    assert result == SAMPLE_JWKS

    # Give the background task a moment to run
    await asyncio.sleep(0.05)

    assert fetcher.calls["count"] == 2
    assert cache._refresh_task is None  # pyright: ignore[reportPrivateUsage]


async def test_background_refresh_not_triggered_before_80_percent_ttl() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=10)

    await cache.get()

    # 70% of TTL elapsed — should NOT trigger background refresh
    cache._cache_time = time.time() - 7  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    await asyncio.sleep(0.05)

    assert fetcher.calls["count"] == 1
    assert cache._refresh_task is None  # pyright: ignore[reportPrivateUsage]


async def test_background_refresh_not_duplicated() -> None:
    """A second call while a background refresh is pending does not start another."""
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=10)

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    await cache.get()  # starts background task
    first_task = cache._refresh_task  # pyright: ignore[reportPrivateUsage]

    await cache.get()  # should reuse the same task, not start a new one
    second_task = cache._refresh_task  # pyright: ignore[reportPrivateUsage]

    assert first_task is second_task or second_task is None

    await asyncio.sleep(0.05)


async def test_background_refresh_error_does_not_crash() -> None:
    good_fetcher = TrackingFetcher(SAMPLE_JWKS)
    cache = JWKSCache(good_fetcher, document_type="jwks", refresh_seconds=10)

    await cache.get()

    # Swap to a failing fetcher for the background refresh
    cache._fetcher = TrackingFetcher(raises=RuntimeError("bg fail"))  # pyright: ignore[reportPrivateUsage]
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    # Should not raise
    result = await cache.get()
    assert result == SAMPLE_JWKS

    await asyncio.sleep(0.05)

    # Cache still holds the original good value
    cache._fetcher = TrackingFetcher(SAMPLE_JWKS)  # pyright: ignore[reportPrivateUsage]
    assert cache._cache is SAMPLE_JWKS  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# aclose
# ---------------------------------------------------------------------------


async def test_aclose_cancels_running_background_task() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=10)

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    await cache.get()  # starts background refresh task
    assert cache._refresh_task is not None  # pyright: ignore[reportPrivateUsage]

    # aclose should cancel the task without raising
    await cache.aclose()

    assert cache._refresh_task is None or cache._refresh_task.done()  # pyright: ignore[reportPrivateUsage]


async def test_aclose_is_safe_with_no_task() -> None:
    """aclose should not raise when no background task exists."""
    cache = JWKSCache(TrackingFetcher(), document_type="jwks")
    await cache.aclose()  # nothing to cancel — must not raise


async def test_aclose_is_safe_when_task_already_done() -> None:
    fetcher = TrackingFetcher()
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=10)

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]
    await cache.get()

    # Let background task finish naturally
    await asyncio.sleep(0.05)

    # aclose on an already-done task must not raise
    await cache.aclose()


# ---------------------------------------------------------------------------
# Server cache headers (expires_at) interaction with configured TTL
# ---------------------------------------------------------------------------


async def test_server_expires_at_shorter_than_configured_uses_server() -> None:
    """When server expires_at is earlier than configured TTL, server wins."""
    now = time.time()
    # Server says expire in 5 seconds, configured TTL is 300
    fetcher = TrackingFetcher(expires_at=now + 5)
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # 6 seconds later: past server expiry, but within configured TTL
    cache._cache_time = now - 6  # pyright: ignore[reportPrivateUsage]
    cache._server_expires_at = now - 1  # expired 1s ago  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    assert fetcher.calls["count"] == 2  # refetched due to server expiry


async def test_server_expires_at_longer_than_configured_uses_configured() -> None:
    """When server expires_at is later than configured TTL, configured wins."""
    now = time.time()
    # Server says expire in 600 seconds, configured TTL is 10
    fetcher = TrackingFetcher(expires_at=now + 600)
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=10)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # 11 seconds later: past configured TTL, but within server expiry
    cache._cache_time = time.time() - 11  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    assert fetcher.calls["count"] == 2  # refetched due to configured TTL


async def test_no_server_headers_uses_configured_ttl() -> None:
    """When server sends no cache headers, configured TTL is used."""
    fetcher = TrackingFetcher(expires_at=None)
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # Within configured TTL
    cache._cache_time = time.time() - 100  # pyright: ignore[reportPrivateUsage]
    await cache.get()
    assert fetcher.calls["count"] == 1  # still cached

    # Past configured TTL
    cache._cache_time = time.time() - 301  # pyright: ignore[reportPrivateUsage]
    await cache.get()
    assert fetcher.calls["count"] == 2  # refetched


async def test_server_expires_at_zero_forces_immediate_refetch() -> None:
    """expires_at=0.0 (no-store/no-cache) causes immediate cache miss."""
    fetcher = TrackingFetcher(expires_at=0.0)
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # Even immediately after, cache should miss due to expires_at=0.0
    await cache.get()
    assert fetcher.calls["count"] == 2


async def test_background_refresh_uses_effective_ttl() -> None:
    """Background refresh triggers at 80% of the effective TTL."""
    now = time.time()
    # Server says expire in 10 seconds, configured is 300
    fetcher = TrackingFetcher(expires_at=now + 10)
    cache = JWKSCache(fetcher, document_type="jwks", refresh_seconds=300)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # Move to 85% of the server TTL (8.5s of 10s)
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]
    cache._server_expires_at = time.time() + 1.5  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    await asyncio.sleep(0.05)

    assert fetcher.calls["count"] == 2  # background refresh triggered


# ---------------------------------------------------------------------------
# Change detection and callbacks
# ---------------------------------------------------------------------------


async def test_change_callback_fires_when_document_changes() -> None:
    """Test that on_change callback is invoked when document content changes."""
    doc_v1: dict[str, Any] = {"keys": [{"kid": "key-1"}]}
    doc_v2: dict[str, Any] = {"keys": [{"kid": "key-2"}]}

    change_events: list[dict[str, Any]] = []

    async def on_change(old_doc: dict[str, Any], new_doc: dict[str, Any]) -> None:
        change_events.append({"old": old_doc, "new": new_doc})

    # Fetcher returns different docs on successive calls
    call_count: dict[str, int] = {"count": 0}

    async def fetcher() -> FetchResult:
        call_count["count"] += 1
        doc = doc_v2 if call_count["count"] > 1 else doc_v1
        return FetchResult(document=doc, expires_at=None)

    cache = JWKSCache(fetcher, document_type="jwks", on_change=on_change)

    # First fetch: no callback (no previous cache)
    await cache.get()
    await asyncio.sleep(0.05)  # Allow callback task to run
    assert len(change_events) == 0

    # Second fetch: document changed, callback should fire
    await cache.get(force_refresh=True)
    await asyncio.sleep(0.05)  # Allow callback task to run
    assert len(change_events) == 1
    assert change_events[0]["old"] == doc_v1
    assert change_events[0]["new"] == doc_v2

    await cache.aclose()


async def test_change_callback_not_fired_when_document_unchanged() -> None:
    """Test that on_change callback is NOT invoked when document is identical."""
    doc: dict[str, Any] = {"keys": [{"kid": "key-1"}]}
    change_events: list[dict[str, Any]] = []

    async def on_change(old_doc: dict[str, Any], new_doc: dict[str, Any]) -> None:
        change_events.append({"old": old_doc, "new": new_doc})

    # Fetcher returns same doc every time
    async def fetcher() -> FetchResult:
        return FetchResult(document=doc, expires_at=None)

    cache = JWKSCache(fetcher, document_type="jwks", on_change=on_change)

    # First fetch
    await cache.get()
    await asyncio.sleep(0.05)
    assert len(change_events) == 0

    # Second fetch: same document, callback should NOT fire
    await cache.get(force_refresh=True)
    await asyncio.sleep(0.05)
    assert len(change_events) == 0

    await cache.aclose()


async def test_change_callback_error_does_not_fail_fetch() -> None:
    """Test that errors in on_change callback don't break cache operation."""
    doc_v1: dict[str, Any] = {"keys": [{"kid": "key-1"}]}
    doc_v2: dict[str, Any] = {"keys": [{"kid": "key-2"}]}

    async def broken_callback(_old_doc: dict[str, Any], _new_doc: dict[str, Any]) -> None:
        raise RuntimeError("Callback failed!")

    call_count: dict[str, int] = {"count": 0}

    async def fetcher() -> FetchResult:
        call_count["count"] += 1
        doc = doc_v2 if call_count["count"] > 1 else doc_v1
        return FetchResult(document=doc, expires_at=None)

    cache = JWKSCache(fetcher, document_type="jwks", on_change=broken_callback)

    # First fetch
    result1 = await cache.get()
    assert result1 == doc_v1

    # Second fetch: callback will error but fetch should succeed
    result2 = await cache.get(force_refresh=True)
    await asyncio.sleep(0.05)  # Allow callback task to run
    assert result2 == doc_v2  # Fetch succeeded despite callback error

    await cache.aclose()


async def test_no_callback_when_on_change_is_none() -> None:
    """Test that cache works normally when on_change is not provided."""
    doc_v1: dict[str, Any] = {"keys": [{"kid": "key-1"}]}
    doc_v2: dict[str, Any] = {"keys": [{"kid": "key-2"}]}

    call_count: dict[str, int] = {"count": 0}

    async def fetcher() -> FetchResult:
        call_count["count"] += 1
        doc = doc_v2 if call_count["count"] > 1 else doc_v1
        return FetchResult(document=doc, expires_at=None)

    # No on_change parameter
    cache = JWKSCache(fetcher, document_type="jwks")

    result1 = await cache.get()
    assert result1 == doc_v1

    result2 = await cache.get(force_refresh=True)
    assert result2 == doc_v2

    await cache.aclose()
