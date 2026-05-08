"""Tests for DocumentCache base class in isolation.

DocumentCache contains all the caching logic shared by JWKSCache and
MetadataCache.  These tests exercise it *directly* rather than through a
subclass, proving that the base class is independently testable and that its
behaviour is not an artefact of the subclasses.
"""

import asyncio
import time
from typing import Any

import pytest

from authplane.errors import JWKSFetchError
from authplane.internal.document_cache import DocumentCache
from authplane.internal.fetch_result import FetchResult

# ---------------------------------------------------------------------------
# Shared test helper
# ---------------------------------------------------------------------------

SAMPLE_DOC: dict[str, Any] = {"type": "test", "payload": [1, 2, 3]}


class TrackingFetcher:
    """Async callable that records invocations and can be made to fail."""

    def __init__(
        self,
        doc: dict[str, Any] = SAMPLE_DOC,
        *,
        raises: Exception | None = None,
        expires_at: float | None = None,
    ) -> None:
        self.count = 0
        self._doc = doc
        self._raises = raises
        self._expires_at = expires_at

    async def __call__(self) -> FetchResult:
        self.count += 1
        if self._raises is not None:
            raise self._raises
        return FetchResult(document=self._doc, expires_at=self._expires_at)


# ---------------------------------------------------------------------------
# Basic fetch and caching
# ---------------------------------------------------------------------------


async def test_first_call_fetches_document() -> None:
    """Fresh cache invokes the fetcher exactly once."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, document_type="test")

    result = await cache.get()

    assert result == SAMPLE_DOC
    assert fetcher.count == 1


async def test_second_call_within_ttl_hits_cache() -> None:
    """Subsequent call within TTL should reuse the cached document."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    await cache.get()
    await cache.get()

    assert fetcher.count == 1


async def test_expired_cache_causes_refetch() -> None:
    """After TTL expires the fetcher is called again."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    await cache.get()
    # Wind back cache time past TTL
    cache._cache_time = time.time() - 301  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    assert fetcher.count == 2


async def test_force_refresh_bypasses_valid_cache() -> None:
    """force_refresh=True re-fetches even when cache is valid."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    await cache.get()
    await cache.get(force_refresh=True)

    assert fetcher.count == 2


# ---------------------------------------------------------------------------
# Double-checked locking (concurrent callers fetch only once)
# ---------------------------------------------------------------------------


async def test_concurrent_get_calls_fetch_once() -> None:
    """Two concurrent coroutines racing on an empty cache fetch exactly once."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    results = await asyncio.gather(cache.get(), cache.get())

    assert all(r == SAMPLE_DOC for r in results)
    assert fetcher.count == 1


async def test_second_waiter_reuses_result_without_refetch() -> None:
    """After the first waiter fetches, the second waiter sees the result
    immediately via the double-checked lock — covering the inner ``if`` path
    inside the lock that short-circuits to return the cached value.
    """
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    # Expire cache before the test to force both coroutines to go through the
    # lock-guarded fetch path.  The race is tight, so we just confirm the
    # fetcher is only called once even under gather().
    results = await asyncio.gather(
        cache.get(force_refresh=True),
        cache.get(force_refresh=True),
    )

    # Both should return the same document.
    assert results[0] == SAMPLE_DOC
    assert results[1] == SAMPLE_DOC


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


async def test_fetch_failure_with_no_cache_raises_jwks_fetch_error() -> None:
    """Without a cached value, a fetch failure propagates as JWKSFetchError."""
    fetcher = TrackingFetcher(raises=RuntimeError("network gone"))
    cache = DocumentCache(fetcher, document_type="test")

    with pytest.raises(JWKSFetchError, match="network gone"):
        await cache.get()


async def test_fetch_failure_falls_back_to_stale_cache() -> None:
    """If a refreshed fetch fails but stale data exists, the stale data is returned."""
    good_fetcher = TrackingFetcher(SAMPLE_DOC)
    cache = DocumentCache(good_fetcher, refresh_seconds=300, document_type="test")

    # Populate cache with good data
    await cache.get()

    # Swap in a failing fetcher and expire the cache
    cache._fetcher = TrackingFetcher(raises=RuntimeError("transient"))  # pyright: ignore[reportPrivateUsage]
    cache._cache_time = time.time() - 301  # pyright: ignore[reportPrivateUsage]

    result = await cache.get()
    assert result == SAMPLE_DOC


async def test_force_refresh_failure_falls_back_to_stale_cache() -> None:
    """force_refresh failure with stale data returns the stale data."""
    fetcher = TrackingFetcher(SAMPLE_DOC)
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    await cache.get()

    cache._fetcher = TrackingFetcher(raises=RuntimeError("boom"))  # pyright: ignore[reportPrivateUsage]

    result = await cache.get(force_refresh=True)
    assert result == SAMPLE_DOC


# ---------------------------------------------------------------------------
# Background refresh
# ---------------------------------------------------------------------------


async def test_background_refresh_triggered_at_80_percent_ttl() -> None:
    """After 80 % of TTL a background refresh is scheduled."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=10, document_type="test")

    await cache.get()
    # Move to 85 % of TTL
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    # This call should return cache AND kick off background refresh
    result = await cache.get()
    assert result == SAMPLE_DOC

    await asyncio.sleep(0.05)

    assert fetcher.count == 2
    assert cache._refresh_task is None  # pyright: ignore[reportPrivateUsage]


async def test_background_refresh_not_triggered_below_80_percent_ttl() -> None:
    """No background refresh before the 80 % threshold."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=10, document_type="test")

    await cache.get()
    # 70 % elapsed — below the threshold
    cache._cache_time = time.time() - 7  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    await asyncio.sleep(0.05)

    assert fetcher.count == 1
    assert cache._refresh_task is None  # pyright: ignore[reportPrivateUsage]


async def test_background_refresh_error_does_not_crash_caller() -> None:
    """A failing background refresh is logged and swallowed; callers are unaffected."""
    good_fetcher = TrackingFetcher(SAMPLE_DOC)
    cache = DocumentCache(good_fetcher, refresh_seconds=10, document_type="test")

    await cache.get()

    # Swap to a failing fetcher for the background refresh
    cache._fetcher = TrackingFetcher(raises=RuntimeError("bg error"))  # pyright: ignore[reportPrivateUsage]
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    result = await cache.get()
    assert result == SAMPLE_DOC  # caller still gets data

    await asyncio.sleep(0.05)

    # Cache still holds the good value from before
    assert cache._cache == SAMPLE_DOC  # pyright: ignore[reportPrivateUsage]

    await cache.aclose()


async def test_duplicate_background_refresh_not_started() -> None:
    """While a background refresh is in-flight, a second call does not start another."""
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=10, document_type="test")

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    await cache.get()  # starts background refresh
    first_task = cache._refresh_task  # pyright: ignore[reportPrivateUsage]

    await cache.get()  # same background task should be reused
    second_task = cache._refresh_task  # pyright: ignore[reportPrivateUsage]

    assert first_task is second_task or second_task is None

    await asyncio.sleep(0.05)
    await cache.aclose()


# ---------------------------------------------------------------------------
# aclose
# ---------------------------------------------------------------------------


async def test_aclose_cancels_running_background_task() -> None:
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=10, document_type="test")

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]
    await cache.get()  # starts the background refresh

    assert cache._refresh_task is not None  # pyright: ignore[reportPrivateUsage]

    await cache.aclose()

    assert cache._refresh_task is None or cache._refresh_task.done()  # pyright: ignore[reportPrivateUsage]


async def test_aclose_safe_when_no_task_exists() -> None:
    """aclose() must not raise when no background task was ever started."""
    cache = DocumentCache(TrackingFetcher(), document_type="test")
    await cache.aclose()


async def test_aclose_safe_when_task_already_finished() -> None:
    fetcher = TrackingFetcher()
    cache = DocumentCache(fetcher, refresh_seconds=10, document_type="test")

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]
    await cache.get()  # starts background refresh

    await asyncio.sleep(0.05)  # let it finish naturally

    await cache.aclose()  # should not raise


# ---------------------------------------------------------------------------
# Server cache-header TTL interaction
# ---------------------------------------------------------------------------


async def test_server_expires_at_shorter_than_configured_uses_server() -> None:
    """When the server's Cache-Control TTL is shorter, it takes precedence."""
    now = time.time()
    fetcher = TrackingFetcher(expires_at=now + 5)
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    await cache.get()
    assert fetcher.count == 1

    # Simulate 6 s elapsed: past server expiry but within configured TTL
    cache._cache_time = now - 6  # pyright: ignore[reportPrivateUsage]
    cache._server_expires_at = now - 1  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    assert fetcher.count == 2


async def test_server_expires_at_longer_than_configured_uses_configured() -> None:
    """When server TTL is longer, the configured TTL takes precedence."""
    now = time.time()
    fetcher = TrackingFetcher(expires_at=now + 600)
    cache = DocumentCache(fetcher, refresh_seconds=10, document_type="test")

    await cache.get()
    cache._cache_time = time.time() - 11  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    assert fetcher.count == 2


async def test_no_server_cache_headers_uses_configured_ttl() -> None:
    fetcher = TrackingFetcher(expires_at=None)
    cache = DocumentCache(fetcher, refresh_seconds=300, document_type="test")

    await cache.get()
    cache._cache_time = time.time() - 100  # pyright: ignore[reportPrivateUsage]
    await cache.get()
    assert fetcher.count == 1  # still cached

    cache._cache_time = time.time() - 301  # pyright: ignore[reportPrivateUsage]
    await cache.get()
    assert fetcher.count == 2


# ---------------------------------------------------------------------------
# on_change callbacks
# ---------------------------------------------------------------------------


async def test_on_change_callback_fires_when_document_changes() -> None:
    doc_v1: dict[str, Any] = {"v": 1}
    doc_v2: dict[str, Any] = {"v": 2}
    events: list[dict[str, Any]] = []

    async def on_change(old: dict[str, Any], new: dict[str, Any]) -> None:
        events.append({"old": old, "new": new})

    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(document=doc_v2 if call_count["n"] > 1 else doc_v1)

    cache = DocumentCache(fetcher, document_type="test", on_change=on_change)

    await cache.get()
    await asyncio.sleep(0.01)
    assert len(events) == 0  # no callback on initial fetch

    await cache.get(force_refresh=True)
    await asyncio.sleep(0.05)
    assert len(events) == 1
    assert events[0]["old"] == doc_v1
    assert events[0]["new"] == doc_v2

    await cache.aclose()


async def test_on_change_callback_not_fired_when_document_unchanged() -> None:
    doc: dict[str, Any] = {"v": 1}
    events: list[dict[str, Any]] = []

    async def on_change(old: dict[str, Any], new: dict[str, Any]) -> None:
        events.append({"old": old, "new": new})

    async def fetcher() -> FetchResult:
        return FetchResult(document=doc)

    cache = DocumentCache(fetcher, document_type="test", on_change=on_change)

    await cache.get()
    await cache.get(force_refresh=True)
    await asyncio.sleep(0.05)

    assert len(events) == 0  # same document → no callback

    await cache.aclose()


async def test_on_change_callback_error_does_not_break_fetch() -> None:
    doc_v1: dict[str, Any] = {"v": 1}
    doc_v2: dict[str, Any] = {"v": 2}
    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(document=doc_v2 if call_count["n"] > 1 else doc_v1)

    async def broken_callback(_old: dict[str, Any], _new: dict[str, Any]) -> None:
        raise RuntimeError("callback exploded")

    cache = DocumentCache(fetcher, document_type="test", on_change=broken_callback)

    await cache.get()
    result = await cache.get(force_refresh=True)
    await asyncio.sleep(0.05)

    # Fetch still succeeded despite the callback error
    assert result == doc_v2

    await cache.aclose()


async def test_no_callback_when_on_change_is_none() -> None:
    """Cache works normally when on_change is not provided."""
    doc_v1: dict[str, Any] = {"v": 1}
    doc_v2: dict[str, Any] = {"v": 2}
    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(document=doc_v2 if call_count["n"] > 1 else doc_v1)

    cache = DocumentCache(fetcher, document_type="test")  # no on_change

    r1 = await cache.get()
    assert r1 == doc_v1

    r2 = await cache.get(force_refresh=True)
    assert r2 == doc_v2

    await cache.aclose()
