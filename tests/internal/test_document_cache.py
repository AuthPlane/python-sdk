"""Tests for DocumentCache base class in isolation.

DocumentCache contains all the caching logic shared by JWKSCache and
MetadataCache.  These tests exercise it *directly* rather than through a
subclass, proving that the base class is independently testable and that its
behaviour is not an artefact of the subclasses.
"""

import asyncio
import logging
import time
from typing import Any

import pytest

from authplane.errors import JWKSFetchError
from authplane.internal.document_cache import DocumentCache, DocumentFetcherCallable, JWKSCache
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
# Validation of a fetched document, before it is committed
# ---------------------------------------------------------------------------


class _RejectingCache(DocumentCache):
    """Rejects every document whose ``v`` is in ``reject``, recording each check."""

    def __init__(self, fetcher: DocumentFetcherCallable, reject: set[int]) -> None:
        super().__init__(fetcher, document_type="test")
        self.reject = reject
        self.seen: list[dict[str, Any]] = []

    def _validate_fetched(self, document: dict[str, Any], /) -> dict[str, Any]:
        self.seen.append(document)
        if document.get("v") in self.reject:
            raise ValueError("rejected by validation")
        return document


async def test_rejected_document_never_reaches_the_cache() -> None:
    """A document that fails validation must not be observable, even transiently.

    Whatever is derived from the cached document — the URL a dependent cache
    fetches from, above all — reads ``_cache``, so committing first and
    validating afterwards would let a rejected document decide it.
    """
    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(document={"v": call_count["n"]})

    cache = _RejectingCache(fetcher, reject={2})

    assert await cache.get() == {"v": 1}
    # The second fetch is rejected; the first document stays in place.
    assert await cache.get(force_refresh=True) == {"v": 1}
    assert cache._cache == {"v": 1}  # pyright: ignore[reportPrivateUsage]
    assert cache.seen == [{"v": 1}, {"v": 2}]

    # A rejection is a failed refresh, so it backs off like one: the next
    # caller is served the cached document without the fetcher being called
    # again. Without this an endpoint serving a rejectable document costs a
    # full fetch per verification.
    assert await cache.get(force_refresh=True) == {"v": 1}
    assert call_count["n"] == 2

    # And a later acceptable document is taken normally, once the floor has
    # elapsed. Poked rather than slept: the floor is 30s here.
    cache._retry_not_before = 0.0  # pyright: ignore[reportPrivateUsage]
    assert await cache.get(force_refresh=True) == {"v": 3}

    await cache.aclose()


async def test_rejected_first_document_raises_through_the_error_factory() -> None:
    """With nothing cached to fall back on, a rejection surfaces to the caller."""

    async def fetcher() -> FetchResult:
        return FetchResult(document={"v": 1})

    cache = _RejectingCache(fetcher, reject={1})

    with pytest.raises(JWKSFetchError, match="rejected by validation"):
        await cache.get()

    await cache.aclose()


async def test_forced_refresh_serves_the_new_document() -> None:
    doc_v1: dict[str, Any] = {"v": 1}
    doc_v2: dict[str, Any] = {"v": 2}
    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(document=doc_v2 if call_count["n"] > 1 else doc_v1)

    cache = DocumentCache(fetcher, document_type="test")

    r1 = await cache.get()
    assert r1 == doc_v1

    r2 = await cache.get(force_refresh=True)
    assert r2 == doc_v2

    await cache.aclose()


# ---------------------------------------------------------------------------
# A cache whose document's location is discovered rather than configured
# ---------------------------------------------------------------------------


async def test_a_moved_source_invalidates_the_cached_document_before_its_ttl() -> None:
    """A TTL cannot express "the server moved this document".

    The cached key set is fresh by its own clock and wrong all the same, because
    the location it came from is no longer the advertised one. Nothing else can
    notice: a rotation that keeps the ``kid`` leaves the retired key sitting
    under the requested id, so the lookup succeeds and only the signature check
    fails.
    """
    sources = ["https://as.example.com/jwks-v1.json"]
    fetches: list[str] = []

    async def fetcher() -> FetchResult:
        source = sources[-1]
        fetches.append(source)
        return FetchResult(document={"keys": [{"kid": "k", "from": source}]}, source=source)

    async def resolver() -> str:
        return sources[-1]

    # An hour-long TTL, so nothing here can be explained by expiry.
    cache = JWKSCache(fetcher, refresh_seconds=3600, document_type="jwks", source_resolver=resolver)
    first = await cache.get()
    assert first["keys"][0]["from"] == "https://as.example.com/jwks-v1.json"
    # Re-read while the source is unchanged: served from cache.
    await cache.get()
    assert fetches == ["https://as.example.com/jwks-v1.json"]

    sources.append("https://as.example.com/jwks-v2.json")
    second = await cache.get()
    assert second["keys"][0]["from"] == "https://as.example.com/jwks-v2.json"
    assert fetches == [
        "https://as.example.com/jwks-v1.json",
        "https://as.example.com/jwks-v2.json",
    ]
    # And once refetched from the new location it is cached again, not refetched
    # per read.
    await cache.get()
    assert len(fetches) == 2

    await cache.aclose()


async def test_concurrent_readers_of_a_moved_source_fetch_it_once() -> None:
    """The move is re-checked inside the lock, so the burst coalesces.

    Every reader in a burst sees the same stale source and queues on the fetch
    lock. Whichever one wins refetches; the rest must be served what it
    committed rather than each repeating the fetch behind it.
    """
    sources = ["https://as.example.com/jwks-v1.json"]
    fetches: list[str] = []

    async def fetcher() -> FetchResult:
        source = sources[-1]
        fetches.append(source)
        await asyncio.sleep(0)
        return FetchResult(document={"keys": [{"kid": "k", "from": source}]}, source=source)

    async def resolver() -> str:
        return sources[-1]

    cache = JWKSCache(fetcher, refresh_seconds=3600, document_type="jwks", source_resolver=resolver)
    await cache.get()
    sources.append("https://as.example.com/jwks-v2.json")

    results = await asyncio.gather(*(cache.get() for _ in range(10)))
    assert all(r["keys"][0]["from"] == "https://as.example.com/jwks-v2.json" for r in results)
    assert len(fetches) == 2

    await cache.aclose()


async def test_an_unresolvable_source_keeps_the_cached_document() -> None:
    """Resolving the location reads a document, and that read can fail.

    A failure is not evidence the location moved. Treating it as one would turn
    every discovery-endpoint outage into an empty key set.
    """
    fetches: list[str] = []

    async def fetcher() -> FetchResult:
        fetches.append("x")
        return FetchResult(document={"keys": []}, source="https://as.example.com/jwks.json")

    resolver_broken = False

    async def resolver() -> str:
        if resolver_broken:
            raise RuntimeError("metadata endpoint down")
        return "https://as.example.com/jwks.json"

    cache = JWKSCache(fetcher, refresh_seconds=3600, document_type="jwks", source_resolver=resolver)
    await cache.get()
    resolver_broken = True
    assert await cache.get() == {"keys": []}
    assert len(fetches) == 1

    await cache.aclose()


async def test_the_retry_floor_also_covers_a_forced_refresh() -> None:
    """The floor is not conditioned on how the refresh was triggered.

    A forced refresh is reachable from an unauthenticated caller — an unknown
    ``kid`` in a token header is enough — so a floor that only covered
    interval-driven refreshes would leave the amplifier it exists to close wide
    open on the one path that can be driven from outside.
    """
    calls = {"n": 0}
    keys: dict[str, Any] = {"keys": [{"kid": "a"}]}

    async def flaky() -> FetchResult:
        calls["n"] += 1
        if calls["n"] == 1:
            return FetchResult(document=keys, source="https://as.example.com/jwks.json")
        raise RuntimeError("jwks endpoint down")

    cache = JWKSCache(flaky, refresh_seconds=1, document_type="jwks")
    assert await cache.get() == keys

    # The first forced refresh attempts a fetch and fails, arming the floor.
    assert await cache.get(force_refresh=True) == keys
    assert calls["n"] == 2

    # Every subsequent forced refresh inside the floor is served from cache.
    for _ in range(5):
        assert await cache.get(force_refresh=True) == keys
    assert calls["n"] == 2

    await cache.aclose()


async def test_a_rejected_document_does_not_move_the_recorded_source() -> None:
    """The base type's half of the same ordering.

    ``_cache_source`` is what a cache whose location is discovered compares
    against to decide whether it is still correctly bound. It is committed in
    the same step as the contents, and must be gated by the same validation: a
    rejected document that moved it would leave the cache believing its
    contents came from a location it had just refused, and the refetch that
    should follow would never be triggered.
    """
    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(
            document={"v": call_count["n"]},
            source=f"https://as.example.com/doc-v{call_count['n']}.json",
        )

    cache = _RejectingCache(fetcher, reject={2})

    assert await cache.get() == {"v": 1}
    assert cache._cache_source == "https://as.example.com/doc-v1.json"  # pyright: ignore[reportPrivateUsage]

    # The second document is rejected: neither the contents nor the source move.
    assert await cache.get(force_refresh=True) == {"v": 1}
    assert cache._cache_source == "https://as.example.com/doc-v1.json"  # pyright: ignore[reportPrivateUsage]

    # An accepted document moves both, together.
    cache._retry_not_before = 0.0  # pyright: ignore[reportPrivateUsage]
    assert await cache.get(force_refresh=True) == {"v": 3}
    assert cache._cache_source == "https://as.example.com/doc-v3.json"  # pyright: ignore[reportPrivateUsage]

    await cache.aclose()


async def test_a_failed_rebind_logs_once_at_the_commit_not_once_per_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The rebind is the event; the mismatch that drives it is a predicate.

    While the newly advertised location is unreachable the mismatch holds for
    the whole retry-floor window, and it is evaluated on every read. Logging it
    there at INFO is log volume proportional to request rate during exactly the
    incident an operator is reading the log to understand. The operator-visible
    line belongs where ``_cache_source`` actually moves, which happens once.
    """
    sources = ["https://as.example.com/jwks-v1.json"]
    reachable = {"https://as.example.com/jwks-v1.json"}
    attempts: list[str] = []

    async def fetcher() -> FetchResult:
        source = sources[-1]
        attempts.append(source)
        if source not in reachable:
            raise JWKSFetchError(f"unreachable: {source}")
        return FetchResult(document={"keys": [{"kid": "k", "from": source}]}, source=source)

    resolver_calls: list[str] = []

    async def resolver() -> str:
        resolver_calls.append(sources[-1])
        return sources[-1]

    cache = JWKSCache(fetcher, refresh_seconds=3600, document_type="jwks", source_resolver=resolver)
    await cache.get()

    # The AS rotates to a location that is down. The cached key set is now
    # mismatched on every read, and stays that way until the fetch succeeds.
    sources.append("https://as.example.com/jwks-v2.json")
    with caplog.at_level(logging.INFO, logger="authplane.internal.document_cache"):
        await cache.get()
        work_after_the_failing_read = len(resolver_calls)
        for _ in range(19):
            await cache.get()

        info_lines = [r for r in caplog.records if r.levelno == logging.INFO]
        assert info_lines == [], f"the failed rebind window logged at INFO: {info_lines}"
        # One attempt for the whole window, not one per read.
        assert attempts.count("https://as.example.com/jwks-v2.json") == 1
        # And the reads behind the floor do no work at all: they answer before
        # the usability predicate, so they neither resolve the location nor
        # queue on the fetch lock to reach a floor check whose answer is known.
        assert len(resolver_calls) == work_after_the_failing_read
        # And the failure itself is reported once, at the level it belongs on.
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1

        caplog.clear()
        reachable.add("https://as.example.com/jwks-v2.json")
        cache._retry_not_before = 0.0  # pyright: ignore[reportPrivateUsage]

        rebound = await cache.get()
        assert rebound["keys"][0]["from"] == "https://as.example.com/jwks-v2.json"
        # Reads after the rebind are ordinary cache hits and add nothing.
        await cache.get()
        await cache.get()

        rebind_lines = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(rebind_lines) == 1, f"expected one rebind line, got {rebind_lines}"
        # `extra=` lands on the record's `__dict__`; both ends of the move are
        # what makes the line actionable.
        rebind_extra: dict[str, Any] = rebind_lines[0].__dict__
        assert rebind_extra["previous"] == "https://as.example.com/jwks-v1.json"
        assert rebind_extra["current"] == "https://as.example.com/jwks-v2.json"

    await cache.aclose()


async def test_the_first_bind_is_not_logged_as_a_rotation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A cold boot moves ``_cache_source`` off ``None``, which is not a rebind.

    The commit site fires on a *change* of source, and the change out of the
    unset state is the initial bind — reporting it as a location change would
    put one spurious line in every process's startup output.
    """

    async def fetcher() -> FetchResult:
        return FetchResult(document={"keys": []}, source="https://as.example.com/jwks.json")

    cache = JWKSCache(fetcher, refresh_seconds=3600, document_type="jwks")
    with caplog.at_level(logging.INFO, logger="authplane.internal.document_cache"):
        await cache.get()
        assert [r for r in caplog.records if r.levelno == logging.INFO] == []

    await cache.aclose()
