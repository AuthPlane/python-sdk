"""Tests for MetadataCache (RFC 8414)."""

import asyncio
import time
from typing import Any

import pytest

from authplane.errors import MetadataFetchError, MissingMetadataEndpointError
from authplane.internal.fetch_result import FetchResult
from authplane.internal.metadata import MetadataCache

SAMPLE_METADATA: dict[str, Any] = {
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/oauth/authorize",
    "token_endpoint": "https://auth.example.com/oauth/token",
    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "scopes_supported": ["read:data", "write:data"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TrackingFetcher:
    """A fetcher that records how many times it was called."""

    def __init__(
        self,
        metadata: dict[str, Any] = SAMPLE_METADATA,
        *,
        raises: Exception | None = None,
        expires_at: float | None = None,
    ) -> None:
        self.calls: dict[str, int] = {"count": 0}
        self._metadata = metadata
        self._raises = raises
        self._expires_at = expires_at

    async def __call__(self) -> FetchResult:
        self.calls["count"] += 1
        if self._raises is not None:
            raise self._raises
        return FetchResult(document=self._metadata, expires_at=self._expires_at)


# ---------------------------------------------------------------------------
# Metadata-specific methods (async getters that auto-load)
# ---------------------------------------------------------------------------


async def test_get_jwks_uri() -> None:
    """get_jwks_uri should auto-load and return jwks_uri."""
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, document_type="metadata")
    jwks_uri = await cache.get_jwks_uri()
    assert jwks_uri == "https://auth.example.com/.well-known/jwks.json"
    assert fetcher.calls["count"] == 1


async def test_get_jwks_uri_uses_cache() -> None:
    """get_jwks_uri should use cache if already loaded."""
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, document_type="metadata")
    # First call loads
    await cache.get_jwks_uri()
    # Second call should use cache
    await cache.get_jwks_uri()
    assert fetcher.calls["count"] == 1


# ---------------------------------------------------------------------------
# get_jwks_uri with missing field (should raise)
# ---------------------------------------------------------------------------


async def test_get_jwks_uri_missing_field() -> None:
    """get_jwks_uri should raise MetadataFetchError if jwks_uri field is missing."""
    metadata_without_jwks: dict[str, Any] = {"issuer": "https://auth.example.com"}
    fetcher = TrackingFetcher(metadata=metadata_without_jwks)
    cache = MetadataCache(fetcher, document_type="metadata")

    with pytest.raises(MetadataFetchError, match="missing required 'jwks_uri' field"):
        await cache.get_jwks_uri()


async def test_expected_issuer_trailing_slash_is_significant() -> None:
    # Identifiers are compared byte-for-byte (RFC 8414 §3.3). A
    # configured issuer that differs from the advertised metadata issuer only
    # by a trailing slash is a genuine mismatch and must be rejected, not
    # silently reconciled.
    fetcher = TrackingFetcher(metadata=SAMPLE_METADATA)  # issuer has no trailing slash
    cache = MetadataCache(
        fetcher,
        expected_issuer="https://auth.example.com/",
        document_type="metadata",
    )

    with pytest.raises(MetadataFetchError, match="issuer mismatch"):
        await cache.get()


# ---------------------------------------------------------------------------
# Basic cache behavior (inherited from DocumentCache)
# ---------------------------------------------------------------------------


async def test_first_call_invokes_fetcher() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, document_type="metadata")

    result = await cache.get()

    assert result == SAMPLE_METADATA
    assert fetcher.calls["count"] == 1


async def test_second_call_within_ttl_uses_cache() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, refresh_seconds=3600, document_type="metadata")

    await cache.get()
    await cache.get()

    assert fetcher.calls["count"] == 1


async def test_expired_cache_triggers_refetch() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, refresh_seconds=3600, document_type="metadata")

    await cache.get()
    # Wind cache time back past TTL
    cache._cache_time = time.time() - 3601  # pyright: ignore[reportPrivateUsage]

    await cache.get()

    assert fetcher.calls["count"] == 2


async def test_force_refresh_bypasses_valid_cache() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, refresh_seconds=3600, document_type="metadata")

    await cache.get()
    await cache.get(force_refresh=True)

    assert fetcher.calls["count"] == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


async def test_fetch_failure_with_no_cache_raises() -> None:
    fetcher = TrackingFetcher(raises=RuntimeError("network error"))
    cache = MetadataCache(fetcher, document_type="metadata")

    with pytest.raises(MetadataFetchError, match="network error"):
        await cache.get()


async def test_fetch_failure_falls_back_to_stale_cache() -> None:
    good_fetcher = TrackingFetcher(SAMPLE_METADATA)
    cache = MetadataCache(good_fetcher, refresh_seconds=3600, document_type="metadata")

    # Populate cache
    await cache.get()

    # Now swap to a failing fetcher and expire the cache
    cache._fetcher = TrackingFetcher(raises=RuntimeError("network gone"))  # pyright: ignore[reportPrivateUsage]
    cache._cache_time = time.time() - 3601  # pyright: ignore[reportPrivateUsage]

    result = await cache.get()

    # Stale cache is returned instead of raising
    assert result == SAMPLE_METADATA


# ---------------------------------------------------------------------------
# Background refresh
# ---------------------------------------------------------------------------


async def test_background_refresh_triggered_at_80_percent_ttl() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, refresh_seconds=10, document_type="metadata")

    # Populate cache
    await cache.get()
    assert fetcher.calls["count"] == 1

    # Move cache time to 85% of TTL (past the 80% threshold)
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    # This call should return cached value AND kick off background refresh
    result = await cache.get()
    assert result == SAMPLE_METADATA

    # Give the background task a moment to run
    await asyncio.sleep(0.05)

    assert fetcher.calls["count"] == 2
    assert cache._refresh_task is None  # pyright: ignore[reportPrivateUsage]


async def test_background_refresh_not_triggered_before_80_percent_ttl() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, refresh_seconds=10, document_type="metadata")

    await cache.get()

    # 70% of TTL elapsed — should NOT trigger background refresh
    cache._cache_time = time.time() - 7  # pyright: ignore[reportPrivateUsage]

    await cache.get()
    await asyncio.sleep(0.05)

    assert fetcher.calls["count"] == 1
    assert cache._refresh_task is None  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# aclose
# ---------------------------------------------------------------------------


async def test_aclose_cancels_running_background_task() -> None:
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, refresh_seconds=10, document_type="metadata")

    await cache.get()
    cache._cache_time = time.time() - 8.5  # pyright: ignore[reportPrivateUsage]

    await cache.get()  # starts background refresh task
    assert cache._refresh_task is not None  # pyright: ignore[reportPrivateUsage]

    # aclose should cancel the task without raising
    await cache.aclose()

    assert cache._refresh_task is None or cache._refresh_task.done()  # pyright: ignore[reportPrivateUsage]


async def test_aclose_is_safe_with_no_task() -> None:
    """aclose should not raise when no background task exists."""
    cache = MetadataCache(TrackingFetcher(), document_type="metadata")
    await cache.aclose()  # nothing to cancel — must not raise


# ---------------------------------------------------------------------------
# get_token_endpoint
# ---------------------------------------------------------------------------


async def test_get_token_endpoint() -> None:
    """get_token_endpoint returns the token_endpoint URL."""
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, document_type="metadata")
    endpoint = await cache.get_token_endpoint()
    assert endpoint == "https://auth.example.com/oauth/token"


async def test_get_token_endpoint_uses_cache() -> None:
    """get_token_endpoint uses cached metadata, does not re-fetch."""
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, document_type="metadata")
    await cache.get_token_endpoint()
    await cache.get_token_endpoint()
    assert fetcher.calls["count"] == 1


async def test_get_token_endpoint_missing_field() -> None:
    """get_token_endpoint raises MetadataFetchError if token_endpoint is absent."""
    metadata_without_token_endpoint: dict[str, Any] = {
        "issuer": "https://auth.example.com",
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
    }
    fetcher = TrackingFetcher(metadata=metadata_without_token_endpoint)
    cache = MetadataCache(fetcher, document_type="metadata")

    with pytest.raises(MetadataFetchError, match="token_endpoint"):
        await cache.get_token_endpoint()


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://[::1/jwks",  # urlsplit itself: "Invalid IPv6 URL"
        "https://auth.example.com:notaport/jwks",  # port cast, at attribute access
        "https://auth.example.com:99999/jwks",  # port out of range
    ],
)
async def test_malformed_endpoint_url_raises_the_sdk_error(bad_url: str) -> None:
    """A malformed authority in AS metadata must not escape as a bare ValueError.

    This value is remote content, and the MCP adapters catch only
    AuthplaneError — so an unwrapped urllib ValueError turns a metadata
    rejection into an unhandled 500. Same guard as ``_split_dpop_url`` and
    ``internal/urls.py``; this call site was the one left out of that audit.
    """
    metadata = dict(SAMPLE_METADATA)
    metadata["jwks_uri"] = bad_url

    class BadFetcher:
        async def __call__(self, *_args: Any, **_kwargs: Any) -> FetchResult:
            return FetchResult(document=metadata)

    cache = MetadataCache(BadFetcher(), document_type="metadata")

    with pytest.raises(MetadataFetchError):
        await cache.get_jwks_uri()


# ---------------------------------------------------------------------------
# Forced-read floor, retry floor, and required jwks_uri
# ---------------------------------------------------------------------------


async def test_forced_reads_are_capped_at_one_per_floor() -> None:
    """A `kid` miss must not cost the AS a discovery fetch per request.

    The caller that reaches a forced read has had only its token *header*
    decoded, so the `kid` is attacker-controlled and the forced read bypasses
    `refresh_seconds` by design. Without a floor, invalid tokens drive AS
    discovery traffic one-for-one.
    """
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=3600)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # First miss after boot: admitted, so a real rotation is followed at once.
    await cache.get(force_refresh=True)
    assert fetcher.calls["count"] == 2

    # A flood of misses inside the floor costs the AS nothing more.
    for _ in range(20):
        await cache.get(force_refresh=True)
    assert fetcher.calls["count"] == 2

    # Past the floor — min(refresh_seconds, 60) — the next miss re-reads.
    cache._last_forced_read = time.time() - 61  # pyright: ignore[reportPrivateUsage]
    await cache.get(force_refresh=True)
    assert fetcher.calls["count"] == 3

    await cache.aclose()


async def test_no_forced_read_floor_when_refresh_seconds_is_zero() -> None:
    """`refresh_seconds=0` means "re-read every time" and opts out of the floor."""
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=0)

    await cache.get()
    await cache.get(force_refresh=True)
    await cache.get(force_refresh=True)
    assert fetcher.calls["count"] == 3

    await cache.aclose()


async def test_failed_refresh_is_not_retried_on_every_read() -> None:
    """An unreachable AS must not cost a full fetch per verification.

    A failed fetch does not advance `_cache_time`, so the document reads as
    expired forever and every caller takes the synchronous refetch branch —
    serialized behind the fetch lock, one HTTP timeout each.
    """
    calls = {"count": 0}

    async def flaky() -> FetchResult:
        calls["count"] += 1
        if calls["count"] == 1:
            return FetchResult(document=SAMPLE_METADATA)
        raise MetadataFetchError("endpoint down")

    cache = MetadataCache(flaky, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=1)
    assert await cache.get() == SAMPLE_METADATA

    cache._cache_time = 0  # pyright: ignore[reportPrivateUsage]
    assert await cache.get() == SAMPLE_METADATA
    assert calls["count"] == 2

    # Still expired, but inside the floor: served from cache, no second attempt.
    for _ in range(5):
        assert await cache.get() == SAMPLE_METADATA
    assert calls["count"] == 2

    await cache.aclose()


async def test_refresh_without_jwks_uri_does_not_displace_the_good_document() -> None:
    """The one field the whole mechanism runs on.

    A document that has dropped `jwks_uri` used to validate, commit with a fresh
    timestamp and displace the good one, after which every JWKS fetch raised for
    the rest of the interval and the first genuinely new `kid` failed.
    """
    calls = {"count": 0}

    async def withdrawing() -> FetchResult:
        calls["count"] += 1
        if calls["count"] == 1:
            return FetchResult(document=SAMPLE_METADATA)
        return FetchResult(document={"issuer": SAMPLE_METADATA["issuer"]})

    cache = MetadataCache(withdrawing, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=1)
    assert await cache.get() == SAMPLE_METADATA

    cache._cache_time = 0  # pyright: ignore[reportPrivateUsage]
    assert await cache.get_jwks_uri() == SAMPLE_METADATA["jwks_uri"]
    assert calls["count"] == 2

    await cache.aclose()


async def test_background_refresh_is_not_gated_by_the_forced_read_floor() -> None:
    """The floor is an anti-abuse gate on an externally triggered read.

    A refresh the cache schedules for itself at 80% of its own TTL is not that
    caller. Routing it through the floored override makes it a silent no-op
    whenever 0.8 * refresh_seconds falls below the floor — the downgraded read
    takes the fast path on a document that is by definition still valid, returns,
    and logs a refresh that never happened.
    """
    fetcher = TrackingFetcher()
    cache = MetadataCache(fetcher, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=10)

    await cache.get()
    assert fetcher.calls["count"] == 1

    # Consume the forced-read slot the way a kid miss would.
    await cache.get(force_refresh=True)
    assert fetcher.calls["count"] == 2

    # Past 80% of a 10 s TTL, and inside the 10 s floor. The background refresh
    # must still reach the network.
    cache._cache_time = time.time() - 9  # pyright: ignore[reportPrivateUsage]
    await cache.get()
    refresh_task = cache._refresh_task  # pyright: ignore[reportPrivateUsage]
    assert refresh_task is not None
    await refresh_task
    assert fetcher.calls["count"] == 3

    await cache.aclose()


async def test_missing_jwks_uri_keeps_its_documented_error_type() -> None:
    """`MissingMetadataEndpointError` is a package-root export.

    Moving the check from read time to fetch time must not change what an
    operator's `except` clause catches.
    """
    cache = MetadataCache(
        TrackingFetcher({"issuer": SAMPLE_METADATA["issuer"]}),
        expected_issuer=SAMPLE_METADATA["issuer"],
        refresh_seconds=1,
    )

    with pytest.raises(MissingMetadataEndpointError):
        await cache.get()

    await cache.aclose()


# ---------------------------------------------------------------------------
# Validation precedes the commit — the ordering, per rejectable field
# ---------------------------------------------------------------------------


_GOOD_JWKS_URI = "https://auth.example.com/.well-known/jwks.json"
_DISCOVERY_URL = "https://auth.example.com/.well-known/oauth-authorization-server"


@pytest.mark.parametrize(
    ("rejected_document", "why"),
    [
        (
            {"issuer": "https://auth.example.com", "jwks_uri": "http://auth.example.com/jwks.json"},
            "jwks_uri is not HTTPS",
        ),
        (
            {"issuer": "https://auth.example.com", "jwks_uri": "/relative-jwks"},
            "jwks_uri is not absolute",
        ),
        (
            {
                "issuer": "https://evil.example.com",
                "jwks_uri": "https://evil.example.com/jwks.json",
            },
            "issuer does not match the configured one",
        ),
        (
            {"issuer": "https://auth.example.com"},
            "jwks_uri is absent",
        ),
        (
            {"jwks_uri": "https://auth.example.com/jwks.json"},
            "issuer is absent",
        ),
    ],
)
async def test_a_rejected_refresh_moves_neither_the_document_nor_the_key_source(
    rejected_document: dict[str, Any], why: str
) -> None:
    """A document that fails validation must decide nothing, for every field.

    The location key retrieval fetches from is read out of the cached document,
    so committing first and validating afterwards would let a rejected document
    name it for as long as it sat there. The recorded source is checked
    alongside the contents because that is the value a dependent cache compares
    against to decide whether it is still correctly bound: a rejected document
    that moved it would leave that cache believing it was bound to a location
    this cache had refused.
    """
    calls = {"count": 0}

    async def then_rejected() -> FetchResult:
        calls["count"] += 1
        if calls["count"] == 1:
            return FetchResult(document=SAMPLE_METADATA, source=_DISCOVERY_URL)
        return FetchResult(document=rejected_document, source="https://elsewhere.example.com/meta")

    cache = MetadataCache(
        then_rejected, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=1
    )
    assert await cache.get() == SAMPLE_METADATA
    assert cache._cache_source == _DISCOVERY_URL  # pyright: ignore[reportPrivateUsage]

    # Expire the interval so the next read refetches and is rejected.
    cache._cache_time = 0  # pyright: ignore[reportPrivateUsage]

    assert await cache.get_jwks_uri() == _GOOD_JWKS_URI, why
    assert calls["count"] == 2, "the rejected document was never fetched"
    assert await cache.get() == SAMPLE_METADATA, why
    assert cache._cache_source == _DISCOVERY_URL, why  # pyright: ignore[reportPrivateUsage]

    await cache.aclose()


async def test_a_rejected_refresh_surfaces_no_partial_document_to_a_concurrent_reader() -> None:
    """Ten readers straddling a rejected refresh all see the accepted document.

    One of them takes the refetch and is rejected; the rest must be served the
    document that was last accepted, never the one in the middle of being
    checked.
    """
    calls = {"count": 0}

    async def then_rejected() -> FetchResult:
        calls["count"] += 1
        if calls["count"] == 1:
            return FetchResult(document=SAMPLE_METADATA, source=_DISCOVERY_URL)
        await asyncio.sleep(0)
        return FetchResult(
            document={"issuer": "https://evil.example.com", "jwks_uri": "https://evil/jwks.json"},
            source=_DISCOVERY_URL,
        )

    cache = MetadataCache(
        then_rejected, expected_issuer=SAMPLE_METADATA["issuer"], refresh_seconds=1
    )
    assert await cache.get() == SAMPLE_METADATA

    cache._cache_time = 0  # pyright: ignore[reportPrivateUsage]
    results = await asyncio.gather(*(cache.get_jwks_uri() for _ in range(10)))
    assert results == [_GOOD_JWKS_URI] * 10

    await cache.aclose()
