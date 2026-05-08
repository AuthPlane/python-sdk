"""Tests for MetadataCache (RFC 8414)."""

import asyncio
import time
from typing import Any

import pytest

from authplane.errors import MetadataFetchError
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


async def test_expected_issuer_trailing_slash_is_normalized() -> None:
    fetcher = TrackingFetcher(metadata=SAMPLE_METADATA)
    cache = MetadataCache(
        fetcher,
        expected_issuer="https://auth.example.com/",
        document_type="metadata",
    )

    metadata = await cache.get()

    assert metadata["issuer"] == "https://auth.example.com"


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
