"""Tests for JWKSCache key-lookup methods.

JWKSCache extends DocumentCache with two JWKS-specific helpers:
  - ``contains_kid(kid)``   — O(n) search returning a bool
  - ``get_key_by_kid(kid)`` — returns the key dict or None

Both are tested in isolation here so that DocumentCache's own behaviour
(caching, TTL, etc.) is not re-tested.
"""

from typing import Any

from authplane.internal.document_cache import JWKSCache
from authplane.internal.fetch_result import FetchResult

SAMPLE_JWKS: dict[str, Any] = {
    "keys": [
        {"kid": "key-rsa", "kty": "RSA", "use": "sig"},
        {"kid": "key-ec", "kty": "EC", "use": "sig"},
    ]
}
EMPTY_JWKS: dict[str, Any] = {"keys": []}
NO_KEYS_FIELD: dict[str, Any] = {"something_else": True}


async def _make_cache(jwks: dict[str, Any] = SAMPLE_JWKS) -> JWKSCache:
    async def fetcher() -> FetchResult:
        return FetchResult(document=jwks)

    cache = JWKSCache(fetcher, document_type="jwks")
    await cache.get()  # warm up cache
    return cache


# ---------------------------------------------------------------------------
# contains_kid
# ---------------------------------------------------------------------------


async def test_contains_kid_returns_true_for_existing_key() -> None:
    cache = await _make_cache()
    assert await cache.contains_kid("key-rsa") is True
    assert await cache.contains_kid("key-ec") is True


async def test_contains_kid_returns_false_for_missing_key() -> None:
    cache = await _make_cache()
    assert await cache.contains_kid("nonexistent-kid") is False


async def test_contains_kid_empty_jwks_returns_false() -> None:
    cache = await _make_cache(EMPTY_JWKS)
    assert await cache.contains_kid("any-kid") is False


async def test_contains_kid_no_keys_field_returns_false() -> None:
    """JWKS document without a 'keys' field should return False gracefully."""
    cache = await _make_cache(NO_KEYS_FIELD)
    assert await cache.contains_kid("any-kid") is False


async def test_contains_kid_force_refresh_triggers_fetch() -> None:
    """force_refresh=True causes the fetcher to be called again."""
    call_count: dict[str, int] = {"n": 0}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        return FetchResult(document=SAMPLE_JWKS)

    cache = JWKSCache(fetcher, document_type="jwks")
    await cache.contains_kid("key-rsa")  # populates cache (1 call)
    await cache.contains_kid("key-rsa", force_refresh=True)  # force re-fetch (2 calls)

    assert call_count["n"] == 2


async def test_contains_kid_ignores_non_signature_keys() -> None:
    cache = await _make_cache({"keys": [{"kid": "key-rsa", "kty": "RSA", "use": "enc"}]})
    assert await cache.contains_kid("key-rsa") is False


# ---------------------------------------------------------------------------
# get_key_by_kid
# ---------------------------------------------------------------------------


async def test_get_key_by_kid_returns_correct_key_dict() -> None:
    cache = await _make_cache()
    key = await cache.get_key_by_kid("key-rsa")
    assert key is not None
    assert key["kid"] == "key-rsa"
    assert key["kty"] == "RSA"


async def test_get_key_by_kid_returns_none_for_missing_kid() -> None:
    cache = await _make_cache()
    assert await cache.get_key_by_kid("does-not-exist") is None


async def test_get_key_by_kid_empty_jwks_returns_none() -> None:
    cache = await _make_cache(EMPTY_JWKS)
    assert await cache.get_key_by_kid("any") is None


async def test_get_key_by_kid_force_refresh() -> None:
    """force_refresh=True re-fetches before searching."""
    call_count: dict[str, int] = {"n": 0}
    new_key: dict[str, Any] = {"kid": "refreshed-key", "kty": "EC"}

    async def fetcher() -> FetchResult:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return FetchResult(document=SAMPLE_JWKS)
        return FetchResult(document={"keys": [new_key]})

    cache = JWKSCache(fetcher, document_type="jwks")
    # First call — cache populated with SAMPLE_JWKS
    assert await cache.get_key_by_kid("key-rsa") is not None

    # After force refresh the JWKS changes; old key gone, new key present
    result = await cache.get_key_by_kid("refreshed-key", force_refresh=True)
    assert result is not None
    assert result["kid"] == "refreshed-key"

    # Old key should no longer be findable
    old = await cache.get_key_by_kid("key-rsa")
    assert old is None
