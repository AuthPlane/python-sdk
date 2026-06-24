"""Tests for TokenCache."""

import time

from authplane.cache import TokenCache


def test_set_and_get():
    cache = TokenCache(ttl_buffer_seconds=0)
    cache.set("key1", "token123", "Bearer", expires_in=3600, scope="read")
    entry = cache.get("key1")
    assert entry is not None
    assert entry.access_token == "token123"
    assert entry.token_type == "Bearer"
    assert entry.scope == "read"


def test_get_returns_none_for_missing():
    cache = TokenCache()
    assert cache.get("nonexistent") is None


def test_expired_entry_returns_none():
    cache = TokenCache(ttl_buffer_seconds=0)
    cache.set("key1", "token", "Bearer", expires_in=1)
    # Simulate expiry
    cache._entries["key1"].expires_at = time.monotonic() - 1  # pyright: ignore[reportPrivateUsage]
    assert cache.get("key1") is None
    assert "key1" not in cache._entries  # pyright: ignore[reportPrivateUsage]


def test_buffer_deduction():
    cache = TokenCache(ttl_buffer_seconds=30.0)
    cache.set("key1", "token", "Bearer", expires_in=31)
    assert cache.get("key1") is not None


def test_skip_cache_when_ttl_too_short():
    cache = TokenCache(ttl_buffer_seconds=30.0)
    cache.set("key1", "token", "Bearer", expires_in=29)
    assert cache.get("key1") is None


def test_default_ttl_used_when_expires_in_is_none():
    """``None`` means the AS omitted ``expires_in``; honor ``default_ttl``."""
    cache = TokenCache(ttl_buffer_seconds=0, default_ttl_seconds=100)
    cache.set("key1", "token", "Bearer", expires_in=None)
    entry = cache.get("key1")
    assert entry is not None
    # ``None`` must round-trip — callers downstream rely on it to
    # distinguish AS-omitted from AS-issued zero.
    assert entry.expires_in is None


def test_zero_expires_in_refuses_to_store():
    """RFC 6749 §5.1: ``expires_in: 0`` is a deliberately-expired one-shot
    token; the cache must refuse to store it so the next ``get`` is a miss
    instead of a default-TTL stale hit.
    """
    cache = TokenCache(ttl_buffer_seconds=0, default_ttl_seconds=100)
    cache.set("key1", "token", "Bearer", expires_in=0)
    assert cache.get("key1") is None


def test_delete():
    cache = TokenCache(ttl_buffer_seconds=0)
    cache.set("key1", "token", "Bearer", expires_in=3600)
    cache.delete("key1")
    assert cache.get("key1") is None


def test_delete_nonexistent_is_noop():
    cache = TokenCache()
    cache.delete("nonexistent")


def test_cache_key_default():
    assert TokenCache.cache_key() == "_default"


def test_cache_key_with_scope():
    assert TokenCache.cache_key("read write") == "read write"


def test_cache_key_sorts_scopes():
    assert TokenCache.cache_key("write read") == "read write"


def test_cache_key_with_resource():
    key = TokenCache.cache_key("read", "https://api.example.com")
    assert key == "read|https://api.example.com"


def test_cache_key_resource_only():
    key = TokenCache.cache_key("", "https://api.example.com")
    assert key == "|https://api.example.com"


# ---------------------------------------------------------------------------
# Bounded LRU
# ---------------------------------------------------------------------------


def test_default_max_entries_matches_cross_sdk_reference():
    """The default cap is 10_000 entries.

    Matches the Java SDK reference (``TokenCacheConfig.DEFAULT_MAX_ENTRIES``)
    so the same workload hits the same eviction watermark across SDKs.
    Verified against the Java source at
    ``core/src/main/java/ai/authplane/sdk/core/TokenCacheConfig.java`` —
    ``public static final int DEFAULT_MAX_ENTRIES = 10_000;``. If either
    side moves, this test catches the drift before a workload notices
    it the hard way.
    """
    assert TokenCache.DEFAULT_MAX_ENTRIES == 10_000


def test_rejects_non_positive_max_entries():
    """A non-positive cap is a programmer-supplied bug, not a runtime
    condition — fail fast at construction so the misconfiguration surfaces
    immediately rather than when the cache happens to overflow."""
    import pytest

    with pytest.raises(ValueError):
        TokenCache(max_entries=0)
    with pytest.raises(ValueError):
        TokenCache(max_entries=-1)


def test_rejects_bool_max_entries():
    """``bool`` is a subclass of ``int`` in Python, so a stray ``True``
    would otherwise silently produce a cap-1 cache. Reject at construction."""
    import pytest

    with pytest.raises(ValueError):
        TokenCache(max_entries=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TokenCache(max_entries=False)  # type: ignore[arg-type]


def test_rejects_float_max_entries():
    """A fractional cap is a programmer bug — reject at construction even
    when the value is integer-valued (e.g. ``10_000.0``) for symmetry with
    the bool rejection."""
    import pytest

    with pytest.raises(ValueError):
        TokenCache(max_entries=1.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TokenCache(max_entries=10_000.0)  # type: ignore[arg-type]


def test_max_entries_property_exposes_configured_cap():
    """Operators can read the cap back without re-threading the constructor
    argument through their own config layer."""
    assert TokenCache().max_entries == TokenCache.DEFAULT_MAX_ENTRIES
    assert TokenCache(max_entries=42).max_entries == 42


def test_evicts_lru_when_cap_exceeded():
    """Inserting a third entry into a cap-2 cache must evict the
    least-recently-used entry."""
    cache = TokenCache(ttl_buffer_seconds=0, max_entries=2)
    cache.set("k1", "v1", "Bearer", expires_in=3600)
    cache.set("k2", "v2", "Bearer", expires_in=3600)
    assert len(cache) == 2
    cache.set("k3", "v3", "Bearer", expires_in=3600)
    assert len(cache) == 2
    assert cache.get("k1") is None
    assert cache.get("k2") is not None
    assert cache.get("k3") is not None


def test_get_bumps_entry_to_mru():
    """A ``get`` hit must promote the entry to MRU so the next overflow
    eviction targets a colder key — pins the touch-on-read behavior."""
    cache = TokenCache(ttl_buffer_seconds=0, max_entries=2)
    cache.set("k1", "v1", "Bearer", expires_in=3600)
    cache.set("k2", "v2", "Bearer", expires_in=3600)
    # Touch k1 — k2 is now the LRU victim.
    assert cache.get("k1") is not None
    cache.set("k3", "v3", "Bearer", expires_in=3600)
    assert cache.get("k1") is not None
    assert cache.get("k2") is None
    assert cache.get("k3") is not None


def test_reset_does_not_grow_size():
    """Re-setting an existing key must not grow the cache."""
    cache = TokenCache(ttl_buffer_seconds=0, max_entries=2)
    cache.set("k1", "v1", "Bearer", expires_in=3600)
    cache.set("k1", "v1-updated", "Bearer", expires_in=3600)
    assert len(cache) == 1
    entry = cache.get("k1")
    assert entry is not None
    assert entry.access_token == "v1-updated"


def test_reset_bumps_entry_to_mru():
    """Touch-on-write: re-setting an existing key bumps it to MRU.

    Without this, the entry stays LRU and gets evicted when a new entry
    lands — which would surprise callers who treat ``set`` as a
    "I care about this entry" signal.
    """
    cache = TokenCache(ttl_buffer_seconds=0, max_entries=2)
    cache.set("k1", "v1", "Bearer", expires_in=3600)
    cache.set("k2", "v2", "Bearer", expires_in=3600)
    cache.set("k1", "v1-updated", "Bearer", expires_in=3600)  # bump k1 to MRU
    cache.set("k3", "v3", "Bearer", expires_in=3600)
    assert cache.get("k1") is not None
    assert cache.get("k2") is None
    assert cache.get("k3") is not None


# ---------------------------------------------------------------------------
# DPoP cnf binding round-trip
# ---------------------------------------------------------------------------


def test_dpop_binding_survives_cache_round_trip():
    # A DPoP-bound token must report its binding when served from cache, not
    # degrade to a bearer-only shape that hides the sender-constrained
    # property (RFC 9449 §6.1).
    cache = TokenCache(ttl_buffer_seconds=0)
    cache.set(
        "key1",
        "dpop-bound-token",
        "DPoP",
        expires_in=3600,
        scope="tools/echo",
        cnf_jkt="thumbprint-abc",
    )
    entry = cache.get("key1")
    assert entry is not None
    assert entry.cnf_jkt == "thumbprint-abc"


def test_set_without_cnf_jkt_defaults_to_empty():
    # Bearer-only tokens (no DPoP binding) keep the empty default so
    # downstream code reading `cnf_jkt` cannot mistake them for bound.
    cache = TokenCache(ttl_buffer_seconds=0)
    cache.set("key1", "bearer-token", "Bearer", expires_in=3600)
    entry = cache.get("key1")
    assert entry is not None
    assert entry.cnf_jkt == ""
