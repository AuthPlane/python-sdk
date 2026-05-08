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


def test_default_ttl_used_when_expires_in_zero():
    cache = TokenCache(ttl_buffer_seconds=0, default_ttl_seconds=100)
    cache.set("key1", "token", "Bearer", expires_in=0)
    assert cache.get("key1") is not None


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
