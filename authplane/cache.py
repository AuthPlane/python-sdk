"""Token cache with TTL buffer and bounded LRU for client_credentials tokens."""

import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """A cached token."""

    access_token: str
    token_type: str
    expires_in: int
    scope: str
    expires_at: float  # monotonic time


class TokenCache:
    """In-memory token cache with TTL buffer and bounded LRU eviction.

    Tokens are evicted ``ttl_buffer_seconds`` before their actual expiry to
    avoid using tokens that are about to expire.

    The cache is bounded by ``max_entries`` (default 10 000) and evicts the
    least-recently-used entry on overflow. Token-exchange cache keys are
    high-cardinality because the subject token is part of the key, so
    never-re-read keys would otherwise accumulate without bound.

    Recency is tracked via :class:`collections.OrderedDict` — every ``get``
    that hits an entry calls ``move_to_end`` so the iterator's first key
    is always the LRU victim.
    """

    DEFAULT_MAX_ENTRIES = 10_000
    """Default cap on cached entries."""

    def __init__(
        self,
        ttl_buffer_seconds: float = 30.0,
        default_ttl_seconds: float = 3600.0,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        # Strict `type() is int` rather than `isinstance(..., int)` so that
        # `bool` (a subclass of `int`) is rejected — a stray `True` would
        # otherwise silently produce a cap-1 cache. Catches runtime-typed
        # inputs from JSON config that bypass the static type check.
        if type(max_entries) is not int or max_entries <= 0:
            raise ValueError(f"max_entries must be a positive integer, got {max_entries!r}")
        self._ttl_buffer = ttl_buffer_seconds
        self._default_ttl = default_ttl_seconds
        self._max_entries = max_entries
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()

    def __len__(self) -> int:
        """Number of stored entries — useful for tests and operator alerts.

        Steady-state size tracking ``max_entries`` signals the cap is too low.
        """
        return len(self._entries)

    @property
    def max_entries(self) -> int:
        """The configured cap on stored entries.

        Exposed so operators can correlate ``len(cache)`` against the cap
        without having to re-thread the constructor argument through their
        own config layer.
        """
        return self._max_entries

    def get(self, key: str) -> CacheEntry | None:
        """Get a cached entry if it exists and hasn't expired.

        On hit, bumps the entry to MRU so the next overflow eviction
        targets a colder key.
        """
        entry = self._entries.get(key)
        if entry is None:
            return None
        if time.monotonic() >= entry.expires_at:
            del self._entries[key]
            return None
        # Bump to MRU.
        self._entries.move_to_end(key)
        return entry

    def set(
        self,
        key: str,
        access_token: str,
        token_type: str,
        expires_in: int = 0,
        scope: str = "",
    ) -> None:
        """Cache a token. Skips caching if effective TTL <= 0."""
        ttl = (expires_in if expires_in > 0 else self._default_ttl) - self._ttl_buffer
        if ttl <= 0:
            return
        # `move_to_end` after insertion in case the key already exists —
        # a re-set is treated as a touch (the entry the caller just wrote
        # is by definition the most-recently-used).
        self._entries[key] = CacheEntry(
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            scope=scope,
            expires_at=time.monotonic() + ttl,
        )
        self._entries.move_to_end(key)
        # Evict the LRU victim(s) until we're at-or-under the cap. The
        # constructor pins ``max_entries``, so in practice this trims
        # exactly one entry on overflow.
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def delete(self, key: str) -> None:
        """Remove a cached entry."""
        self._entries.pop(key, None)

    @staticmethod
    def cache_key(scope: str = "", resource: str = "") -> str:
        """Generate a deterministic cache key from scope and resource.

        Scopes are sorted for consistency.
        """
        parts = sorted(scope.split()) if scope else []
        scope_part = " ".join(parts)
        if resource:
            return f"{scope_part}|{resource}" if scope_part else f"|{resource}"
        return scope_part or "_default"
