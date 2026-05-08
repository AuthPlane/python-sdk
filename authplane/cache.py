"""Token cache with TTL buffer for client_credentials tokens."""

import time
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
    """In-memory token cache with configurable TTL buffer.

    Tokens are evicted `ttl_buffer_seconds` before their actual expiry
    to avoid using tokens that are about to expire.
    """

    def __init__(
        self,
        ttl_buffer_seconds: float = 30.0,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self._ttl_buffer = ttl_buffer_seconds
        self._default_ttl = default_ttl_seconds
        self._entries: dict[str, CacheEntry] = {}

    def get(self, key: str) -> CacheEntry | None:
        """Get a cached entry if it exists and hasn't expired."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if time.monotonic() >= entry.expires_at:
            del self._entries[key]
            return None
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
        self._entries[key] = CacheEntry(
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            scope=scope,
            expires_at=time.monotonic() + ttl,
        )

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
