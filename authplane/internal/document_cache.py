"""Document cache with pluggable fetcher (base) and JWKS specialization."""

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

from ..errors import JWKSFetchError
from .fetch_result import FetchResult

logger = logging.getLogger(__name__)

# A coroutine that loads and returns a FetchResult when called.
DocumentFetcherCallable = Callable[[], Awaitable[FetchResult]]

# Callback invoked when a document changes: (old_doc, new_doc) -> None
DocumentChangeCallback = Callable[[dict[str, Any], dict[str, Any]], Awaitable[None]]
DocumentErrorFactory = Callable[[str], Exception]


def _default_document_error(message: str) -> Exception:
    return JWKSFetchError(message)


class DocumentCache:
    """Base cache for JSON documents with TTL, refresh, and stale fallback.

    Provides:
    - TTL-based caching with HTTP cache header awareness
    - Effective TTL = min(configured refresh_seconds, server cache duration)
    - Background refresh at 80% of effective TTL
    - Stale cache fallback on fetch errors
    - Lock-coordinated fetching
    - Optional change notification callback
    """

    def __init__(
        self,
        fetcher: DocumentFetcherCallable,
        refresh_seconds: int = 300,
        document_type: str = "document",
        on_change: DocumentChangeCallback | None = None,
        error_factory: DocumentErrorFactory | None = None,
    ) -> None:
        self._fetcher = fetcher
        self._refresh_seconds = refresh_seconds
        self._document_type = document_type
        self._on_change = on_change
        self._error_factory: DocumentErrorFactory = error_factory or _default_document_error

        self._cache: dict[str, Any] | None = None
        self._cache_time: float = 0
        self._server_expires_at: float | None = None
        self._fetch_lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[None] | None = None
        self._change_task: asyncio.Task[None] | None = None

    def _effective_expires_at(self) -> float:
        """Compute the effective cache expiry timestamp."""
        configured_expires = self._cache_time + self._refresh_seconds
        if self._server_expires_at is not None:
            return min(configured_expires, self._server_expires_at)
        return configured_expires

    async def get(self, force_refresh: bool = False) -> dict[str, Any]:
        """Return the cached document, fetching or refreshing as needed."""
        now = time.time()
        effective_expires = self._effective_expires_at()

        if not force_refresh and self._cache is not None and now < effective_expires:
            # Trigger background refresh at 80% of effective TTL
            effective_ttl = effective_expires - self._cache_time
            if (
                effective_ttl > 0
                and (now - self._cache_time) >= effective_ttl * 0.8
                and self._refresh_task is None
            ):
                self._refresh_task = asyncio.create_task(self._background_refresh())
            return self._cache

        # Acquire the lock so only one coroutine fetches at a time.
        async with self._fetch_lock:
            # Another coroutine may have already refreshed while we waited.
            effective_expires = self._effective_expires_at()
            if not force_refresh and self._cache is not None and time.time() < effective_expires:
                return self._cache

            try:
                fetch_result = await self._fetcher()

                # Capture old cache before updating
                old_cache = self._cache
                new_document = fetch_result.document

                # Update cache
                self._cache = new_document
                self._cache_time = time.time()
                self._server_expires_at = fetch_result.expires_at
                logger.debug("%s fetched and cached", self._document_type.capitalize())

                # Notify callback if document changed
                if (
                    self._on_change is not None
                    and old_cache is not None
                    and old_cache != new_document
                ):
                    self._change_task = asyncio.create_task(
                        self._safe_invoke_callback(old_cache, new_document)
                    )

                return new_document
            except Exception as e:
                if self._cache is not None:
                    logger.warning(
                        "%s fetch failed, using stale cache: %s",
                        self._document_type.capitalize(),
                        e,
                    )
                    return self._cache
                raise self._error_factory(f"Failed to fetch {self._document_type}: {e}") from e

    async def aclose(self) -> None:
        """Cancel any pending background refresh task."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._refresh_task

    async def _background_refresh(self) -> None:
        """Background refresh task."""
        try:
            await self.get(force_refresh=True)
            logger.debug("Background %s refresh completed", self._document_type)
        except Exception as e:
            logger.warning("Background %s refresh failed: %s", self._document_type, e)
        finally:
            self._refresh_task = None

    async def _safe_invoke_callback(self, old_doc: dict[str, Any], new_doc: dict[str, Any]) -> None:
        """Safely invoke the on_change callback with error handling."""
        try:
            if self._on_change is not None:
                await self._on_change(old_doc, new_doc)
        except Exception as e:
            logger.exception(
                "%s change callback raised exception: %s", self._document_type.capitalize(), e
            )


class JWKSCache(DocumentCache):
    """JWKS cache with key ID lookup methods."""

    async def contains_kid(
        self,
        kid: str,
        force_refresh: bool = False,
        algorithm: str | None = None,
    ) -> bool:
        """Check if a usable signature-verification key ID exists in the JWKS."""
        jwks = await self.get(force_refresh=force_refresh)
        for raw_key in jwks.get("keys", []):
            if not isinstance(raw_key, dict):
                continue
            key = cast("dict[str, Any]", raw_key)
            if key.get("kid") != kid:
                continue
            use: str | None = key.get("use")
            if use is not None and use != "sig":
                continue
            key_ops: list[str] | None = key.get("key_ops")
            if isinstance(key_ops, list) and "verify" not in key_ops:
                continue
            jwk_alg: str | None = key.get("alg")
            if algorithm is not None and jwk_alg is not None and jwk_alg != algorithm:
                continue
            return True
        return False

    async def get_key_by_kid(
        self,
        kid: str,
        force_refresh: bool = False,
        algorithm: str | None = None,
    ) -> dict[str, Any] | None:
        """Get a specific key by its key ID."""
        jwks = await self.get(force_refresh=force_refresh)
        for raw_key in jwks.get("keys", []):
            if not isinstance(raw_key, dict):
                continue
            key = cast("dict[str, Any]", raw_key)
            if key.get("kid") != kid:
                continue
            use: str | None = key.get("use")
            if use is not None and use != "sig":
                continue
            key_ops: list[str] | None = key.get("key_ops")
            if isinstance(key_ops, list) and "verify" not in key_ops:
                continue
            jwk_alg: str | None = key.get("alg")
            if algorithm is not None and jwk_alg is not None and jwk_alg != algorithm:
                continue
            return key
        return None
