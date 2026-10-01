"""Document cache with pluggable fetcher (base) and JWKS specialization."""

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

from ..errors import JWKSFetchError, MetadataFetchError
from .fetch_result import FetchResult

logger = logging.getLogger(__name__)

# A coroutine that loads and returns a FetchResult when called.
DocumentFetcherCallable = Callable[[], Awaitable[FetchResult]]

DocumentErrorFactory = Callable[[str], Exception]

# A coroutine returning the URL a document should currently be fetched from.
DocumentSourceResolver = Callable[[], Awaitable[str]]


def _default_document_error(message: str) -> Exception:
    return JWKSFetchError(message)


#: Ceiling on the post-failure retry floor, in seconds.
_FAILURE_BACKOFF_SECONDS = 30.0

#: Defaults shared by `DocumentCache` and every subclass that forwards them.
#: Held here rather than repeated in each signature: a subclass that restates
#: the literal keeps the old value silently when the base one is changed.
_DEFAULT_REFRESH_SECONDS = 300
_DEFAULT_DOCUMENT_TYPE = "document"


class DocumentCache:
    """Base cache for JSON documents with TTL, refresh, and stale fallback.

    Provides:
    - TTL-based caching with HTTP cache header awareness
    - Effective TTL = min(configured refresh_seconds, server cache duration)
    - Background refresh at 80% of effective TTL
    - Stale cache fallback on fetch errors
    - Lock-coordinated fetching
    - Validation of a fetched document before it is committed
    """

    def __init__(
        self,
        fetcher: DocumentFetcherCallable,
        refresh_seconds: int = _DEFAULT_REFRESH_SECONDS,
        document_type: str = _DEFAULT_DOCUMENT_TYPE,
        error_factory: DocumentErrorFactory | None = None,
    ) -> None:
        self._fetcher = fetcher
        self._refresh_seconds = refresh_seconds
        self._document_type = document_type
        self._error_factory: DocumentErrorFactory = error_factory or _default_document_error

        self._cache: dict[str, Any] | None = None
        self._cache_time: float = 0
        # Where the currently cached document came from. Only meaningful for a
        # document whose location is itself discovered; see `_cache_is_usable`.
        self._cache_source: str | None = None
        self._server_expires_at: float | None = None
        self._fetch_lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[None] | None = None
        self._retry_not_before: float = 0.0

    def _failure_backoff_seconds(self) -> float:
        """Seconds to wait after a failed refresh before attempting another.

        A failed fetch does not advance ``_cache_time``, so without this the
        document stays permanently expired and every reader takes the
        synchronous refetch branch — against an unreachable endpoint that is a
        full HTTP timeout per call, serialized behind ``_fetch_lock``. On the
        verification path, which this cache now sits on, that turns an AS
        outage into a resource-server latency collapse rather than a degraded
        but serviceable one.

        Never longer than the configured interval: a cache asked to refresh
        every five seconds must not be pinned to a thirty-second floor.
        """
        return max(1.0, min(_FAILURE_BACKOFF_SECONDS, float(self._refresh_seconds)))

    def _serve_during_backoff(self) -> dict[str, Any] | None:
        """The cached document while a failed refresh is still being backed off.

        A failed refresh leaves ``_cache_time`` where it was, so the document
        reads as expired and every caller would otherwise take the refetch
        branch again — one full HTTP timeout each, serialized behind
        ``_fetch_lock``. Serve what we have until the floor elapses.

        ``None`` when the floor has passed or there is nothing cached to serve,
        which is the caller's signal to go and fetch.
        """
        if self._cache is None or time.time() >= self._retry_not_before:
            return None
        logger.debug(
            "%s refresh backing off after a failed attempt, serving the cached document",
            self._document_type.capitalize(),
        )
        return self._cache

    def _is_passthrough_error(self, error: Exception, /) -> bool:
        """Whether an error should surface as-is rather than be relabelled.

        Overridden by a subclass whose fetcher resolves its URL through another
        document, where relabelling would point the operator at the wrong one.
        The base cache has no such dependency and relabels everything.
        """
        return False

    def _effective_expires_at(self) -> float:
        """Compute the effective cache expiry timestamp."""
        configured_expires = self._cache_time + self._refresh_seconds
        if self._server_expires_at is not None:
            return min(configured_expires, self._server_expires_at)
        return configured_expires

    async def get(self, force_refresh: bool = False) -> dict[str, Any]:
        """Return the cached document, fetching or refreshing as needed."""
        # Answered before the lock, and before the usability predicate: while a
        # refresh is backing off, every branch below that can be reached with a
        # document in hand returns that same document, so resolving the source,
        # taking the lock and spawning a background refresh are all work whose
        # result is already known. A rebind to an unreachable location holds
        # this state for the whole backoff window and is re-entered by every
        # read, so this is the path that has to stay cheap. The background
        # refresh skipped here would reach this same floor and no-op anyway.
        backoff_document = self._serve_during_backoff()
        if backoff_document is not None:
            return backoff_document

        now = time.time()
        effective_expires = self._effective_expires_at()

        if (
            not force_refresh
            and self._cache is not None
            and now < effective_expires
            and await self._cache_is_usable()
        ):
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
            if (
                not force_refresh
                and self._cache is not None
                and time.time() < effective_expires
                and await self._cache_is_usable()
            ):
                # Re-checked inside the lock, and re-checked including the
                # usability predicate: when two readers both find the cached
                # document unusable they queue here, and the second must see
                # the document the first one committed rather than fetching it
                # a second time.
                return self._cache

            # Re-checked inside the lock: the coroutine we queued behind may
            # have been the one whose failure set the floor.
            backoff_document = self._serve_during_backoff()
            if backoff_document is not None:
                return backoff_document

            try:
                fetch_result = await self._fetcher()
            except Exception as e:
                return self._handle_refresh_failure(e)

            try:
                # Validate before committing, never after reading. `_cache` is
                # what every reader sees, so a document that fails validation
                # must not reach it even transiently: anything derived from the
                # cached document — the URL a dependent cache fetches from, for
                # one — would otherwise be taken from a rejected document.
                new_document = self._validate_fetched(fetch_result.document)
            except Exception as e:
                # Separated from the transport failure above so a rejection is
                # logged as one. A bug in a validator lands here too, and used
                # to be indistinguishable from an unreachable endpoint except by
                # reading the message.
                return self._handle_refresh_failure(e, rejected=True)

            previous_source = self._cache_source
            self._cache = new_document
            self._cache_time = time.time()
            self._server_expires_at = fetch_result.expires_at
            self._cache_source = fetch_result.source
            self._retry_not_before = 0.0
            if previous_source is not None and fetch_result.source != previous_source:
                # The rebind is the event; the mismatch that drives it is a
                # per-read predicate and logs at debug. Emitted here, where
                # `_cache_source` actually moves, this is one line per rotation
                # rather than one per read for as long as the new location
                # stays unreachable. A `None` previous source is the cold-boot
                # bind, not a rotation.
                logger.info(
                    "%s rebound to the newly advertised location",
                    self._document_type.capitalize(),
                    extra={"previous": previous_source, "current": fetch_result.source},
                )
            logger.debug("%s fetched and cached", self._document_type.capitalize())
            return new_document

    def _handle_refresh_failure(
        self, error: Exception, /, *, rejected: bool = False
    ) -> dict[str, Any]:
        """Apply the retry floor, then serve stale or re-raise."""
        self._retry_not_before = time.time() + self._failure_backoff_seconds()
        if self._cache is not None:
            logger.warning(
                "%s %s, keeping the cached document for up to %.0fs: %s",
                self._document_type.capitalize(),
                "document rejected" if rejected else "refresh failed",
                self._failure_backoff_seconds(),
                error,
            )
            return self._cache
        if self._is_passthrough_error(error):
            raise error
        raise self._error_factory(f"Failed to fetch {self._document_type}: {error}") from error

    async def _cache_is_usable(self) -> bool:
        """Whether the cached document may still be served without refetching.

        Consulted only when the document is otherwise fresh, so this is the one
        way a cache can declare its contents stale ahead of their TTL. It exists
        for a document whose *location* is discovered rather than configured: a
        TTL says when the contents may have changed, and says nothing about the
        authorization server having moved them somewhere else in the meantime.

        The base cache fetches from a fixed URL, so its contents can never be
        from the wrong place and it always answers yes.
        """
        return True

    def _validate_fetched(self, document: dict[str, Any], /) -> dict[str, Any]:
        """Check a freshly fetched document before it is committed to the cache.

        Raising here leaves the previously cached document in place, so a
        rejected document is never observable. The base implementation accepts
        every document; subclasses that carry a document format override it.
        """
        return document

    async def aclose(self) -> None:
        """Cancel any pending background refresh task."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._refresh_task

    async def _background_refresh(self) -> None:
        """Background refresh task.

        Calls ``DocumentCache.get`` rather than ``self.get`` on purpose. A
        subclass may gate a forced read — ``MetadataCache`` floors it, because a
        forced read is externally triggered by a ``kid`` miss on an
        unauthenticated token. This caller is not that: it is the cache
        refreshing itself at 80% of its own TTL, so the anti-abuse gate does not
        apply to it and going through the override would make this a silent
        no-op whenever ``0.8 x refresh_seconds`` falls below the floor — the
        downgraded read takes the fast path on a document that is by definition
        still valid, returns, and logs a refresh that never happened. For any
        interval at or below 75 s that would defeat stale-while-revalidate for
        the rest of the interval and hand the next ``verify()`` a blocking
        synchronous fetch, which is what the retry floor exists to prevent.
        """
        try:
            await DocumentCache.get(self, force_refresh=True)
            logger.debug("Background %s refresh completed", self._document_type)
        except Exception as e:
            logger.warning("Background %s refresh failed: %s", self._document_type, e)
        finally:
            self._refresh_task = None


class JWKSCache(DocumentCache):
    """JWKS cache with key ID lookup methods, bound to a discovered location."""

    def __init__(
        self,
        fetcher: DocumentFetcherCallable,
        refresh_seconds: int = _DEFAULT_REFRESH_SECONDS,
        document_type: str = _DEFAULT_DOCUMENT_TYPE,
        error_factory: DocumentErrorFactory | None = None,
        *,
        source_resolver: DocumentSourceResolver | None = None,
    ) -> None:
        super().__init__(
            fetcher,
            refresh_seconds=refresh_seconds,
            document_type=document_type,
            error_factory=error_factory,
        )
        self._source_resolver = source_resolver

    async def _cache_is_usable(self) -> bool:
        """Whether the cached key set still came from the advertised `jwks_uri`.

        A key set is only as current as the location it was fetched from. When
        an authorization server rotates `jwks_uri`, the document naming the new
        location is re-read on its own interval, but the key set fetched from
        the withdrawn location stays fresh by its own TTL — so without this
        check the rotation is not followed until that TTL lapses, and a rotation
        that reuses a `kid` is not followed at all: the retired key is found
        under the requested `kid`, so nothing looks stale, and every
        verification fails on the signature instead.

        Comparing the advertised location against the one the cached key set
        came from closes that. Resolving the location reads a cached document
        and costs no request of its own until that document's own interval is
        up, and the answer can only change as often as that document is
        re-read — so this cannot be driven faster than the metadata refresh
        interval. A failed refresh is still held off by the retry floor in
        `DocumentCache.get`, which is not conditioned on how the refresh was
        triggered.
        """
        if self._source_resolver is None or self._cache_source is None:
            return True
        try:
            current_source = await self._source_resolver()
        except Exception as e:
            # Resolving the location means reading the document that names it,
            # and that read can fail. A failure is not evidence the location
            # moved, so keep serving the key set we have rather than treating
            # an unreachable discovery document as a rotation.
            logger.debug(
                "Could not resolve the current %s location, serving the cached document: %s",
                self._document_type,
                e,
            )
            return True
        if current_source != self._cache_source:
            logger.debug(
                "%s location no longer matches the advertised one, refetching",
                self._document_type.capitalize(),
                extra={"previous": self._cache_source, "current": current_source},
            )
            return False
        return True

    def _is_passthrough_error(self, error: Exception, /) -> bool:
        """Let a metadata failure keep its own type.

        This cache's fetcher resolves ``jwks_uri`` through the metadata cache,
        so a metadata failure surfaces here. Relabelling it ``JWKSFetchError``
        would point the operator at the wrong document. The base cache has no
        such dependency, which is why the check lives here rather than there.
        """
        return isinstance(error, MetadataFetchError)

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
