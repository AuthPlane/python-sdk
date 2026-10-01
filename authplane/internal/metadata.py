"""Authorization Server Metadata cache (RFC 8414)."""

import logging
import time
from typing import Any
from urllib.parse import urlsplit

from ..errors import MetadataFetchError, MissingMetadataEndpointError
from .document_cache import DocumentCache, DocumentFetcherCallable

logger = logging.getLogger(__name__)

#: Ceiling on the interval between forced metadata reads. The floor itself is
#: ``min(refresh_seconds, this)``, so a deployment asking for fresher metadata
#: than a minute still gets it.
_FORCED_READ_FLOOR_CEILING_SECONDS = 60.0


class MetadataCache(DocumentCache):
    """AS Metadata cache with RFC 8414 validation and field extraction."""

    def __init__(
        self,
        fetcher: DocumentFetcherCallable,
        *,
        expected_issuer: str = "",
        allow_http: bool = False,
        refresh_seconds: int = 3600,
        document_type: str = "metadata",
    ) -> None:
        super().__init__(
            fetcher,
            refresh_seconds=refresh_seconds,
            document_type=document_type,
            error_factory=lambda msg: MetadataFetchError(msg),
        )
        # Identity: the expected issuer is stored verbatim. RFC 8414 §3.3
        # requires the returned `issuer` to be identical to the configured one,
        # so a trailing-slash difference is a genuine mismatch and must not be
        # normalized away on either side of the comparison.
        self._expected_issuer = expected_issuer
        self._allow_http = allow_http
        # A forced read bypasses the refresh interval by design, so on its own
        # it is no rate limit. The caller that reaches it is a JWKS `kid` miss,
        # and nothing upstream of that has authenticated anything — `verify()`
        # has only decoded the header — so a well-formed header carrying an
        # arbitrary `kid` would otherwise cost the AS one discovery fetch per
        # request, on top of the pre-existing JWKS fetch, forever.
        #
        # The floor caps that while still following a real rotation promptly:
        # the first miss after it elapses re-reads immediately. Refusing only
        # downgrades the read to an ordinary one, which still serves a valid
        # cached document or refetches an expired one — and, because the
        # downgraded read takes the fast path, it also stops N concurrent
        # bogus-`kid` requests serializing N forced fetches behind the fetch
        # lock that legitimate verifications queue on.
        #
        # A floor of zero would opt out, but `AuthplaneClient` rejects
        # `metadata_refresh_seconds <= 0` with `ValueError`, so that state is
        # unreachable through the public API here — the branch is defensive.
        # Note the rotation conformance case no longer reaches this floor at
        # all: it rotates under a stable `kid`, so no miss is produced and the
        # re-read it drives is the ordinary interval-driven one. The floor is
        # covered by the unit suite instead.
        self._forced_read_floor = min(float(refresh_seconds), _FORCED_READ_FLOOR_CEILING_SECONDS)
        self._last_forced_read: float | None = None

    def _is_passthrough_error(self, error: Exception, /) -> bool:
        """Let a missing-endpoint rejection keep its own type.

        `_error_factory` would relabel it `MetadataFetchError` on the cold-boot
        path, which is the base class — so an operator's
        `except MissingMetadataEndpointError` would stop catching the condition
        it was written for the moment the check moved from read time to fetch
        time. The stale-fallback path is unaffected either way, since the type
        subclasses the one the cache already treats as a failed refresh.
        """
        return isinstance(error, MissingMetadataEndpointError)

    def _admit_forced_read(self) -> bool:
        """Whether a forced read is allowed now, recording it if so."""
        if self._forced_read_floor <= 0:
            return True
        now = time.time()
        if (
            self._last_forced_read is not None
            and now - self._last_forced_read < self._forced_read_floor
        ):
            return False
        self._last_forced_read = now
        return True

    async def get(self, force_refresh: bool = False) -> dict[str, Any]:
        """Return the cached document, applying the forced-read floor."""
        return await super().get(force_refresh=force_refresh and self._admit_forced_read())

    def _validate_endpoint_url(self, field: str, value: str) -> None:
        """Validate that a metadata endpoint URL is absolute and uses HTTPS.

        In production mode (allow_http=False), endpoint URLs must be absolute
        HTTPS URLs. In dev mode (allow_http=True), HTTP is also permitted.
        """
        # urlsplit, guarded. Two urllib traps escape as a bare ValueError on a
        # malformed authority — a netloc with `[` and no `]` ("Invalid IPv6
        # URL"), and a non-numeric port, which is parsed lazily and raises at
        # attribute access — and this value is AS metadata, i.e. remote content.
        # The MCP adapters catch only AuthplaneError, so an unwrapped ValueError
        # here turns a metadata rejection into an unhandled 500. Same guard as
        # `_split_dpop_url` and `internal/urls.py`; this call site was the one
        # left out of that audit.
        #
        # urlsplit rather than urlparse for the module's one parse idiom: only
        # scheme and netloc are read, so `;params` cannot reach anything here,
        # but the safety of a urlparse should not have to be re-argued per site.
        try:
            parsed = urlsplit(value)
            # Read, not discarded: SplitResult.port is parsed lazily, so an
            # out-of-range or non-numeric port raises here rather than at split.
            _ = parsed.port
        except ValueError as exc:
            raise MetadataFetchError(
                f"AS metadata field {field!r} is not a valid URL: {value!r}"
            ) from exc
        if not parsed.scheme or not parsed.netloc:
            raise MetadataFetchError(
                f"AS metadata field {field!r} is not an absolute URL: {value!r}"
            )
        if not self._allow_http and parsed.scheme != "https":
            raise MetadataFetchError(
                f"AS metadata field {field!r} must use HTTPS, got {parsed.scheme!r}: {value!r}"
            )

    def _validate_fetched(self, metadata: dict[str, Any], /) -> dict[str, Any]:
        """Apply the RFC 8414 checks before the document reaches the cache.

        Running here rather than on the way out is what keeps a rejected
        document from deciding anything: ``jwks_uri`` is read from the cached
        document on every key-set fetch, so a document that fails the §3.3
        issuer identity check would otherwise steer key retrieval to whatever
        it advertised — and a token signed by that key set would then verify
        against the configured issuer. A rejection leaves the last accepted
        document in place, so verification keeps working off the key set it was
        already using.
        """
        issuer = str(metadata.get("issuer", ""))
        if not issuer:
            raise MetadataFetchError("AS metadata missing required 'issuer' field")
        if self._expected_issuer and issuer != self._expected_issuer:
            msg = f"AS metadata issuer mismatch: expected {self._expected_issuer!r}, got {issuer!r}"
            # The comparison above stays byte-for-byte; only the hint is
            # conditional. Append the trailing-slash note only when the two
            # values are otherwise identical — a genuine wrong-host mismatch
            # would be misleadingly blamed on a slash otherwise.
            if issuer.rstrip("/") == self._expected_issuer.rstrip("/"):
                msg += " (identifiers are compared byte-for-byte; a trailing slash is significant)"
            raise MetadataFetchError(msg)
        # Required, not merely validated-when-present. `create()` already fails
        # without it, so this only changes what a *refresh* may do: before, a
        # document that had dropped `jwks_uri` validated, was committed with a
        # fresh timestamp, and displaced the good one — after which every JWKS
        # fetch raised for the rest of the interval, the key set went stale, and
        # the first genuinely new `kid` failed to verify. RFC 8414 §2 lists the
        # field as OPTIONAL, but an AS issuing JWT access tokens has no way for
        # this SDK to verify one without it.
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            # MissingMetadataEndpointError, not the base class: this is the error
            # `get_required_endpoint` already raised for the same condition, it is
            # a package-root export documented as "required discovered endpoint
            # missing", and moving the check to fetch time must not quietly change
            # what an operator's `except` clause catches. It subclasses
            # MetadataFetchError, so the cache's stale-fallback path treats it as
            # a failed refresh either way.
            raise MissingMetadataEndpointError(
                "AS metadata missing required 'jwks_uri' field; keeping the previously cached document"
            )
        for field in (
            "jwks_uri",
            "token_endpoint",
            "introspection_endpoint",
            "revocation_endpoint",
        ):
            value = metadata.get(field)
            if value:
                self._validate_endpoint_url(field, str(value))
        return metadata

    async def get_required_endpoint(self, field: str, force_refresh: bool = False) -> str:
        """Return a required AS metadata field, raising MissingMetadataEndpointError if absent."""
        metadata = await self.get(force_refresh=force_refresh)
        value = metadata.get(field)
        if not value:
            raise MissingMetadataEndpointError(
                f"AS metadata missing required {field!r} field. "
                f"Received metadata keys: {list(metadata.keys())}"
            )
        return str(value)

    async def get_jwks_uri(self, force_refresh: bool = False) -> str:
        """Return the ``jwks_uri`` from AS metadata."""
        jwks_uri = await self.get_required_endpoint("jwks_uri", force_refresh=force_refresh)
        logger.info("Extracted jwks_uri from AS metadata", extra={"jwks_uri": jwks_uri})
        return jwks_uri

    async def get_token_endpoint(self, force_refresh: bool = False) -> str:
        """Return the ``token_endpoint`` from AS metadata."""
        token_endpoint = await self.get_required_endpoint(
            "token_endpoint", force_refresh=force_refresh
        )
        logger.info(
            "Extracted token_endpoint from AS metadata", extra={"token_endpoint": token_endpoint}
        )
        return token_endpoint

    async def get_introspection_endpoint(self, force_refresh: bool = False) -> str:
        """Return the ``introspection_endpoint`` from AS metadata."""
        return await self.get_required_endpoint(
            "introspection_endpoint", force_refresh=force_refresh
        )

    async def get_revocation_endpoint(self, force_refresh: bool = False) -> str:
        """Return the ``revocation_endpoint`` from AS metadata."""
        return await self.get_required_endpoint("revocation_endpoint", force_refresh=force_refresh)
