"""Authorization Server Metadata cache (RFC 8414)."""

import logging
from typing import Any
from urllib.parse import urlsplit

from ..errors import MetadataFetchError, MissingMetadataEndpointError
from .document_cache import DocumentCache, DocumentChangeCallback, DocumentFetcherCallable

logger = logging.getLogger(__name__)


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
        on_change: DocumentChangeCallback | None = None,
    ) -> None:
        super().__init__(
            fetcher,
            refresh_seconds=refresh_seconds,
            document_type=document_type,
            on_change=on_change,
            error_factory=lambda msg: MetadataFetchError(msg),
        )
        # Identity: the expected issuer is stored verbatim. RFC 8414 §3.3
        # requires the returned `issuer` to be identical to the configured one,
        # so a trailing-slash difference is a genuine mismatch and must not be
        # normalized away on either side of the comparison.
        self._expected_issuer = expected_issuer
        self._allow_http = allow_http

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

    def _validate_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
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

    async def get(self, force_refresh: bool = False) -> dict[str, Any]:
        metadata = await super().get(force_refresh=force_refresh)
        return self._validate_metadata(metadata)

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
