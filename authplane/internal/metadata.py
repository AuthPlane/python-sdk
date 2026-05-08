"""Authorization Server Metadata cache (RFC 8414)."""

import logging
from typing import Any
from urllib.parse import urlparse

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
        self._expected_issuer = expected_issuer.rstrip("/")
        self._allow_http = allow_http

    def _validate_endpoint_url(self, field: str, value: str) -> None:
        """Validate that a metadata endpoint URL is absolute and uses HTTPS.

        In production mode (allow_http=False), endpoint URLs must be absolute
        HTTPS URLs. In dev mode (allow_http=True), HTTP is also permitted.
        """
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            raise MetadataFetchError(
                f"AS metadata field {field!r} is not an absolute URL: {value!r}"
            )
        if not self._allow_http and parsed.scheme != "https":
            raise MetadataFetchError(
                f"AS metadata field {field!r} must use HTTPS, got {parsed.scheme!r}: {value!r}"
            )

    def _validate_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        issuer = str(metadata.get("issuer", "")).rstrip("/")
        if not issuer:
            raise MetadataFetchError("AS metadata missing required 'issuer' field")
        if self._expected_issuer and issuer != self._expected_issuer:
            raise MetadataFetchError(
                f"AS metadata issuer mismatch: expected {self._expected_issuer!r}, got {issuer!r}"
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
