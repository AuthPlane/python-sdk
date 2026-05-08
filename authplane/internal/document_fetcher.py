"""Generic JSON document fetching with optional SSRF protection."""

import logging

import httpx

from ..net.fetch_settings import FetchSettings
from ..net.ssrf import ssrf_safe_get
from .cache_headers import parse_expires_at
from .fetch_result import FetchResult

logger = logging.getLogger(__name__)


class DocumentFetcher:
    """Fetches JSON documents from URLs with optional SSRF protection.

    Creates a new HTTP client per fetch when SSRF protection is disabled.
    Generic fetcher reusable for JWKS, AS metadata, and other JSON documents.
    """

    def __init__(
        self,
        url: str,
        *,
        document_type: str = "document",
        settings: FetchSettings | None = None,
        max_size: int = 65536,  # Now configurable, default 64KB
    ):
        """Initialize document fetcher.

        Args:
            url: URL to fetch JSON document from
            document_type: Type of document (e.g., "jwks", "metadata") for logging/metrics
            settings: Fetch settings (SSRF protection, HTTP, localhost, etc.). Defaults to secure production settings.
            max_size: Maximum document size in bytes (default 64KB)
        """
        self._url = url
        self._document_type = document_type
        self._settings = settings or FetchSettings()
        self._max_size = max_size

    @property
    def ssrf_protection(self) -> bool:
        """Whether SSRF protection is enabled for this fetcher."""
        return self._settings.ssrf_protection

    @property
    def allow_http(self) -> bool:
        """Whether HTTP (in addition to HTTPS) is allowed."""
        return self._settings.allow_http

    @property
    def allow_localhost(self) -> bool:
        """Whether localhost addresses are allowed."""
        return self._settings.allow_localhost

    @property
    def allow_private_networks(self) -> bool:
        """Whether private network addresses are allowed."""
        return self._settings.allow_private_networks

    async def fetch(self) -> FetchResult:
        """Fetch JSON document from the configured URL.

        Returns:
            FetchResult with parsed JSON document and server cache expiry

        Raises:
            SSRFError: If SSRF validation fails (when ssrf_protection=True)
            httpx.HTTPError: If HTTP request fails
        """
        if self._settings.ssrf_protection:
            # Use SSRF-protected fetch (returns HttpResponse for any status)
            try:
                http_response = await ssrf_safe_get(
                    self._url,
                    allow_http=self._settings.allow_http,
                    allow_localhost=self._settings.allow_localhost,
                    allow_private_networks=self._settings.allow_private_networks,
                    max_size=self._max_size,
                    timeout=self._settings.timeout,
                )
            except Exception as e:
                logger.error(
                    "SSRF protection blocked %s fetch from %s: %s",
                    self._document_type,
                    self._url,
                    e,
                )
                raise
            if http_response.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"HTTP {http_response.status_code} from {self._url}",
                    request=httpx.Request("GET", self._url),
                    response=httpx.Response(
                        status_code=http_response.status_code,
                        headers=http_response.headers,
                    ),
                )
            logger.debug("Fetched %s from %s (SSRF-protected)", self._document_type, self._url)
            return FetchResult(
                document=http_response.body,
                expires_at=parse_expires_at(http_response.headers),
            )
        else:
            # Direct fetch without SSRF protection — new client per call
            async with httpx.AsyncClient(timeout=self._settings.timeout) as client:
                response = await client.get(self._url)
                response.raise_for_status()
                logger.debug("Fetched %s from %s", self._document_type, self._url)
                return FetchResult(
                    document=response.json(),
                    expires_at=parse_expires_at(dict(response.headers)),
                )
