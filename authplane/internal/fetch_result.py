"""Fetch result container for the document fetching pipeline."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FetchResult:
    """Result of a document fetch, carrying both the document and cache metadata.

    Attributes:
        document: The parsed JSON document.
        expires_at: Absolute Unix timestamp when the server considers the response
            stale, derived from HTTP cache headers (Cache-Control max-age or Expires).
            None if the server sent no cache headers.
        source: The URL this document was actually retrieved from. Recorded
            because a document whose location is itself discovered — the key set,
            whose ``jwks_uri`` comes from AS metadata — can outlive the location
            it was fetched from. Comparing the recorded source against the
            currently advertised one is what lets a cache notice that its
            contents came from a URL the authorization server has since
            replaced. None when the fetcher has no single URL to report.
    """

    document: dict[str, Any]
    expires_at: float | None = None
    source: str | None = None
