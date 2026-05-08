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
    """

    document: dict[str, Any]
    expires_at: float | None = None
