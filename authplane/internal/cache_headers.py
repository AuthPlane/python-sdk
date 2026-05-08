"""HTTP cache header parsing utilities (RFC 7234)."""

import logging
import time
from collections.abc import Mapping
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)


def parse_expires_at(headers: Mapping[str, str]) -> float | None:
    """Extract an absolute expiry timestamp from HTTP response cache headers.

    Precedence (per RFC 7234 Section 4.2.2):
    1. Cache-Control: no-store / no-cache → 0.0  (already expired)
    2. Cache-Control: max-age=N → time.time() + N
    3. Expires header → parsed to Unix timestamp
    4. None if no usable cache header is present

    Args:
        headers: HTTP response headers (case-insensitive mapping, e.g. httpx.Headers).

    Returns:
        Absolute Unix timestamp when the cached document expires,
        or None if no cache headers were found.
    """
    cache_control = headers.get("cache-control", "")
    if cache_control:
        lower_cc = cache_control.lower()

        if "no-store" in lower_cc or "no-cache" in lower_cc:
            return 0.0

        for directive in lower_cc.split(","):
            directive = directive.strip()
            if directive.startswith("max-age="):
                try:
                    max_age = float(directive.split("=", 1)[1].strip())
                    if max_age >= 0:
                        return time.time() + max_age
                except (ValueError, IndexError):
                    logger.debug(
                        "Failed to parse max-age from Cache-Control: %s",
                        cache_control,
                    )

    expires = headers.get("expires", "")
    if expires:
        try:
            expires_dt = parsedate_to_datetime(expires)
            return expires_dt.timestamp()
        except (ValueError, TypeError):
            logger.debug("Failed to parse Expires header: %s", expires)

    return None
