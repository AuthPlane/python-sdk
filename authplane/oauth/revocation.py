"""RFC 7009 token revocation — bare protocol implementation."""

import logging
import time

from ..dpop import DPoPProvider
from ..net.fetch_settings import FetchSettings
from ..net.http import form_post

logger = logging.getLogger(__name__)


async def revoke_token(
    revocation_endpoint: str,
    token: str,
    auth_header: dict[str, str],
    fetch_settings: FetchSettings,
    token_type_hint: str = "access_token",
    *,
    dpop_provider: DPoPProvider | None = None,
) -> None:
    """Revoke a token at the AS (RFC 7009)."""
    form_data = {"token": token, "token_type_hint": token_type_hint}

    start_time = time.time()

    try:
        response = await form_post(
            revocation_endpoint,
            form_data,
            fetch_settings,
            extra_headers=auth_header,
            dpop_provider=dpop_provider,
        )
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(
            "revocation: request failed",
            extra={"endpoint": revocation_endpoint, "error": str(exc), "duration_ms": duration_ms},
        )
        raise

    duration_ms = int((time.time() - start_time) * 1000)

    # RFC 7009: 200 means success (even if token was already invalid)
    if 200 <= response.status_code < 300:
        logger.info(
            "revocation: success",
            extra={"endpoint": revocation_endpoint, "duration_ms": duration_ms},
        )
        return

    from ..errors import map_oauth_error

    raise map_oauth_error(
        "revocation",
        response.status_code,
        response.body,
        revocation_endpoint,
        duration_ms,
    )
