"""OAuth 2.0 client_credentials grant — bare protocol implementation."""

import logging
import time

from ..dpop import DPoPProvider
from ..net.fetch_settings import FetchSettings
from ..net.http import form_post
from .parsing import parse_token_response
from .types import TokenResponse

logger = logging.getLogger(__name__)


async def client_credentials_grant(
    token_endpoint: str,
    auth_header: dict[str, str],
    fetch_settings: FetchSettings,
    scopes: list[str] | None = None,
    resources: list[str] | None = None,
    *,
    dpop_provider: DPoPProvider | None = None,
) -> TokenResponse:
    """Obtain a token using client_credentials grant."""
    form_data: list[tuple[str, str]] = [("grant_type", "client_credentials")]

    if scopes:
        form_data.append(("scope", " ".join(scopes)))
    if resources:
        for r in resources:
            form_data.append(("resource", r))

    start_time = time.time()

    try:
        response = await form_post(
            token_endpoint,
            form_data,
            fetch_settings,
            extra_headers=auth_header,
            dpop_provider=dpop_provider,
        )
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(
            "client_credentials: request failed",
            extra={"endpoint": token_endpoint, "error": str(exc), "duration_ms": duration_ms},
        )
        raise

    duration_ms = int((time.time() - start_time) * 1000)

    if 200 <= response.status_code < 300:
        logger.info(
            "client_credentials: success",
            extra={"endpoint": token_endpoint, "duration_ms": duration_ms},
        )
        return parse_token_response(
            response.body,
            allow_issued_token_type=False,
            expect_dpop=dpop_provider is not None,
        )

    from ..errors import map_oauth_error

    raise map_oauth_error(
        "client_credentials",
        response.status_code,
        response.body,
        token_endpoint,
        duration_ms,
    )
