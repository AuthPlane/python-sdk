"""RFC 8693 token exchange — bare protocol implementation."""

import logging
import time

from ..dpop import DPoPProvider
from ..net.fetch_settings import FetchSettings
from ..net.http import form_post
from .parsing import parse_token_response
from .types import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TokenExchangeOptions,
    TokenResponse,
)

logger = logging.getLogger(__name__)


async def exchange_token(
    token_endpoint: str,
    options: TokenExchangeOptions,
    auth_header: dict[str, str],
    fetch_settings: FetchSettings,
    *,
    dpop_provider: DPoPProvider | None = None,
) -> TokenResponse:
    """Perform RFC 8693 token exchange."""
    if not options.subject_token:
        raise ValueError("authplane: token exchange: subject_token is required")

    subject_token_type = options.subject_token_type or TOKEN_TYPE_ACCESS_TOKEN

    form_data: list[tuple[str, str]] = [
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", options.subject_token),
        ("subject_token_type", subject_token_type),
    ]

    if options.actor_token:
        actor_token_type = options.actor_token_type or TOKEN_TYPE_ACCESS_TOKEN
        form_data.append(("actor_token", options.actor_token))
        form_data.append(("actor_token_type", actor_token_type))

    if options.scope:
        form_data.append(("scope", options.scope))

    for resource in options.resources:
        form_data.append(("resource", resource))
    for audience in options.audiences:
        form_data.append(("audience", audience))

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
            "token exchange: request failed",
            extra={"endpoint": token_endpoint, "error": str(exc), "duration_ms": duration_ms},
        )
        raise

    duration_ms = int((time.time() - start_time) * 1000)

    if 200 <= response.status_code < 300:
        logger.info(
            "token exchange: success",
            extra={"endpoint": token_endpoint, "duration_ms": duration_ms},
        )
        return parse_token_response(
            response.body,
            allow_issued_token_type=True,
            expect_dpop=dpop_provider is not None,
        )

    from ..errors import map_oauth_error

    raise map_oauth_error(
        "token exchange",
        response.status_code,
        response.body,
        token_endpoint,
        duration_ms,
    )
