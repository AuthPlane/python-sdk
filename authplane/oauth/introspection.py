"""RFC 7662 token introspection — bare protocol implementation."""

import logging
import time
from typing import Any, cast

from ..dpop import DPoPProvider
from ..net.fetch_settings import FetchSettings
from ..net.http import form_post
from .types import IntrospectionResponse

logger = logging.getLogger(__name__)


async def introspect_token(
    introspection_endpoint: str,
    token: str,
    auth_header: dict[str, str],
    fetch_settings: FetchSettings,
    *,
    dpop_provider: DPoPProvider | None = None,
) -> IntrospectionResponse:
    """Call the introspection endpoint (RFC 7662)."""
    form_data = {"token": token, "token_type_hint": "access_token"}

    start_time = time.time()

    try:
        response = await form_post(
            introspection_endpoint,
            form_data,
            fetch_settings,
            extra_headers=auth_header,
            dpop_provider=dpop_provider,
        )
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(
            "introspection: request failed",
            extra={
                "endpoint": introspection_endpoint,
                "error": str(exc),
                "duration_ms": duration_ms,
            },
        )
        raise

    duration_ms = int((time.time() - start_time) * 1000)

    if 200 <= response.status_code < 300:
        return _parse_introspection_response(response.body)

    from ..errors import map_oauth_error

    raise map_oauth_error(
        "introspection",
        response.status_code,
        response.body,
        introspection_endpoint,
        duration_ms,
    )


def _parse_introspection_response(data: dict[str, Any]) -> IntrospectionResponse:
    raw_chain: object = data.get("agent_chain", [])
    agent_chain: tuple[str, ...] = (
        tuple(str(x) for x in cast("list[object]", raw_chain))
        if isinstance(raw_chain, list)
        else ()
    )
    return IntrospectionResponse(
        active=bool(data.get("active", False)),
        scope=str(data.get("scope", "")),
        client_id=str(data.get("client_id", "")),
        sub=str(data.get("sub", "")),
        token_type=str(data.get("token_type", "")),
        iss=str(data.get("iss", "")),
        aud=data.get("aud"),
        exp=data.get("exp"),
        iat=data.get("iat"),
        jti=str(data.get("jti", "")),
        agent_id=str(data.get("agent_id", "")),
        agent_chain=agent_chain,
    )
