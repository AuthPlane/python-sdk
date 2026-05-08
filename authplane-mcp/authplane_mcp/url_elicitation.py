"""URL elicitation primitive for the MCP adapter.

The factory function :func:`authplane_mcp.authplane_mcp_auth` wraps the
``AuthplaneClient`` it returns so that ``client.exchange()`` consent errors
auto-translate into MCP ``-32042`` (URL elicitation required) before user
tool code sees them.  This module exposes the underlying conversion as a
small primitive for unusual flows where users build a consent error outside
the wrapped client and want to raise the MCP-shaped error themselves.
"""

from __future__ import annotations

from uuid import uuid4

from authplane.errors import ConsentRequiredError
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp.types import ElicitRequestURLParams


def to_url_elicitation_required_error(
    error: BaseException,
) -> UrlElicitationRequiredError | None:
    """Map a :class:`ConsentRequiredError` with a ``consent_url`` to MCP -32042.

    Returns ``None`` for any other input — non-consent errors and consent
    errors without a ``consent_url`` are not translatable.  Callers then
    re-raise the original exception unchanged.
    """
    if not isinstance(error, ConsentRequiredError) or not error.consent_url:
        return None

    return UrlElicitationRequiredError(
        elicitations=[
            ElicitRequestURLParams(
                mode="url",
                url=error.consent_url,
                elicitationId=str(uuid4()),
                message=error.describe(),
            )
        ],
        message=str(error),
    )
