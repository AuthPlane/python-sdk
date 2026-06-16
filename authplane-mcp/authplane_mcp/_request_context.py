"""Per-request ASGI context for the authplane-mcp adapter.

The MCP SDK's ``TokenVerifier`` protocol exposes only
``verify_token(token: str)`` with no per-request hook — unlike FastMCP,
which ships ``fastmcp.server.dependencies.get_http_request()``. To
forward a :class:`~authplane.DPoPRequestContext` to
:meth:`AuthplaneResource.verify`, the verifier needs to reach the active
:class:`~starlette.requests.Request` from inside ``verify_token``.

This module provides:

* :data:`_current_request` — a :class:`contextvars.ContextVar` holding
  the active Starlette ``Request`` for the duration of the ASGI scope.
* :func:`get_current_request` — the default lookup the verifier uses to
  read that ContextVar; raises ``RuntimeError("No active HTTP request
  found.")`` outside an HTTP request (message matches FastMCP's
  ``get_http_request`` so the verifier's narrow-on-message fallback
  catches both).
* :class:`AuthplaneRequestContextMiddleware` — an ASGI middleware that
  populates the ContextVar at the start of each HTTP request and clears
  it on exit. Must run *before* MCP's ``AuthenticationMiddleware`` so
  ``BearerAuthBackend.authenticate(conn)`` finds the request set when it
  calls ``verify_token``.

Install via :func:`authplane_mcp.install_request_context` (wraps the
Starlette app returned by ``mcp.streamable_http_app()``); see the
``authplane_mcp_auth`` docstring for the integration pattern.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING

from starlette.requests import Request

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

_current_request: ContextVar[Request | None] = ContextVar(
    "authplane_mcp_current_request", default=None
)

_NO_ACTIVE_REQUEST_MESSAGE = "No active HTTP request found."


def get_current_request() -> Request:
    """Return the active Starlette ``Request`` for the current ASGI scope.

    Raises:
        RuntimeError: If called outside an HTTP request scope (no active
            request set by :class:`AuthplaneRequestContextMiddleware`).
            The message is intentionally identical to the one FastMCP's
            ``get_http_request`` raises so the verifier's narrow-on-
            message fallback catches both sources without branching.
    """
    request = _current_request.get()
    if request is None:
        raise RuntimeError(_NO_ACTIVE_REQUEST_MESSAGE)
    return request


class AuthplaneRequestContextMiddleware:
    """ASGI middleware exposing the active Starlette ``Request`` via ContextVar.

    Must run **before** MCP's ``AuthenticationMiddleware`` so the
    ContextVar is populated when ``BearerAuthBackend.authenticate(conn)``
    calls into :meth:`AuthplaneTokenVerifier.verify_token`. The
    middleware is a no-op for non-HTTP scopes (lifespan, websocket).

    Use :func:`authplane_mcp.install_request_context` to install on a
    ``FastMCP`` instance; that helper wraps the Starlette app returned by
    ``mcp.streamable_http_app()`` so ``mcp.run(transport="streamable-
    http")`` picks the middleware up transparently.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Building the Request once here and storing on the ContextVar lets
        # the verifier reuse ``request.state`` (same underlying scope state
        # object) for the per-request verify cache.
        token = _current_request.set(Request(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            _current_request.reset(token)
