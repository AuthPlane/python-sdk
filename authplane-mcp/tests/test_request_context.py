"""Tests for the ASGI plumbing that publishes the active Request via ContextVar.

The MCP SDK's ``TokenVerifier`` protocol has no per-request hook, so
``authplane-mcp`` ships :class:`AuthplaneRequestContextMiddleware` which
sets a ContextVar that :func:`get_current_request` reads from inside
``verify_token``. These tests pin the public behavior of that plumbing
end-to-end (middleware → ContextVar → lookup) so the DPoP path the
verifier relies on doesn't silently regress.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp.server.fastmcp import FastMCP

if TYPE_CHECKING:
    from starlette.types import Message

from authplane_mcp import (
    AuthplaneRequestContextMiddleware,
    get_current_request,
    install_request_context,
)
from authplane_mcp._request_context import (
    _current_request,  # pyright: ignore[reportPrivateUsage]
)


def test_get_current_request_outside_scope_raises() -> None:
    """Outside any ASGI scope, the lookup raises with the FastMCP-matching message.

    The verifier's narrow-on-message fallback catches
    ``"No active HTTP request found."`` from both this lookup and from
    FastMCP's ``get_http_request`` — keep the wording in sync so the
    narrow doesn't bit-rot.
    """
    # Ensure no leftover ContextVar from a previous test
    assert _current_request.get() is None
    with pytest.raises(RuntimeError, match=r"No active HTTP request found\."):
        get_current_request()


@pytest.mark.asyncio
async def test_middleware_publishes_and_clears_request() -> None:
    """During the ASGI call, ``get_current_request`` returns the active Request.

    Asserts the contextvar contract: set on entry, cleared on exit even
    if downstream raises (the ``finally`` in the middleware is what
    guarantees no cross-request leak).
    """
    seen: dict[str, Any] = {}

    async def downstream(scope: Any, receive: Any, send: Any) -> None:
        request = get_current_request()
        seen["method"] = request.method
        seen["path"] = request.url.path
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = AuthplaneRequestContextMiddleware(downstream)
    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/mcp/tools",
        "raw_path": b"/mcp/tools",
        "query_string": b"",
        "headers": [],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": None,
        "root_path": "",
        "http_version": "1.1",
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)

    assert seen == {"method": "POST", "path": "/mcp/tools"}
    # Cleared on exit so subsequent code outside the request context
    # cannot accidentally pick up the stale Request.
    assert _current_request.get() is None


@pytest.mark.asyncio
async def test_middleware_clears_contextvar_on_exception() -> None:
    """Downstream raising must not leave the ContextVar populated.

    The middleware's ``finally`` is what guarantees the next request on
    the same task / loop doesn't see a stale Request — exercise that
    explicitly so a future edit doesn't accidentally drop the ``finally``.
    """

    async def boom(scope: Any, receive: Any, send: Any) -> None:
        _ = get_current_request()  # confirm it's set during the call
        raise RuntimeError("downstream failure")

    app = AuthplaneRequestContextMiddleware(boom)
    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": None,
        "root_path": "",
        "http_version": "1.1",
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_: Message) -> None:
        return None

    with pytest.raises(RuntimeError, match="downstream failure"):
        await app(scope, receive, send)

    assert _current_request.get() is None


@pytest.mark.asyncio
async def test_middleware_skips_non_http_scope() -> None:
    """Lifespan / websocket scopes are passed through without touching the ContextVar.

    Setting the ContextVar for non-HTTP scopes would not break anything
    today, but the middleware is documented as HTTP-only and a future
    reader should be able to trust that.
    """
    called = False

    async def downstream(scope: Any, receive: Any, send: Any) -> None:
        nonlocal called
        called = True
        # ContextVar should be untouched for non-HTTP scopes.
        assert _current_request.get() is None

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(_: Message) -> None:
        return None

    app = AuthplaneRequestContextMiddleware(downstream)
    await app({"type": "lifespan"}, receive, send)
    assert called
    assert _current_request.get() is None


# ---------------------------------------------------------------------------
# install_request_context — monkeypatches FastMCP.streamable_http_app
# ---------------------------------------------------------------------------


def test_install_request_context_wraps_streamable_http_app() -> None:
    """The helper installs the middleware on the Starlette app FastMCP builds.

    ``FastMCP`` wires its middleware list internally with no public hook,
    so the helper patches ``mcp.streamable_http_app`` to add ours after
    the fact. Asserting on ``app.user_middleware`` membership is the
    most direct way to verify the install without spinning up a server.
    """
    mcp: FastMCP[Any] = FastMCP("test")
    install_request_context(mcp)
    app = mcp.streamable_http_app()
    middleware_classes = [m.cls for m in app.user_middleware]
    assert AuthplaneRequestContextMiddleware in middleware_classes
    # Must be the outermost user middleware (added via ``add_middleware`` →
    # inserted at index 0) so it sets the ContextVar before MCP's
    # ``AuthenticationMiddleware`` runs ``verify_token``.
    assert app.user_middleware[0].cls is AuthplaneRequestContextMiddleware


def test_install_request_context_is_idempotent() -> None:
    """A second install on the same FastMCP must be a no-op.

    Without a guard, repeated installs chain wrappers: the inner
    middleware's ``ContextVar.reset`` then fires against a token created
    by the outer wrapper, raising ``RuntimeError: <Token> was created in
    a different Context`` at request time. The guard keeps a single
    middleware entry on the Starlette app regardless of how many times
    the helper is called.
    """
    mcp: FastMCP[Any] = FastMCP("test")
    install_request_context(mcp)
    install_request_context(mcp)
    install_request_context(mcp)
    app = mcp.streamable_http_app()
    middleware_classes = [m.cls for m in app.user_middleware]
    assert middleware_classes.count(AuthplaneRequestContextMiddleware) == 1
