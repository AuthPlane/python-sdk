"""Tests for the ASGI plumbing that publishes the active Request via ContextVar.

The MCP SDK's ``TokenVerifier`` protocol has no per-request hook, so
``authplane-mcp`` ships :class:`AuthplaneRequestContextMiddleware` which
sets a ContextVar that :func:`get_current_request` reads from inside
``verify_token``. These tests pin the public behavior of that plumbing
end-to-end (middleware → ContextVar → lookup) so the DPoP path the
verifier relies on doesn't silently regress.
"""

from __future__ import annotations

import warnings
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

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
from authplane_mcp.verifier import AuthplaneTokenVerifier


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


# ---------------------------------------------------------------------------
# install_request_context — verbatim-PRM detection (three distinct states)
# ---------------------------------------------------------------------------


def _stub_verifier(**kwargs: Any) -> AuthplaneTokenVerifier:
    resource = SimpleNamespace(resource="https://api.example.com/mcp")
    return AuthplaneTokenVerifier(cast("Any", resource), **kwargs)


def test_no_warning_when_server_has_no_auth() -> None:
    """A FastMCP with no auth configured has nothing to rewrite.

    ``_token_verifier`` exists on the instance and is ``None``. The old code
    branched on ``is None`` alone and warned here, telling the operator the MCP
    SDK had renamed a private attribute — which is not what happened.
    """
    mcp: FastMCP[Any] = FastMCP("test")
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        install_request_context(mcp)


def test_warns_when_verifier_carries_no_verbatim_identifiers() -> None:
    """The regression the warning exists to catch, on the path it used to miss.

    ``AuthplaneTokenVerifier(verifier)`` is a supported public constructor and
    leaves both verbatim identifiers unset. The verifier *is* present, so the
    old ``is None`` check stayed quiet while the served PRM kept advertising the
    slash-normalized identifiers this SDK's own comparison rejects.
    """
    mcp: FastMCP[Any] = FastMCP("test")
    mcp._token_verifier = _stub_verifier()  # type: ignore[attr-defined]
    with pytest.warns(RuntimeWarning, match="no verbatim issuer/resource"):
        install_request_context(mcp)


def test_no_warning_when_verbatim_identifiers_are_present() -> None:
    mcp: FastMCP[Any] = FastMCP("test")
    mcp._token_verifier = _stub_verifier(  # type: ignore[attr-defined]
        verbatim_issuer="https://auth.example.com",
        verbatim_resource="https://api.example.com/mcp",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        install_request_context(mcp)


def test_warns_about_a_renamed_sdk_attribute_only_when_absent() -> None:
    """The 'SDK renamed the attribute' wording is reserved for that case."""
    mcp: FastMCP[Any] = FastMCP("test")
    # ``_token_verifier`` is set on the instance by FastMCP.__init__; deleting it
    # is the closest stand-in for an upstream rename, which is the only thing
    # that should produce this wording.
    del mcp._token_verifier  # type: ignore[attr-defined]
    assert not hasattr(mcp, "_token_verifier")
    with pytest.warns(RuntimeWarning, match="renamed the private attribute"):
        install_request_context(mcp)


def test_verbatim_identifiers_accessor() -> None:
    assert _stub_verifier().verbatim_identifiers() is None
    assert _stub_verifier(verbatim_issuer="https://a").verbatim_identifiers() is None
    assert _stub_verifier(
        verbatim_issuer="https://a", verbatim_resource="https://b"
    ).verbatim_identifiers() == ("https://a", "https://b")


def test_install_tolerates_a_server_without_sse_app() -> None:
    """A future 1.x that drops ``sse_app`` must not break streamable-HTTP servers.

    Everything else in ``install_request_context`` is defensive (``getattr`` for
    ``_token_verifier``, ``*args``/``**kwargs`` forwarding); the ``sse_app``
    lookup was the one bare attribute access, and SSE is not on the
    streamable-HTTP path at all.
    """
    mcp: FastMCP[Any] = FastMCP("test")
    # Save and restore rather than reload: `from ... import FastMCP` bound this
    # module's name to the original class object, so importlib.reload would build
    # a *new* class and leave this one permanently mutated for later tests.
    original = FastMCP.sse_app
    del FastMCP.sse_app  # type: ignore[attr-defined]
    try:
        install_request_context(mcp)
        app = mcp.streamable_http_app()
        assert app.user_middleware[0].cls is AuthplaneRequestContextMiddleware
    finally:
        FastMCP.sse_app = original  # type: ignore[attr-defined]


def test_install_wraps_sse_app_when_present() -> None:
    """The present branch had no coverage at all.

    Only the absent-`sse_app` case was pinned, so `mcp.sse_app = sse_app` could
    have been deleted outright and every suite stayed green — on a line that had
    just been moved inside a conditional.

    Asserted on the instance dict, not by comparing the attribute to a value
    captured earlier: attribute access on a method builds a fresh bound object
    each time, so an identity check passes whether or not the assignment
    happened. The instance dict gains the key only when it does.
    """
    mcp: FastMCP[Any] = FastMCP("test")
    assert "sse_app" not in vars(mcp)

    install_request_context(mcp)

    assert "sse_app" in vars(mcp)
    assert vars(mcp)["sse_app"].__name__ == "sse_app"
