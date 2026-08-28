"""Integration tests for authplane-mcp with a real MCP SDK ``FastMCP`` app.

These tests verify that the Protected Resource Metadata (PRM) endpoint the MCP
SDK auto-registers advertises the operator-configured issuer / resource
identifiers byte-for-byte, matching the core SDK's strict comparison
(RFC 8414 §3.3, RFC 9728 §3.3). Upstream serializes those fields through
``pydantic.AnyHttpUrl``, which appends a trailing slash to an empty-path
authority; :func:`install_request_context` rewrites the served document back to
the verbatim form.
"""

from unittest.mock import AsyncMock, PropertyMock

import pytest
from authplane import AuthplaneResource
from httpx import ASGITransport, AsyncClient
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from authplane_mcp import AuthplaneTokenVerifier, install_request_context


def _build_app(*, issuer: str, resource: str) -> FastMCP:
    mock = AsyncMock(spec=AuthplaneResource)
    type(mock).scopes = PropertyMock(return_value=["tools/query"])
    type(mock).resource = PropertyMock(return_value=resource)

    token_verifier = AuthplaneTokenVerifier(
        mock,
        verbatim_issuer=issuer,
        verbatim_resource=resource,
    )
    auth_settings = AuthSettings(
        issuer_url=AnyHttpUrl(issuer),
        resource_server_url=AnyHttpUrl(resource),
    )
    mcp = FastMCP(
        "Test Server",
        json_response=True,
        token_verifier=token_verifier,
        auth=auth_settings,
    )
    install_request_context(mcp)
    return mcp


@pytest.mark.asyncio
async def test_prm_advertises_issuer_verbatim() -> None:
    """The served PRM advertises the issuer without an added trailing slash."""
    mcp = _build_app(
        issuer="https://auth.example.com",
        resource="https://api.example.com/mcp",
    )
    asgi_app = mcp.streamable_http_app()

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    prm = response.json()
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["resource"] == "https://api.example.com/mcp"


@pytest.mark.asyncio
async def test_sse_app_serves_the_verbatim_prm_too() -> None:
    """The SSE branch of ``install_request_context``, pinned by behaviour.

    ``test_request_context.py::test_install_wraps_sse_app_when_present`` pins
    that the wrapper is *installed*, and is explicit that this is all it pins:
    its ``FastMCP("test")`` has ``_token_verifier = None``, so the rewrite
    inside the wrapper is a no-op there and deleting the ``rewrite_prm(app)``
    call from the body keeps it green. This covers what the wrapper *does*.

    Built through ``sse_app()`` rather than ``streamable_http_app()``, with the
    empty-path authority — the shape where ``pydantic.AnyHttpUrl`` appends a
    trailing slash — so the assertion fails unless the rewrite actually ran on
    this path.
    """
    mcp = _build_app(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
    )
    # Guarded the way `auth.py:218` guards it. That call site reaches `sse_app`
    # through `getattr(..., None)` precisely because a future `mcp` 1.x may drop
    # it — SSE is not on the streamable-HTTP path. Calling it bare here means
    # that removal lands as an `AttributeError` on an unrelated PR instead of a
    # sentence saying what needs re-pinning.
    #
    # `skip` here where `_upstream_resource_url` uses `fail` for a structurally
    # similar upstream-symbol disappearance, because the two resolve differently:
    # production *depends* on `_get_resource_url`, so its removal has to be red,
    # while production *guards* `sse_app` and degrades — a run without it is the
    # documented outcome, not a broken claim.
    sse_app = getattr(mcp, "sse_app", None)
    if sse_app is None:
        pytest.skip(
            "mcp no longer exposes sse_app; the SSE wrapping in auth.py and this "
            "case both need re-pinning against the current transport surface"
        )
    asgi_app = sse_app()

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    prm = response.json()
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["resource"] == "https://api.example.com"


@pytest.mark.asyncio
async def test_prm_advertises_trailing_slash_resource_verbatim() -> None:
    """A resource whose path ends in a slash is advertised verbatim.

    This is the shape the route-selection fix was written for, and until now it
    was covered only by a unit test that *hand-wrote* the registered route path
    (``/.well-known/oauth-protected-resource/mcp/``) — encoding the very
    assumption about upstream's registration that produced the bug. If upstream
    changed that rule the unit test would stay green while the served document
    went back to advertising the normalized identifier.

    Going through ``streamable_http_app()`` pins it against the real
    registration instead: whatever path upstream registers, the rewrite has to
    find it and the document has to come back with the configured string.

    ``follow_redirects=True`` is what makes the assertion match that claim. The
    request path here is fixed, so if upstream ever registered ``/mcp`` without
    the terminating slash, Starlette's ``redirect_slashes`` would answer 307 and
    the default client — which does not follow redirects — would fail on
    ``status_code == 200`` with the rewrite working correctly. That is a false
    failure attributed to our code, which is exactly what this test exists to
    rule out.

    **The load-bearing assertion is the one on ``authorization_servers``, not
    the one this test is named for.** ``pydantic.AnyHttpUrl`` only appends a
    slash to an *empty-path* authority, so ``https://api.example.com/mcp/``
    round-trips through it unchanged: both ``resource`` assertions below hold
    with the rewrite entirely absent. The issuer *is* the empty-path case
    (``https://auth.example.com`` becomes ``https://auth.example.com/``), so it
    is the only served field that moves when the route is not wrapped, and
    therefore the only one that can witness route selection. Do not prune it as
    an unrelated issuer check in a resource-named test — that guts the test
    while leaving it green.
    """
    mcp = _build_app(
        issuer="https://auth.example.com",
        resource="https://api.example.com/mcp/",
    )
    asgi_app = mcp.streamable_http_app()

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
        follow_redirects=True,
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp/")

    assert response.status_code == 200
    prm = response.json()
    # This is the assertion that pins route selection — see the docstring.
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["resource"] == "https://api.example.com/mcp/"
    assert prm["resource"].endswith("/")


@pytest.mark.asyncio
async def test_prm_advertises_root_resource_verbatim() -> None:
    """A resource configured with no trailing slash is advertised verbatim.

    An empty-path authority is exactly where ``pydantic.AnyHttpUrl`` inserts a
    trailing slash (``AuthSettings.resource_server_url`` becomes
    ``https://api.example.com/``), so this pins the rewrite of the served
    ``resource`` back to the configured ``https://api.example.com``.
    """
    mcp = _build_app(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
    )
    asgi_app = mcp.streamable_http_app()

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    prm = response.json()
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["resource"] == "https://api.example.com"
    assert not prm["resource"].endswith("/")
