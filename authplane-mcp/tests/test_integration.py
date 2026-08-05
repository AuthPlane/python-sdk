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
