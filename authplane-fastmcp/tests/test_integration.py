"""Integration tests for authplane-fastmcp with a real FastMCP app.

These tests verify that the adapter correctly integrates with FastMCP's HTTP layer,
specifically testing the Protected Resource Metadata (PRM) endpoint which FastMCP
exposes when an auth provider is configured.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_prm_endpoint(test_client: AsyncClient) -> None:
    """GET /.well-known/oauth-protected-resource/mcp returns valid PRM JSON."""
    response = await test_client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    prm = response.json()

    # Verify PRM structure per RFC 9728
    assert "resource" in prm
    assert "authorization_servers" in prm
    # The advertised issuer must be byte-for-byte the configured identifier.
    # Upstream serializes it through pydantic AnyHttpUrl, which would append a
    # trailing slash to the empty-path authority; the adapter rewrites the
    # served value back to the verbatim form so it matches the core SDK's
    # strict comparison (RFC 8414 §3.3, RFC 9728 §3.3).
    assert prm["authorization_servers"] == ["https://auth.example.com"]

    # The advertised resource is likewise verbatim (no trailing slash added).
    assert prm["resource"] == "https://api.example.com/mcp"

    assert "scopes_supported" in prm
    assert set(prm["scopes_supported"]) == {
        "tools/query",
        "tools/write",
        "tools/admin",
    }

    assert "bearer_methods_supported" in prm
    assert "header" in prm["bearer_methods_supported"]


@pytest.mark.asyncio
async def test_prm_advertises_configured_issuer_without_trailing_slash(
    test_client: AsyncClient,
) -> None:
    """An issuer configured without a trailing slash is advertised verbatim.

    An empty-path authority is exactly where ``pydantic.AnyHttpUrl`` inserts a
    trailing slash, so this pins the rewrite that keeps the advertised
    identifier byte-for-byte the configured value.
    """
    response = await test_client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    prm = response.json()
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert not prm["authorization_servers"][0].endswith("/")
    # The resource keeps its exact configured form (path preserved, no slash added).
    assert prm["resource"] == "https://api.example.com/mcp"
