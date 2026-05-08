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
    # Pydantic AnyHttpUrl normalizes URLs with trailing slash
    assert prm["authorization_servers"] == ["https://auth.example.com/"]

    assert "scopes_supported" in prm
    assert set(prm["scopes_supported"]) == {
        "tools/query",
        "tools/write",
        "tools/admin",
    }

    assert "bearer_methods_supported" in prm
    assert "header" in prm["bearer_methods_supported"]
