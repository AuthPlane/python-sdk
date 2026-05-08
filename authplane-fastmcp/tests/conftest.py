"""Shared test fixtures for authplane-fastmcp tests."""

import time
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, PropertyMock

import pytest
from authplane import AuthplaneResource, VerifiedClaims
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken, RemoteAuthProvider, require_scopes
from httpx import ASGITransport, AsyncClient
from pydantic import AnyHttpUrl

from authplane_fastmcp import AuthplaneTokenVerifier


@pytest.fixture
def valid_claims() -> VerifiedClaims:
    """Fixed VerifiedClaims for testing.

    Returns:
        VerifiedClaims with sub="user_123", client_id="client_456",
        scopes=["tools/query", "tools/write"], and tenant_id in raw
    """
    now = int(time.time())
    raw_claims = {
        "iss": "https://auth.example.com",
        "aud": "https://api.example.com",
        "sub": "user_123",
        "client_id": "client_456",
        "scope": "tools/query tools/write",
        "exp": now + 3600,
        "nbf": now,
        "iat": now,
        "jti": "token-id-123",
        "tenant_id": "tenant_789",
    }

    return VerifiedClaims(
        sub="user_123",
        client_id="client_456",
        scopes=("tools/query", "tools/write"),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=now + 3600,
        issued_at=now,
        jti="token-id-123",
        kid="test-key-1",
        raw=raw_claims,
    )


@pytest.fixture
def mock_verifier(valid_claims: VerifiedClaims) -> AsyncMock:
    """Mock AuthplaneResource.

    Returns:
        Mock AuthplaneResource where verify("valid_token") returns valid_claims
        and verify("invalid_token") raises AuthplaneError
    """
    from authplane import AuthplaneError

    mock = AsyncMock(spec=AuthplaneResource)
    type(mock).scopes = PropertyMock(return_value=["tools/query", "tools/write"])

    async def verify_side_effect(token: str) -> VerifiedClaims:
        if token == "valid_token":
            return valid_claims
        raise AuthplaneError("Invalid token")

    mock.verify = AsyncMock(side_effect=verify_side_effect)
    return mock


@pytest.fixture
def token_verifier(mock_verifier: AsyncMock) -> AuthplaneTokenVerifier:
    """AuthplaneTokenVerifier with mocked AuthplaneResource.

    Returns:
        AuthplaneTokenVerifier(mock_verifier)
    """
    return AuthplaneTokenVerifier(mock_verifier, base_url="https://api.example.com")


@pytest.fixture
def fastmcp_app(token_verifier: AuthplaneTokenVerifier) -> FastMCP:
    """Minimal FastMCP app with three tools for testing.

    Tools:
    - echo: no scope, no token param
    - query: auth=require_scopes("tools/query"), injects token
    - admin: auth=require_scopes("tools/admin"), injects token (not in test token)

    Returns:
        FastMCP application instance
    """
    auth_provider = RemoteAuthProvider(
        token_verifier=token_verifier,
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
        base_url=AnyHttpUrl("https://api.example.com"),
        scopes_supported=["tools/query", "tools/write", "tools/admin"],
    )

    mcp = FastMCP("Test Server", auth=auth_provider)

    @mcp.tool()
    async def echo(message: str) -> str:
        """Echo tool - no scope, no token param."""
        return f"echo: {message}"

    @mcp.tool(auth=require_scopes("tools/query"))
    async def query(q: str, token: AccessToken = CurrentAccessToken()) -> str:  # noqa: B008
        """Query tool - requires tools/query scope, injects token."""
        sub = token.claims.get("sub")
        tenant_id = token.claims.get("tenant_id")
        return f"query={q}, sub={sub}, tenant={tenant_id}"

    @mcp.tool(auth=require_scopes("tools/admin"))
    async def admin(action: str, token: AccessToken = CurrentAccessToken()) -> str:  # noqa: B008
        """Admin tool - requires tools/admin scope (not in test token)."""
        return f"admin: {action}"

    _ = echo, query, admin  # registered with mcp, not referenced directly
    return mcp


@pytest.fixture
async def test_client(fastmcp_app: FastMCP) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client pointed at fastmcp_app.

    Returns:
        AsyncClient configured to talk to the FastMCP app HTTP endpoints
    """
    asgi_app = fastmcp_app.http_app(transport="streamable-http")

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
    ) as client:
        yield client
