"""Tests for AuthplaneClient."""

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from authplane import ASCredentials, AuthplaneClient
from authplane.errors import CircuitOpenError, ServerError
from authplane.oauth.types import IntrospectionResponse, TokenResponse


async def make_client(**kwargs: Any):
    """Create a client with mocked metadata/JWKS initialization."""
    with patch.object(AuthplaneClient, "_initialize_caches", new_callable=AsyncMock):
        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            auth=ASCredentials(client_id="test", client_secret="secret"),
            **kwargs,
        )
        mock_metadata = AsyncMock()
        mock_metadata.get = AsyncMock(
            return_value={
                "token_endpoint": "https://auth.example.com/oauth/token",
                "introspection_endpoint": "https://auth.example.com/oauth/introspect",
                "revocation_endpoint": "https://auth.example.com/oauth/revoke",
            }
        )
        mock_metadata.get_token_endpoint = AsyncMock(
            return_value="https://auth.example.com/oauth/token"
        )
        mock_metadata.get_introspection_endpoint = AsyncMock(
            return_value="https://auth.example.com/oauth/introspect"
        )
        mock_metadata.get_revocation_endpoint = AsyncMock(
            return_value="https://auth.example.com/oauth/revoke"
        )
        mock_metadata.aclose = AsyncMock()
        client._metadata_cache = mock_metadata  # pyright: ignore[reportPrivateUsage]
        return client


@pytest.mark.asyncio
async def test_client_credentials_caches_token():
    client = await make_client()
    mock_response = TokenResponse(
        access_token="tok1",
        token_type="Bearer",
        expires_in=3600,
        scope="read",
    )

    with patch(
        "authplane.client.client_credentials_grant",
        new_callable=AsyncMock,
        return_value=mock_response,
    ):
        result1 = await client.client_credentials(scopes=["read"])
        assert result1.access_token == "tok1"

        result2 = await client.client_credentials(scopes=["read"])
        assert result2.access_token == "tok1"


@pytest.mark.asyncio
async def test_client_credentials_preserves_cnf_jkt_on_cache_hit():
    # The cache-hit branch must rebuild the TokenResponse with its DPoP
    # binding intact; otherwise a sender-constrained token degrades to a
    # bearer-only shape on every subsequent hit (RFC 9449 §6.1).
    client = await make_client()
    mock_response = TokenResponse(
        access_token="tok1",
        token_type="DPoP",
        expires_in=3600,
        scope="read",
        cnf_jkt="thumbprint-abc",
    )

    with patch(
        "authplane.client.client_credentials_grant",
        new_callable=AsyncMock,
        return_value=mock_response,
    ) as mock_grant:
        # First call populates the cache via the grant path.
        first = await client.client_credentials(scopes=["read"])
        assert first.cnf_jkt == "thumbprint-abc"

        # Second call must take the cache-hit branch (no extra grant call)
        # and still surface the binding.
        second = await client.client_credentials(scopes=["read"])
        assert mock_grant.await_count == 1
        assert second.token_type == "DPoP"
        assert second.cnf_jkt == "thumbprint-abc"


@pytest.mark.asyncio
async def test_circuit_breaker_opens_on_server_errors():
    client = await make_client(circuit_breaker_threshold=2)

    with patch(
        "authplane.client.client_credentials_grant",
        new_callable=AsyncMock,
        side_effect=ServerError("server error", code="server_error", status_code=500),
    ):
        with pytest.raises(ServerError):
            await client.client_credentials()
        with pytest.raises(ServerError):
            await client.client_credentials()

        with pytest.raises(CircuitOpenError):
            await client.client_credentials()


@pytest.mark.asyncio
async def test_revoke_calls_endpoint():
    client = await make_client()

    with patch("authplane.client.revoke_token", new_callable=AsyncMock) as mock_revoke:
        await client.revoke("some-token")
        mock_revoke.assert_called_once()


@pytest.mark.asyncio
async def test_introspect_returns_response():
    client = await make_client()
    mock_resp = IntrospectionResponse(active=True, sub="user1")

    with patch("authplane.client.introspect_token", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.introspect("some-token")
        assert result.active is True
        assert result.sub == "user1"


@pytest.mark.asyncio
async def test_resource_factory():
    client = await make_client()
    res = client.resource(resource="https://api.example.com", scopes=["read"])
    assert res.resource == "https://api.example.com"
    assert res.scopes == ("read",)


@pytest.mark.asyncio
async def test_aclose():
    client = await make_client()
    mock_jwks = AsyncMock()
    client._jwks_cache = mock_jwks  # pyright: ignore[reportPrivateUsage]

    await client.aclose()
    mock_jwks.aclose.assert_called_once()
