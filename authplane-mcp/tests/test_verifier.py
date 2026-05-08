from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from authplane import AuthplaneError, VerifiedClaims
from mcp.server.auth.provider import AccessToken

from authplane_mcp.verifier import AuthplaneTokenVerifier


@pytest.fixture
def valid_claims() -> VerifiedClaims:
    return VerifiedClaims(
        sub="user_123",
        client_id="client_456",
        scopes=("read", "write"),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1700000000,
        issued_at=1699999000,
        jti="token_123",
        kid="key_1",
        raw={"sub": "user_123", "client_id": "client_456"},
    )


@pytest.mark.asyncio
async def test_verify_token_success(valid_claims: VerifiedClaims) -> None:
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = valid_claims

    adapter = AuthplaneTokenVerifier(mock_verifier)
    result = await adapter.verify_token("valid_jwt")

    assert isinstance(result, AccessToken)
    assert result.token == "valid_jwt"
    assert result.client_id == "client_456"
    assert result.scopes == ["read", "write"]
    assert result.expires_at == 1700000000
    assert result.resource == "https://api.example.com"

    mock_verifier.verify.assert_awaited_once_with("valid_jwt")


@pytest.mark.asyncio
async def test_verify_token_failure() -> None:
    mock_verifier = AsyncMock()
    mock_verifier.verify.side_effect = AuthplaneError("Invalid token")

    adapter = AuthplaneTokenVerifier(mock_verifier)
    result = await adapter.verify_token("invalid_jwt")

    assert result is None
    mock_verifier.verify.assert_awaited_once_with("invalid_jwt")


@pytest.mark.asyncio
async def test_verify_token_with_list_audience(valid_claims: VerifiedClaims) -> None:
    mock_verifier = AsyncMock()
    # Simulate audience being a list from a mocked verifier.
    claims_with_list_aud: VerifiedClaims = replace(
        valid_claims, audience=["https://api.example.com"]
    )

    mock_verifier.verify.return_value = claims_with_list_aud

    adapter = AuthplaneTokenVerifier(mock_verifier)
    result = await adapter.verify_token("valid_jwt")

    assert isinstance(result, AccessToken)
    assert result.resource == "https://api.example.com"


def test_verifier_property() -> None:
    """verifier property exposes the underlying AuthplaneResource."""
    mock_verifier = AsyncMock()
    adapter = AuthplaneTokenVerifier(mock_verifier)
    assert adapter.verifier is mock_verifier
