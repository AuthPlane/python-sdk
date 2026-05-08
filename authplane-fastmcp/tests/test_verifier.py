"""Unit tests for AuthplaneTokenVerifier."""

from unittest.mock import AsyncMock

import pytest
from authplane import VerifiedClaims

from authplane_fastmcp import AuthplaneTokenVerifier


@pytest.mark.asyncio
async def test_verify_token_valid(
    token_verifier: AuthplaneTokenVerifier, valid_claims: VerifiedClaims
) -> None:
    """verify_token() with valid token returns AccessToken with correct fields."""
    access_token = await token_verifier.verify_token("valid_token")

    assert access_token is not None
    assert access_token.client_id == "client_456"
    assert access_token.scopes == ["tools/query", "tools/write"]
    assert access_token.expires_at == valid_claims.expires_at


@pytest.mark.asyncio
async def test_verify_token_claims_equals_raw(
    token_verifier: AuthplaneTokenVerifier, valid_claims: VerifiedClaims
) -> None:
    """verify_token() with valid token: AccessToken.claims equals VerifiedClaims.raw."""
    access_token = await token_verifier.verify_token("valid_token")

    assert access_token is not None
    assert access_token.claims == valid_claims.raw


@pytest.mark.asyncio
async def test_verify_token_claims_sub_matches(
    token_verifier: AuthplaneTokenVerifier, valid_claims: VerifiedClaims
) -> None:
    """verify_token() with valid token: AccessToken.claims['sub'] matches VerifiedClaims.sub."""
    access_token = await token_verifier.verify_token("valid_token")

    assert access_token is not None
    assert access_token.claims["sub"] == valid_claims.sub
    assert access_token.claims["sub"] == "user_123"


@pytest.mark.asyncio
async def test_verify_token_invalid_returns_none(token_verifier: AuthplaneTokenVerifier) -> None:
    """verify_token() with invalid token returns None."""
    access_token = await token_verifier.verify_token("invalid_token")
    assert access_token is None


@pytest.mark.asyncio
async def test_verify_token_expired_returns_none(
    mock_verifier: AsyncMock, valid_claims: VerifiedClaims
) -> None:
    """verify_token() with expired token returns None."""
    from authplane.errors import TokenExpiredError

    async def verify_expired(token: str) -> VerifiedClaims:
        raise TokenExpiredError("Token has expired")

    mock_verifier.verify.side_effect = verify_expired

    verifier = AuthplaneTokenVerifier(mock_verifier)
    access_token = await verifier.verify_token("expired_token")
    assert access_token is None


@pytest.mark.asyncio
async def test_access_token_scopes_match(
    token_verifier: AuthplaneTokenVerifier, valid_claims: VerifiedClaims
) -> None:
    """AccessToken.scopes matches VerifiedClaims.scopes (same list, same order)."""
    access_token = await token_verifier.verify_token("valid_token")

    assert access_token is not None
    assert access_token.scopes == list(valid_claims.scopes)
    assert access_token.scopes == ["tools/query", "tools/write"]


@pytest.mark.asyncio
async def test_custom_claims_accessible(token_verifier: AuthplaneTokenVerifier) -> None:
    """Custom claims like tenant_id are accessible in AccessToken.claims."""
    access_token = await token_verifier.verify_token("valid_token")

    assert access_token is not None
    assert "tenant_id" in access_token.claims
    assert access_token.claims["tenant_id"] == "tenant_789"


def test_scopes_supported_property(
    token_verifier: AuthplaneTokenVerifier, mock_verifier: AsyncMock
) -> None:
    """scopes_supported property returns verifier's scopes."""
    assert token_verifier.scopes_supported == ["tools/query", "tools/write"]
    assert token_verifier.scopes_supported == mock_verifier.scopes


def test_verifier_property(
    token_verifier: AuthplaneTokenVerifier, mock_verifier: AsyncMock
) -> None:
    """verifier property exposes the underlying AuthplaneResource."""
    assert token_verifier.verifier is mock_verifier
