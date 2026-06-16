"""Unit tests for AuthplaneTokenVerifier."""

import logging
from unittest.mock import AsyncMock

import pytest
from authplane import AuthplaneError, TokenExpiredError, VerifiedClaims

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

    async def verify_expired(token: str, *, dpop_request: object | None = None) -> VerifiedClaims:
        _ = dpop_request
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


@pytest.mark.asyncio
async def test_verify_token_failure_logs_typed_error_at_debug(
    mock_verifier: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    # Regression: contract-required None return must still
    # produce an operator-side signal carrying the typed error class and
    # message. Debug-level so steady-state invalid tokens stay quiet.
    mock_verifier.verify.side_effect = TokenExpiredError("expired at 2026")

    verifier = AuthplaneTokenVerifier(mock_verifier)

    with caplog.at_level(logging.DEBUG, logger="authplane_fastmcp.verifier"):
        result = await verifier.verify_token("expired_jwt")

    assert result is None
    matching = [r for r in caplog.records if r.name == "authplane_fastmcp.verifier"]
    assert len(matching) == 1
    record = matching[0]
    assert record.levelno == logging.DEBUG
    assert record.message == "authplane.token_verification_failed"
    assert record.error_class == "TokenExpiredError"  # type: ignore[attr-defined]
    assert record.error == "expired at 2026"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_verify_token_failure_silent_above_debug(
    mock_verifier: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    # Default INFO level must not surface the event.
    mock_verifier.verify.side_effect = AuthplaneError("bad token")

    verifier = AuthplaneTokenVerifier(mock_verifier)

    with caplog.at_level(logging.INFO, logger="authplane_fastmcp.verifier"):
        result = await verifier.verify_token("bad")

    assert result is None
    assert not [r for r in caplog.records if r.name == "authplane_fastmcp.verifier"]
