import logging
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from authplane import AuthplaneError, TokenExpiredError, VerifiedClaims
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


@pytest.mark.asyncio
async def test_verify_token_failure_logs_typed_error_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Regression: returning None still has to happen (the MCP
    # contract requires it), but operators must see *which* typed error caused
    # the 401 in their logs. Debug-level because invalid tokens are expected
    # steady-state and shouldn't page on-call.
    mock_verifier = AsyncMock()
    mock_verifier.verify.side_effect = TokenExpiredError("expired at 2026")

    adapter = AuthplaneTokenVerifier(mock_verifier)

    with caplog.at_level(logging.DEBUG, logger="authplane_mcp.verifier"):
        result = await adapter.verify_token("expired_jwt")

    assert result is None
    matching = [r for r in caplog.records if r.name == "authplane_mcp.verifier"]
    assert len(matching) == 1
    record = matching[0]
    assert record.levelno == logging.DEBUG
    assert record.message == "authplane.token_verification_failed"
    assert record.error_class == "TokenExpiredError"  # type: ignore[attr-defined]
    assert record.error == "expired at 2026"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_verify_token_failure_silent_above_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # At default (INFO) level the structured event must not surface — invalid
    # tokens are too common in steady state to log at info.
    mock_verifier = AsyncMock()
    mock_verifier.verify.side_effect = AuthplaneError("bad token")

    adapter = AuthplaneTokenVerifier(mock_verifier)

    with caplog.at_level(logging.INFO, logger="authplane_mcp.verifier"):
        result = await adapter.verify_token("bad")

    assert result is None
    assert not [r for r in caplog.records if r.name == "authplane_mcp.verifier"]
