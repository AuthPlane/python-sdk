"""Unit tests for authplane_auth factory function."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from authplane import DPoPProvider, FetchSettings, VerifiedClaims

from authplane_fastmcp import authplane_auth
from authplane_fastmcp.auth import AuthplaneAuthResult


@pytest.mark.asyncio
async def test_authplane_auth_parameter_propagation():
    """Verify that parameters are split correctly between client and verifier."""
    custom_fetch_settings = FetchSettings(ssrf_protection=False, allow_http=True, timeout=30.0)
    dpop_provider = MagicMock(spec=DPoPProvider)

    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            scopes=["read"],
            dpop=dpop_provider,
            allowed_algorithms=["RS256"],
            jwks_refresh_seconds=600,
            metadata_refresh_seconds=7200,
            cache_ttl_buffer_seconds=15.0,
            default_ttl_seconds=900.0,
            cache_max_entries=500,
            circuit_breaker_threshold=7,
            circuit_breaker_cooldown_seconds=45.0,
            clock_skew_seconds=60,
            dev_mode=True,
            fetch_settings=custom_fetch_settings,
        )

        # Client-level params
        mock_client_cls.create.assert_called_once()
        client_kwargs = mock_client_cls.create.call_args.kwargs
        assert client_kwargs["issuer"] == "https://auth.example.com"
        assert client_kwargs["dpop"] is dpop_provider
        assert client_kwargs["dev_mode"] is True
        assert client_kwargs["jwks_refresh_seconds"] == 600
        assert client_kwargs["metadata_refresh_seconds"] == 7200
        assert client_kwargs["cache_ttl_buffer_seconds"] == 15.0
        assert client_kwargs["default_ttl_seconds"] == 900.0
        assert client_kwargs["cache_max_entries"] == 500
        assert client_kwargs["circuit_breaker_threshold"] == 7
        assert client_kwargs["circuit_breaker_cooldown_seconds"] == 45.0
        assert client_kwargs["fetch_settings"] is custom_fetch_settings

        # Verifier-level params
        mock_client.resource.assert_called_once()
        verifier_kwargs = mock_client.resource.call_args
        assert verifier_kwargs.kwargs["allowed_algorithms"] == ["RS256"]
        assert verifier_kwargs.kwargs["clock_skew_seconds"] == 60
        assert verifier_kwargs.kwargs["resource"] == "https://api.example.com/mcp"  # resource
        assert verifier_kwargs.kwargs["scopes"] == ["read"]


@pytest.mark.asyncio
async def test_authplane_auth_none_filtering():
    """Verify that None values are NOT passed to AuthplaneClient.create or client.resource."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        mock_client_cls.create.assert_called_once()
        client_kwargs = mock_client_cls.create.call_args.kwargs
        # Standard params should be there
        assert "issuer" in client_kwargs

        # Optional params NOT specified should NOT be in kwargs (so SDK can use defaults)
        assert "dpop" not in client_kwargs
        assert "dev_mode" not in client_kwargs
        assert "fetch_settings" not in client_kwargs
        assert "metadata_refresh_seconds" not in client_kwargs
        assert "cache_ttl_buffer_seconds" not in client_kwargs
        assert "default_ttl_seconds" not in client_kwargs
        assert "cache_max_entries" not in client_kwargs
        assert "circuit_breaker_threshold" not in client_kwargs
        assert "circuit_breaker_cooldown_seconds" not in client_kwargs

        # Verifier-level optional params should also be filtered
        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert "clock_skew_seconds" not in verifier_kwargs
        assert "allowed_algorithms" not in verifier_kwargs


@pytest.mark.asyncio
async def test_authplane_auth_revocation_checker_default_is_none():
    """When revocation_checker is not passed, None is forwarded (no revocation checking)."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        # Default is None -> no revocation checking (offline validation only)
        assert verifier_kwargs["revocation_checker"] is None


@pytest.mark.asyncio
async def test_authplane_auth_revocation_checker_custom_callable():
    """A custom async revocation_checker is forwarded to client.resource()."""

    async def my_checker(claims: VerifiedClaims, raw_token: str) -> bool:
        return False

    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            revocation_checker=my_checker,
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert verifier_kwargs["revocation_checker"] is my_checker


@pytest.mark.asyncio
async def test_authplane_auth_resource_derivation():
    """Verify resource URL construction from base_url and mcp_path."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        # Case 1: Trailing slash on base_url, leading slash on mcp_path
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com/",
            mcp_path="/mcp",
        )
        assert mock_client.resource.call_args.kwargs["resource"] == "https://api.example.com/mcp"

        # Case 2: No trailing slash, leading slash
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            mcp_path="/mcp",
        )
        assert mock_client.resource.call_args.kwargs["resource"] == "https://api.example.com/mcp"

        # Case 3: Custom mcp_path
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            mcp_path="api/v1/mcp",
        )
        assert (
            mock_client.resource.call_args.kwargs["resource"]
            == "https://api.example.com/api/v1/mcp"
        )


@pytest.mark.asyncio
async def test_authplane_auth_as_credentials_passthrough():
    """as_credentials is forwarded to AuthplaneClient.create as auth."""
    from authplane import ASCredentials

    creds = ASCredentials(client_id="client_id", client_secret="secret")
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            as_credentials=creds,
        )

        client_kwargs = mock_client_cls.create.call_args.kwargs
        assert client_kwargs["auth"] is creds


@pytest.mark.asyncio
async def test_authplane_auth_returns_auth_result():
    """authplane_auth() returns an AuthplaneAuthResult with auth, token_verifier, and client."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with (
        patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls,
        patch("authplane_fastmcp.auth.RemoteAuthProvider") as mock_auth_cls,
    ):
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        result = await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        assert isinstance(result, AuthplaneAuthResult)
        assert result.auth is mock_auth_cls.return_value
        assert result.token_verifier is not None
        assert result.client is mock_client


def test_authplane_auth_result_keys():
    """AuthplaneAuthResult.keys() returns only 'auth'."""
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=MagicMock())
    assert result.keys() == ["auth"]


def test_authplane_auth_result_getitem_auth():
    """AuthplaneAuthResult['auth'] returns the auth provider."""
    mock_auth = AsyncMock()
    result = AuthplaneAuthResult(auth=mock_auth, token_verifier=AsyncMock(), client=MagicMock())
    assert result["auth"] is mock_auth


def test_authplane_auth_result_getitem_unknown_raises():
    """AuthplaneAuthResult[unknown_key] raises KeyError."""
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=MagicMock())
    with pytest.raises(KeyError):
        _ = result["unknown"]


def test_authplane_auth_result_iter():
    """Iterating AuthplaneAuthResult yields only 'auth'."""
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=MagicMock())
    assert list(result) == ["auth"]


def test_authplane_auth_result_unpack():
    """AuthplaneAuthResult supports ** unpacking with only the 'auth' key."""
    mock_auth = AsyncMock()
    result = AuthplaneAuthResult(auth=mock_auth, token_verifier=AsyncMock(), client=MagicMock())
    unpacked = {**result}
    assert unpacked == {"auth": mock_auth}


# ---------------------------------------------------------------------------
# aclose lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_auth_result_aclose_delegates_to_client():
    """aclose() calls client.aclose() to release resources."""
    mock_client = AsyncMock()
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=mock_client)
    await result.aclose()
    mock_client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_authplane_auth_result_aclose_idempotent():
    """aclose() can be called multiple times without error."""
    mock_client = AsyncMock()
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=mock_client)
    await result.aclose()
    await result.aclose()
    assert mock_client.aclose.await_count == 2


# ---------------------------------------------------------------------------
# Resource URL alignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_auth_resource_matches_default_mcp_path():
    """Resource passed to verifier must equal base_url + default mcp_path (/mcp)."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )
        resource = mock_client.resource.call_args.kwargs["resource"]
        assert resource == "https://api.example.com/mcp"


# ---------------------------------------------------------------------------
# Non-AuthplaneError propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_token_non_authplane_error_propagates():
    """Unexpected exceptions from AuthplaneResource.verify() propagate (HTTP 500)."""
    from authplane_fastmcp import AuthplaneTokenVerifier

    mock_verifier = AsyncMock()
    mock_verifier.resource = "https://api.example.com/mcp"
    mock_verifier.verify.side_effect = RuntimeError("unexpected")

    tv = AuthplaneTokenVerifier(mock_verifier)
    with pytest.raises(RuntimeError, match="unexpected"):
        await tv.verify_token("some_token")
