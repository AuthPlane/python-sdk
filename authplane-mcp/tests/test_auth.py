"""Unit tests for authplane_mcp_auth factory function and require_scope helper."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from authplane import DPoPProvider, FetchSettings, VerifiedClaims
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from authplane_mcp.auth import AuthplaneAuthResult, authplane_mcp_auth, require_scope
from authplane_mcp.verifier import AuthplaneTokenVerifier

# ---------------------------------------------------------------------------
# require_scope
# ---------------------------------------------------------------------------


def _make_token(scopes: list[str]) -> AccessToken:
    return AccessToken(
        token="tok",
        client_id="client_1",
        scopes=scopes,
        expires_at=9999999999,
        resource="https://api.example.com",
    )


def test_require_scope_passes_when_scope_present():
    with patch(
        "authplane_mcp.auth._get_access_token",
        return_value=_make_token(["tools/add", "tools/multiply"]),
    ):
        require_scope("tools/add")  # must not raise


def test_require_scope_raises_when_scope_missing():
    with (
        patch("authplane_mcp.auth._get_access_token", return_value=_make_token(["tools/multiply"])),
        pytest.raises(PermissionError, match="tools/add"),
    ):
        require_scope("tools/add")


def test_require_scope_raises_when_token_is_none():
    with (
        patch("authplane_mcp.auth._get_access_token", return_value=None),
        pytest.raises(PermissionError, match="tools/add"),
    ):
        require_scope("tools/add")


def test_require_scope_raises_when_scopes_empty():
    with (
        patch("authplane_mcp.auth._get_access_token", return_value=_make_token([])),
        pytest.raises(PermissionError),
    ):
        require_scope("tools/add")


# ---------------------------------------------------------------------------
# authplane_mcp_auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_mcp_auth_returns_auth_result():
    """Verify return type and AuthSettings fields."""
    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        result = await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
            scopes=["read"],
            dev_mode=True,
        )

        assert isinstance(result, AuthplaneAuthResult)
        assert isinstance(result.token_verifier, AuthplaneTokenVerifier)
        assert isinstance(result.auth, AuthSettings)
        assert result.client is mock_client

        assert str(result.auth.issuer_url) == "https://auth.example.com/"
        assert str(result.auth.resource_server_url) == "https://api.example.com/"
        # Scopes must NOT be passed as required_scopes — the MCP SDK
        # enforces required_scopes globally via RequireAuthMiddleware,
        # which would reject clients that don't carry ALL listed scopes.
        assert result.auth.required_scopes is None

        # Mapping protocol
        assert result.keys() == ["token_verifier", "auth"]
        assert result["token_verifier"] is result.token_verifier
        assert result["auth"] is result.auth


@pytest.mark.asyncio
async def test_authplane_mcp_auth_parameter_propagation():
    """Verify that parameters are split correctly between client and verifier."""
    custom_fetch_settings = FetchSettings(ssrf_protection=False, allow_http=True, timeout=30.0)
    dpop_provider = MagicMock(spec=DPoPProvider)

    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
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
        assert verifier_kwargs.kwargs["resource"] == "https://api.example.com"  # resource
        assert verifier_kwargs.kwargs["scopes"] == ["read"]  # scopes


@pytest.mark.asyncio
async def test_authplane_mcp_auth_none_filtering():
    """Verify that None values are NOT passed to AuthplaneClient.create or client.resource."""
    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
        )

        mock_client_cls.create.assert_called_once()
        client_kwargs = mock_client_cls.create.call_args.kwargs
        # Standard params should be there
        assert "issuer" in client_kwargs

        # Optional params NOT specified should NOT be in kwargs
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
async def test_authplane_mcp_auth_revocation_checker_default_is_none():
    """When revocation_checker is not passed, None is forwarded (no revocation checking)."""
    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        # Default is None -> no revocation checking (offline validation only)
        assert verifier_kwargs["revocation_checker"] is None


@pytest.mark.asyncio
async def test_authplane_mcp_auth_revocation_checker_custom_callable():
    """A custom async revocation_checker is forwarded to client.resource()."""

    async def my_checker(claims: VerifiedClaims, raw_token: str) -> bool:
        return False

    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
            revocation_checker=my_checker,
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert verifier_kwargs["revocation_checker"] is my_checker


@pytest.mark.asyncio
async def test_authplane_mcp_auth_as_credentials_passthrough():
    """as_credentials is forwarded to AuthplaneClient.create as auth."""
    from authplane import ASCredentials

    creds = ASCredentials(client_id="client_id", client_secret="secret")
    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
            as_credentials=creds,
        )

        client_kwargs = mock_client_cls.create.call_args.kwargs
        assert client_kwargs["auth"] is creds


def test_authplane_auth_result_unpack():
    """AuthplaneAuthResult supports ** unpacking with token_verifier and auth keys."""
    mock_tv = MagicMock()
    mock_auth = MagicMock()
    result = AuthplaneAuthResult(token_verifier=mock_tv, auth=mock_auth, client=MagicMock())
    unpacked = {**result}
    assert unpacked == {"token_verifier": mock_tv, "auth": mock_auth}


def test_authplane_auth_result_getitem_unknown_raises():
    """AuthplaneAuthResult[unknown_key] raises KeyError."""
    result = AuthplaneAuthResult(token_verifier=MagicMock(), auth=MagicMock(), client=MagicMock())
    with pytest.raises(KeyError):
        _ = result["unknown"]


# ---------------------------------------------------------------------------
# aclose lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_auth_result_aclose_delegates_to_client():
    """aclose() calls client.aclose() to release resources."""
    mock_client = AsyncMock()
    result = AuthplaneAuthResult(token_verifier=MagicMock(), auth=MagicMock(), client=mock_client)
    await result.aclose()
    mock_client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_authplane_auth_result_aclose_idempotent():
    """aclose() can be called multiple times without error."""
    mock_client = AsyncMock()
    result = AuthplaneAuthResult(token_verifier=MagicMock(), auth=MagicMock(), client=mock_client)
    await result.aclose()
    await result.aclose()
    assert mock_client.aclose.await_count == 2


# ---------------------------------------------------------------------------
# Scopes are NOT passed as required_scopes (MCP SDK enforces globally)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_mcp_auth_scopes_not_enforced_globally():
    """Scopes must not be set as AuthSettings.required_scopes.

    The MCP SDK uses required_scopes for both PRM scopes_supported AND
    RequireAuthMiddleware enforcement.  Passing scopes here would reject
    any client whose token does not carry ALL listed scopes, breaking
    per-tool enforcement via require_scope().
    """
    mock_client = MagicMock()
    mock_client.resource = MagicMock(return_value=MagicMock(resource="https://api.example.com"))

    with patch("authplane_mcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        result = await authplane_mcp_auth(
            issuer="https://auth.example.com",
            resource="https://api.example.com",
            scopes=["tools/add", "tools/multiply"],
        )

        # Scopes are passed to the verifier (for JWT audience/scope validation)
        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert verifier_kwargs["scopes"] == ["tools/add", "tools/multiply"]

        # But NOT to AuthSettings (would break per-tool enforcement)
        assert result.auth.required_scopes is None


# ---------------------------------------------------------------------------
# Non-AuthplaneError propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_token_non_authplane_error_propagates():
    """Unexpected exceptions from AuthplaneResource.verify() propagate (HTTP 500)."""
    from unittest.mock import PropertyMock

    from authplane import AuthplaneResource

    mock_verifier = AsyncMock(spec=AuthplaneResource)
    type(mock_verifier).resource = PropertyMock(return_value="https://api.example.com")
    mock_verifier.verify.side_effect = RuntimeError("unexpected")

    tv = AuthplaneTokenVerifier(mock_verifier)
    with pytest.raises(RuntimeError, match="unexpected"):
        await tv.verify_token("some_token")
