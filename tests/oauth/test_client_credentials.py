"""Tests for client_credentials_grant bare function."""

from unittest.mock import AsyncMock, patch

import pytest

from authplane.errors import InvalidClientError, ServerError
from authplane.net import FetchSettings
from authplane.net.http import FormPostResponse
from authplane.oauth.client_credentials import client_credentials_grant


@pytest.mark.asyncio
async def test_success():
    mock_data = {
        "access_token": "new_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
    }
    with patch(
        "authplane.oauth.client_credentials.form_post",
        new_callable=AsyncMock,
        return_value=FormPostResponse(status_code=200, body=mock_data, headers={}),
    ):
        result = await client_credentials_grant(
            "https://auth.example.com/oauth/token",
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            FetchSettings(ssrf_protection=False),
            scopes=["read"],
        )
        assert result.access_token == "new_token"
        assert result.token_type == "Bearer"


@pytest.mark.asyncio
async def test_server_error():
    with (
        patch(
            "authplane.oauth.client_credentials.form_post",
            new_callable=AsyncMock,
            return_value=FormPostResponse(
                status_code=500, body={"error": "server_error"}, headers={}
            ),
        ),
        pytest.raises(ServerError),
    ):
        await client_credentials_grant(
            "https://auth.example.com/oauth/token",
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            FetchSettings(ssrf_protection=False),
        )


@pytest.mark.asyncio
async def test_invalid_client():
    with (
        patch(
            "authplane.oauth.client_credentials.form_post",
            new_callable=AsyncMock,
            return_value=FormPostResponse(
                status_code=401,
                body={"error": "invalid_client", "error_description": "bad creds"},
                headers={},
            ),
        ),
        pytest.raises(InvalidClientError, match="bad creds"),
    ):
        await client_credentials_grant(
            "https://auth.example.com/oauth/token",
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            FetchSettings(ssrf_protection=False),
        )
