"""Tests for revoke_token bare function."""

from unittest.mock import AsyncMock, patch

import pytest

from authplane.errors import ServerError
from authplane.net import FetchSettings
from authplane.net.http import FormPostResponse
from authplane.oauth.revocation import revoke_token


@pytest.mark.asyncio
async def test_revoke_success():
    with patch(
        "authplane.oauth.revocation.form_post",
        new_callable=AsyncMock,
        return_value=FormPostResponse(status_code=200, body={}, headers={}),
    ):
        await revoke_token(
            "https://auth.example.com/oauth/revoke",
            "token_to_revoke",
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            FetchSettings(ssrf_protection=False),
        )


@pytest.mark.asyncio
async def test_revoke_server_error():
    with (
        patch(
            "authplane.oauth.revocation.form_post",
            new_callable=AsyncMock,
            return_value=FormPostResponse(
                status_code=500, body={"error": "server_error"}, headers={}
            ),
        ),
        pytest.raises(ServerError),
    ):
        await revoke_token(
            "https://auth.example.com/oauth/revoke",
            "token_to_revoke",
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            FetchSettings(ssrf_protection=False),
        )
