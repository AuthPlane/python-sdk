"""Unit tests for introspect_token() bare function (RFC 7662)."""

import base64
from dataclasses import FrozenInstanceError
from urllib.parse import quote

import httpx
import pytest
import respx

from authplane import FetchSettings
from authplane.errors import ServerError
from authplane.net.http import build_basic_auth_header
from authplane.oauth.introspection import introspect_token
from authplane.oauth.types import IntrospectionResponse

# Disable SSRF protection in tests so respx can intercept requests without
# DNS resolution attempting real network calls.
_NO_SSRF = FetchSettings(ssrf_protection=False)

INTROSPECTION_URL = "https://auth.example.com/oauth/introspect"


# ---------------------------------------------------------------------------
# active=true
# ---------------------------------------------------------------------------


@respx.mock
async def test_active_true_returns_active_response() -> None:
    """introspect_token returns IntrospectionResponse with active=True."""
    respx.post(INTROSPECTION_URL).mock(return_value=respx.MockResponse(200, json={"active": True}))
    result = await introspect_token(
        INTROSPECTION_URL,
        "raw-token",
        {},
        _NO_SSRF,
    )
    assert isinstance(result, IntrospectionResponse)
    assert result.active is True


# ---------------------------------------------------------------------------
# active=false
# ---------------------------------------------------------------------------


@respx.mock
async def test_active_false_returns_inactive_response() -> None:
    """introspect_token returns IntrospectionResponse with active=False."""
    respx.post(INTROSPECTION_URL).mock(return_value=respx.MockResponse(200, json={"active": False}))
    result = await introspect_token(
        INTROSPECTION_URL,
        "raw-token",
        {},
        _NO_SSRF,
    )
    assert result.active is False


# ---------------------------------------------------------------------------
# HTTP error raises
# ---------------------------------------------------------------------------


@respx.mock
async def test_http_error_raises() -> None:
    """introspect_token raises on HTTP 500."""
    respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(500, json={"error": "server_error"})
    )
    with pytest.raises(ServerError):
        await introspect_token(
            INTROSPECTION_URL,
            "raw-token",
            {},
            _NO_SSRF,
        )


@respx.mock
async def test_network_error_raises() -> None:
    """introspect_token raises when the endpoint is unreachable."""
    respx.post(INTROSPECTION_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    with pytest.raises(httpx.ConnectError):
        await introspect_token(
            INTROSPECTION_URL,
            "raw-token",
            {},
            _NO_SSRF,
        )


# ---------------------------------------------------------------------------
# Request shape — unauthenticated (no credentials)
# ---------------------------------------------------------------------------


@respx.mock
async def test_posts_token_and_hint() -> None:
    """introspect_token POSTs the raw token with token_type_hint=access_token."""
    route = respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    await introspect_token(INTROSPECTION_URL, "my.raw.token", {}, _NO_SSRF)

    request = route.calls.last.request
    body_str = request.content.decode()
    captured: dict[str, str] = {}
    for p in body_str.split("&"):
        if "=" in p:
            k, v = p.split("=", 1)
            captured[k] = v

    assert captured["token"] == "my.raw.token"
    assert captured["token_type_hint"] == "access_token"


@respx.mock
async def test_no_auth_header_without_credentials() -> None:
    """introspect_token sends no Authorization header when auth_header is empty."""
    route = respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    await introspect_token(INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)

    request = route.calls.last.request
    assert "authorization" not in request.headers


# ---------------------------------------------------------------------------
# Authenticated call (with client credentials)
# ---------------------------------------------------------------------------


@respx.mock
async def test_basic_auth_header_sent_with_credentials() -> None:
    """introspect_token sends Authorization: Basic when auth_header is provided."""
    auth_header = build_basic_auth_header("my-client-id", "my-client-secret")
    route = respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    result = await introspect_token(INTROSPECTION_URL, "raw-token", auth_header, _NO_SSRF)

    assert result.active is True
    request = route.calls.last.request
    expected = base64.b64encode(b"my-client-id:my-client-secret").decode()
    assert request.headers.get("authorization") == f"Basic {expected}"


# ---------------------------------------------------------------------------
# URL-encoded client_id in Basic auth
# ---------------------------------------------------------------------------


@respx.mock
async def test_url_client_id_is_percent_encoded_in_basic_auth() -> None:
    """RFC 6749 section 2.3.1: client_id with special chars must be URL-encoded before base64."""
    auth_header = build_basic_auth_header("http://localhost:8080/mcp", "s3cret")
    route = respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    await introspect_token(INTROSPECTION_URL, "raw-token", auth_header, _NO_SSRF)

    request = route.calls.last.request
    encoded_id = quote("http://localhost:8080/mcp", safe="")
    encoded_secret = quote("s3cret", safe="")
    expected = base64.b64encode(f"{encoded_id}:{encoded_secret}".encode()).decode()
    assert request.headers.get("authorization") == f"Basic {expected}"


# ---------------------------------------------------------------------------
# Missing 'active' field defaults to False
# ---------------------------------------------------------------------------


@respx.mock
async def test_missing_active_field_defaults_to_false() -> None:
    """introspect_token returns active=False when response lacks 'active' field."""
    respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"error": "invalid_token"})
    )
    result = await introspect_token(INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert result.active is False


# ---------------------------------------------------------------------------
# Response field parsing
# ---------------------------------------------------------------------------


@respx.mock
async def test_full_response_fields_parsed() -> None:
    """All standard introspection response fields are parsed correctly."""
    respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "active": True,
                "scope": "read:data write:data",
                "client_id": "client456",
                "sub": "user123",
                "token_type": "access_token",
                "iss": "https://auth.example.com",
                "exp": 1234567890,
                "iat": 1234567800,
                "jti": "token-id-123",
            },
        )
    )
    result = await introspect_token(INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)

    assert result.active is True
    assert result.scope == "read:data write:data"
    assert result.client_id == "client456"
    assert result.sub == "user123"
    assert result.token_type == "access_token"
    assert result.iss == "https://auth.example.com"
    assert result.exp == 1234567890
    assert result.iat == 1234567800
    assert result.jti == "token-id-123"


# ---------------------------------------------------------------------------
# IntrospectionResponse is frozen
# ---------------------------------------------------------------------------


def test_introspection_response_is_frozen() -> None:
    """IntrospectionResponse should be immutable."""
    resp = IntrospectionResponse(active=True)
    with pytest.raises(FrozenInstanceError):
        resp.active = False  # type: ignore[misc]
