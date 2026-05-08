"""Unit tests for token exchange (RFC 8693) using bare functions."""

import base64
from dataclasses import FrozenInstanceError

import httpx
import pytest
import respx

from authplane import FetchSettings
from authplane.errors import (
    AuthError,
    AuthplaneError,
    ConsentRequiredError,
    InvalidClientError,
    InvalidGrantError,
    InvalidScopeError,
    ServerError,
)
from authplane.net.http import build_basic_auth_header
from authplane.oauth.token_exchange import exchange_token
from authplane.oauth.types import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TokenExchangeOptions,
    TokenResponse,
)

# Disable SSRF protection so respx can intercept without real DNS resolution.
_NO_SSRF = FetchSettings(ssrf_protection=False)

TOKEN_ENDPOINT = "https://auth.example.com/oauth/token"
CLIENT_ID = "my-service"
CLIENT_SECRET = "s3cr3t"
SUBJECT_TOKEN = "eyJhbGciOiJFUzI1NiJ9.subject"
ACTOR_TOKEN = "eyJhbGciOiJFUzI1NiJ9.actor"
EXCHANGED_TOKEN = "eyJhbGciOiJFUzI1NiJ9.exchanged"


def make_auth_header() -> dict[str, str]:
    """Build HTTP Basic auth header for tests."""
    return build_basic_auth_header(CLIENT_ID, CLIENT_SECRET)


def success_body(**extra: object) -> dict[str, object]:
    return {
        "access_token": EXCHANGED_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "tools/echo",
        "issued_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        **extra,
    }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_grant_type_constant() -> None:
    assert GRANT_TYPE_TOKEN_EXCHANGE == "urn:ietf:params:oauth:grant-type:token-exchange"


def test_token_type_constant() -> None:
    assert TOKEN_TYPE_ACCESS_TOKEN == "urn:ietf:params:oauth:token-type:access_token"


# ---------------------------------------------------------------------------
# TokenExchangeOptions defaults
# ---------------------------------------------------------------------------


def test_options_defaults() -> None:
    opts = TokenExchangeOptions(subject_token=SUBJECT_TOKEN)
    assert opts.subject_token == SUBJECT_TOKEN
    assert opts.subject_token_type == ""
    assert opts.actor_token == ""
    assert opts.actor_token_type == ""
    assert opts.scope == ""
    assert opts.resources == ()
    assert opts.audiences == ()


# ---------------------------------------------------------------------------
# Successful exchange
# ---------------------------------------------------------------------------


@respx.mock
async def test_exchange_success() -> None:
    """A 200 response maps to a populated TokenResponse."""
    respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))

    resp = await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )

    assert isinstance(resp, TokenResponse)
    assert resp.access_token == EXCHANGED_TOKEN
    assert resp.token_type == "Bearer"
    assert resp.expires_in == 3600
    assert resp.scope == "tools/echo"
    assert resp.issued_token_type == TOKEN_TYPE_ACCESS_TOKEN


@respx.mock
async def test_exchange_success_optional_refresh_token() -> None:
    """refresh_token is populated when present in response."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(200, json=success_body(refresh_token="rt-abc"))
    )
    resp = await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )
    assert resp.refresh_token == "rt-abc"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


async def test_exchange_missing_subject_token_raises() -> None:
    """Empty subject_token raises ValueError before any HTTP call."""
    with pytest.raises(ValueError, match="subject_token is required"):
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=""),
            make_auth_header(),
            _NO_SSRF,
        )


# ---------------------------------------------------------------------------
# Default token type applied
# ---------------------------------------------------------------------------


@respx.mock
async def test_exchange_default_subject_token_type() -> None:
    """subject_token_type defaults to TOKEN_TYPE_ACCESS_TOKEN when empty."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )

    request = route.calls.last.request
    body = dict(pair.split("=") for pair in request.content.decode().split("&"))
    assert body["subject_token_type"] == TOKEN_TYPE_ACCESS_TOKEN.replace(":", "%3A").replace(
        "+", "%2B"
    )


@respx.mock
async def test_exchange_custom_subject_token_type_preserved() -> None:
    """A non-empty subject_token_type is sent as-is."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    custom_type = "urn:ietf:params:oauth:token-type:jwt"
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN, subject_token_type=custom_type),
        make_auth_header(),
        _NO_SSRF,
    )
    request = route.calls.last.request
    assert custom_type.replace(":", "%3A") in request.content.decode()


# ---------------------------------------------------------------------------
# Optional fields
# ---------------------------------------------------------------------------


@respx.mock
async def test_exchange_optional_fields_omitted_when_empty() -> None:
    """actor_token, scope, and resource are absent from POST body when empty."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )

    body = route.calls.last.request.content.decode()
    assert "actor_token" not in body
    assert "actor_token_type" not in body
    assert "scope" not in body
    assert "resource" not in body


@respx.mock
async def test_exchange_actor_token_included() -> None:
    """actor_token and actor_token_type are included when actor_token is set."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN, actor_token=ACTOR_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert "actor_token=" in body
    assert "actor_token_type=" in body


@respx.mock
async def test_exchange_actor_token_type_defaults_when_actor_set() -> None:
    """actor_token_type defaults to TOKEN_TYPE_ACCESS_TOKEN when actor_token is set."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN, actor_token=ACTOR_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert TOKEN_TYPE_ACCESS_TOKEN.replace(":", "%3A").replace("+", "%2B") in body


@respx.mock
async def test_exchange_custom_actor_token_type_preserved() -> None:
    """A non-empty actor_token_type is sent as-is."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    custom_type = "urn:ietf:params:oauth:token-type:jwt"
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(
            subject_token=SUBJECT_TOKEN,
            actor_token=ACTOR_TOKEN,
            actor_token_type=custom_type,
        ),
        make_auth_header(),
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert custom_type.replace(":", "%3A") in body


@respx.mock
async def test_exchange_scope_included() -> None:
    """scope field is present in POST body when set."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN, scope="tools/echo"),
        make_auth_header(),
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert "scope=tools%2Fecho" in body or "scope=tools/echo" in body


@respx.mock
async def test_exchange_resource_included() -> None:
    """resource field is present in POST body when set."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN, resources=("https://mcp.example.com/",)),
        make_auth_header(),
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert "resource=" in body


# ---------------------------------------------------------------------------
# HTTP Basic auth header
# ---------------------------------------------------------------------------


@respx.mock
async def test_exchange_http_basic_auth_header_format() -> None:
    """Authorization header is correct RFC 6749 HTTP Basic auth."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )

    auth_header = route.calls.last.request.headers["authorization"]
    assert auth_header.startswith("Basic ")
    decoded = base64.b64decode(auth_header[6:]).decode()
    assert decoded == f"{CLIENT_ID}:{CLIENT_SECRET}"


@respx.mock
async def test_exchange_special_chars_in_credentials_url_encoded() -> None:
    """Special characters in client_id/secret are URL-encoded before base64."""
    auth_header = build_basic_auth_header("client+id", "sec:ret")
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        auth_header,
        _NO_SSRF,
    )

    auth = route.calls.last.request.headers["authorization"]
    raw = base64.b64decode(auth[6:]).decode()
    # URL-encoded form: + -> %2B, : -> %3A
    assert raw == "client%2Bid:sec%3Aret"


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


@respx.mock
async def test_exchange_invalid_grant() -> None:
    """400 invalid_grant maps to InvalidGrantError."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            400,
            json={"error": "invalid_grant", "error_description": "token expired"},
        )
    )
    with pytest.raises(InvalidGrantError, match="token expired"):
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
            make_auth_header(),
            _NO_SSRF,
        )


@respx.mock
async def test_exchange_invalid_scope() -> None:
    """400 invalid_scope maps to InsufficientScopeError."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            400,
            json={"error": "invalid_scope", "error_description": "scope exceeds grant"},
        )
    )
    with pytest.raises(InvalidScopeError, match="scope exceeds grant"):
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN, scope="admin"),
            make_auth_header(),
            _NO_SSRF,
        )


@respx.mock
async def test_exchange_invalid_client() -> None:
    """400 invalid_client maps to InvalidClaimsError."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            400,
            json={"error": "invalid_client", "error_description": "bad credentials"},
        )
    )
    with pytest.raises(InvalidClientError, match="bad credentials"):
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
            make_auth_header(),
            _NO_SSRF,
        )


@respx.mock
async def test_exchange_consent_required_maps_to_consent_required_error() -> None:
    """400 consent_required maps to ConsentRequiredError with metadata."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "consent_required",
                "error_description": "user must grant access",
                "service_id": "calendar",
                "cause": "missing_user_consent",
                "consent_url": "https://as.example.com/consent?service=calendar",
            },
        )
    )
    with pytest.raises(ConsentRequiredError) as exc:
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
            make_auth_header(),
            _NO_SSRF,
        )

    error = exc.value
    assert error.code == "consent_required"
    assert error.service_id == "calendar"
    assert error.cause_detail == "missing_user_consent"
    assert error.consent_url == "https://as.example.com/consent?service=calendar"


@respx.mock
async def test_exchange_interaction_required_maps_to_consent_required_error() -> None:
    """400 interaction_required maps to ConsentRequiredError."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "interaction_required",
                "error_description": "user interaction required",
                "service": "profile",
            },
        )
    )
    with pytest.raises(ConsentRequiredError) as exc:
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
            make_auth_header(),
            _NO_SSRF,
        )

    error = exc.value
    assert error.code == "interaction_required"
    assert error.service_id == "profile"


@respx.mock
async def test_exchange_401_no_oauth_error_maps_to_invalid_claims() -> None:
    """401 without OAuth error body maps to InvalidClaimsError."""
    respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(401, json={}))
    with pytest.raises(InvalidClientError):
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
            make_auth_header(),
            _NO_SSRF,
        )


@respx.mock
async def test_exchange_500_maps_to_invalid_claims() -> None:
    """500 server error maps to InvalidClaimsError."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(500, json={"error": "server_error"})
    )
    with pytest.raises(ServerError):
        await exchange_token(
            TOKEN_ENDPOINT,
            TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
            make_auth_header(),
            _NO_SSRF,
        )


@respx.mock
async def test_exchange_errors_are_authplane_errors() -> None:
    """All token exchange errors are AuthplaneError subclasses."""
    for err_code, _ in [
        ("invalid_grant", InvalidGrantError),
        ("invalid_scope", InvalidScopeError),
        ("invalid_client", InvalidClientError),
    ]:
        respx.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(400, json={"error": err_code, "error_description": "test"})
        )
        with pytest.raises(AuthError):
            await exchange_token(
                TOKEN_ENDPOINT,
                TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
                make_auth_header(),
                _NO_SSRF,
            )


def test_auth_error_inherits_from_authplane_error() -> None:
    assert issubclass(AuthError, AuthplaneError)


# ---------------------------------------------------------------------------
# grant_type always present
# ---------------------------------------------------------------------------


@respx.mock
async def test_exchange_grant_type_always_present() -> None:
    """grant_type is always included in POST body."""
    route = respx.post(TOKEN_ENDPOINT).mock(return_value=httpx.Response(200, json=success_body()))
    await exchange_token(
        TOKEN_ENDPOINT,
        TokenExchangeOptions(subject_token=SUBJECT_TOKEN),
        make_auth_header(),
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert "grant_type=" in body
    assert "token-exchange" in body


# ---------------------------------------------------------------------------
# TokenResponse is immutable
# ---------------------------------------------------------------------------


def test_token_response_is_frozen() -> None:
    resp = TokenResponse(access_token="tok", token_type="Bearer", expires_in=3600, scope="read")
    with pytest.raises(FrozenInstanceError):
        resp.access_token = "other"  # type: ignore[misc]
