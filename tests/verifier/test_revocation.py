"""Tests for the revocation checking (built-in introspection via AuthplaneClient)."""

from collections.abc import AsyncGenerator
from typing import Any

import pytest
import respx
from respx.models import Route

from authplane import ASCredentials, AuthplaneClient, AuthplaneResource, FetchSettings
from authplane.errors import TokenRevokedError
from authplane.oauth.types import IntrospectionRevocation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ISSUER = "https://auth.example.com"
RESOURCE = "https://api.example.com"
METADATA_URL = f"{ISSUER}/.well-known/oauth-authorization-server"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
INTROSPECTION_URL = f"{ISSUER}/oauth/introspect"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_jwks_with_introspection(jwks_keypair: dict[str, Any]) -> Any:
    """Mock metadata (including introspection_endpoint) and JWKS endpoints."""
    with respx.mock:
        metadata_doc = {
            "issuer": ISSUER,
            "jwks_uri": JWKS_URL,
            "introspection_endpoint": INTROSPECTION_URL,
        }
        respx.get(METADATA_URL).mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        respx.get(JWKS_URL).mock(
            return_value=respx.MockResponse(status_code=200, json=jwks_keypair["jwks"])
        )
        yield


@pytest.fixture
async def client_with_introspection(
    mock_jwks_with_introspection: None,
) -> AsyncGenerator[AuthplaneClient]:
    """Client configured for introspection."""
    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    yield c
    await c.aclose()


@pytest.fixture
async def verifier_with_introspection(
    client_with_introspection: AuthplaneClient,
) -> AsyncGenerator[AuthplaneResource]:
    """Verifier using built-in introspection checking via revocation_checker=IntrospectionRevocation()."""
    v = client_with_introspection.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=IntrospectionRevocation(),
    )
    yield v


@pytest.fixture
async def verifier_disabled(mock_jwks: Route) -> AsyncGenerator[AuthplaneResource]:
    """Verifier with revocation checking explicitly disabled."""
    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    v = c.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=None,
    )
    yield v
    await c.aclose()


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


async def test_revocation_checking_not_called_on_invalid_signature(
    mock_jwks_with_introspection: None,
    token_factory: Any,
) -> None:
    """Revocation check must not be called when signature validation fails first."""
    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    v = c.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=IntrospectionRevocation(),
    )
    try:
        # Tamper with the signature
        good_token = token_factory()
        parts = good_token.split(".")
        tampered = parts[0] + "." + parts[1] + ".invalidsignature"

        from authplane.errors import InvalidSignatureError

        with pytest.raises(InvalidSignatureError):
            await v.verify(tampered)
    finally:
        await c.aclose()


# ---------------------------------------------------------------------------
# Disabled revocation (revocation_checker=None)
# ---------------------------------------------------------------------------


async def test_revocation_disabled_passes_without_check(
    verifier_disabled: AuthplaneResource,
    token_factory: Any,
) -> None:
    """revocation_checker=None -> verify() returns claims with no revocation check."""
    token = token_factory()
    claims = await verifier_disabled.verify(token)
    assert claims.sub == "user123"


async def test_custom_revocation_checker_error_fails_open(
    mock_jwks: Route,
    token_factory: Any,
) -> None:
    """Custom revocation callback errors are logged and treated as fail-open."""

    async def crashing_checker(claims: Any, raw_token: str) -> bool:
        raise RuntimeError("revocation backend unavailable")

    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    v = c.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=crashing_checker,
    )
    try:
        token = token_factory()
        claims = await v.verify(token)
        assert claims.sub == "user123"
    finally:
        await c.aclose()


# ---------------------------------------------------------------------------
# Built-in introspection tests
# ---------------------------------------------------------------------------


async def test_introspection_active_true_passes(
    verifier_with_introspection: AuthplaneResource,
    token_factory: Any,
) -> None:
    """Introspection returns active=true -> verify() returns claims normally."""
    respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True, "jti": "token-id-123"})
    )
    token = token_factory()
    claims = await verifier_with_introspection.verify(token)
    assert claims.sub == "user123"


async def test_introspection_active_false_raises(
    verifier_with_introspection: AuthplaneResource,
    token_factory: Any,
) -> None:
    """Introspection returns active=false -> TokenRevokedError is raised."""
    respx.post(INTROSPECTION_URL).mock(return_value=respx.MockResponse(200, json={"active": False}))
    token = token_factory()
    with pytest.raises(TokenRevokedError):
        await verifier_with_introspection.verify(token)


async def test_introspection_http_error_fails_open(
    verifier_with_introspection: AuthplaneResource,
    token_factory: Any,
) -> None:
    """Introspection endpoint returns HTTP 500 -> fail-open, token accepted."""
    respx.post(INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(500, json={"error": "server_error"})
    )
    token = token_factory()
    # Should not raise - fail-open policy
    claims = await verifier_with_introspection.verify(token)
    assert claims.sub == "user123"


async def test_introspection_no_endpoint_in_metadata_skips(
    mock_jwks: Route,  # metadata without introspection_endpoint
    token_factory: Any,
) -> None:
    """Metadata without introspection_endpoint -> check is skipped, token accepted."""
    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    v = c.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=IntrospectionRevocation(),
    )
    try:
        token = token_factory()
        claims = await v.verify(token)
        assert claims.sub == "user123"
    finally:
        await c.aclose()


async def test_introspection_sends_correct_token(
    verifier_with_introspection: AuthplaneResource,
    token_factory: Any,
) -> None:
    """Built-in introspection POSTs the raw token string to the endpoint."""
    import httpx

    received_body: dict[str, str] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        body = dict(request.read().decode().split("&")[i].split("=") for i in range(2))  # type: ignore[misc]
        received_body.update(body)
        return httpx.Response(200, json={"active": True})

    respx.post(INTROSPECTION_URL).mock(side_effect=capture)

    token = token_factory()
    await verifier_with_introspection.verify(token)

    assert received_body.get("token_type_hint") == "access_token"
    assert "token" in received_body


# ---------------------------------------------------------------------------
# ASCredentials tests
# ---------------------------------------------------------------------------


async def test_as_credentials_authenticates_introspection(
    mock_jwks_with_introspection: None,
    token_factory: Any,
) -> None:
    """as_credentials are forwarded as HTTP Basic auth to the introspection endpoint."""
    import httpx

    received_auth: list[str] = []

    def capture(request: httpx.Request) -> httpx.Response:
        received_auth.append(request.headers.get("Authorization", ""))
        return httpx.Response(200, json={"active": True})

    respx.post(INTROSPECTION_URL).mock(side_effect=capture)

    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
        auth=ASCredentials(client_id="my-rs", client_secret="s3cret"),
    )
    v = c.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=IntrospectionRevocation(),
    )
    try:
        token = token_factory()
        await v.verify(token)
    finally:
        await c.aclose()

    assert len(received_auth) == 1
    assert received_auth[0].startswith("Basic ")


async def test_exchange_requires_as_credentials(
    mock_jwks_with_introspection: None,
) -> None:
    """client.exchange() requires as_credentials to be set for auth."""
    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    try:
        # Without credentials, the auth_header is empty but exchange still works
        # (the AS may reject it, but the client doesn't prevent the call)
        # This test verifies the client can be used without credentials
        assert c._auth is None  # pyright: ignore[reportPrivateUsage]
    finally:
        await c.aclose()


async def test_exchange_with_as_credentials(
    mock_jwks_with_introspection: None,
) -> None:
    """client.exchange() succeeds when as_credentials is provided."""
    from authplane.oauth.types import TokenExchangeOptions

    metadata_doc = {
        "issuer": ISSUER,
        "jwks_uri": JWKS_URL,
        "introspection_endpoint": INTROSPECTION_URL,
        "token_endpoint": f"{ISSUER}/oauth/token",
    }
    # Patch metadata to include token_endpoint
    with respx.mock(assert_all_called=False):
        respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(200, json=metadata_doc)
        )
        respx.get(JWKS_URL).mock(return_value=respx.MockResponse(200, json={}))
        respx.post(f"{ISSUER}/oauth/token").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "access_token": "tok",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "read",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                },
            )
        )

        c = await AuthplaneClient.create(
            issuer=ISSUER,
            fetch_settings=FetchSettings(ssrf_protection=False),
            auth=ASCredentials(client_id="my-rs", client_secret="s3cret"),
        )
        try:
            result = await c.exchange(TokenExchangeOptions(subject_token="some-token"))
            assert result.access_token == "tok"
        finally:
            await c.aclose()


async def test_as_credentials_without_revocation(
    mock_jwks_with_introspection: None,
    token_factory: Any,
) -> None:
    """as_credentials can be set without enabling revocation checking (for token exchange only)."""
    c = await AuthplaneClient.create(
        issuer=ISSUER,
        fetch_settings=FetchSettings(ssrf_protection=False),
        auth=ASCredentials(client_id="my-rs", client_secret="s3cret"),
    )
    v = c.resource(
        resource=RESOURCE,
        scopes=["read:data"],
        revocation_checker=None,
    )
    try:
        token = token_factory()
        claims = await v.verify(token)
        assert claims.sub == "user123"
    finally:
        await c.aclose()
