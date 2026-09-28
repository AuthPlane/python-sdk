"""Tests for AuthplaneResource core validation logic."""

import asyncio
import time
from collections.abc import Callable
from typing import Any, Protocol

import httpx
import pytest
import respx
from respx.models import Route

from authplane import AuthplaneClient, AuthplaneResource, FetchSettings, InboundDPoPOptions
from authplane.errors import (
    InsufficientScopeError,
    InvalidClaimsError,
    InvalidResourceError,
    InvalidSignatureError,
    JWKSFetchError,
    MetadataFetchError,
    TokenExpiredError,
    response_headers_for,
)


class SigningKey(Protocol):
    """Shape of the keys minted by the ``signing_key_factory`` fixture.

    Declared structurally here for the same reason ``TokenFactory`` is declared
    in ``tests/conftest.py``: test modules are not a package, so the fixture's
    concrete type cannot be imported.
    """

    @property
    def jwks(self) -> dict[str, Any]:
        """The single-key JWKS document publishing this key."""
        ...

    def sign(self, **overrides: Any) -> str:
        """Sign an otherwise-valid access token for the default test resource."""
        ...


async def test_valid_token(verifier: AuthplaneResource, token_factory: Callable[..., str]) -> None:
    """Should successfully verify a valid token."""
    token = token_factory()
    claims = await verifier.verify(token)

    assert claims.sub == "user123"
    assert claims.client_id == "client456"
    assert claims.scopes == ("read:data", "write:data")
    assert claims.issuer == "https://auth.example.com"
    assert claims.audience == ("https://api.example.com",)
    assert claims.jti == "token-id-123"
    assert claims.kid == "test-key-1"
    assert "sub" in claims.raw


async def test_expired_token(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise TokenExpiredError for expired tokens."""
    # Create token that expired 1 hour ago
    exp = int(time.time()) - 3600
    token = token_factory(exp=exp)

    with pytest.raises(TokenExpiredError) as exc_info:
        await verifier.verify(token)

    assert "expired" in str(exc_info.value).lower()


async def test_wrong_issuer(verifier: AuthplaneResource, token_factory: Callable[..., str]) -> None:
    """Should raise InvalidClaimsError for wrong issuer."""
    token = token_factory(iss="https://wrong-issuer.com")

    with pytest.raises(InvalidClaimsError) as exc_info:
        await verifier.verify(token)

    assert "claim" in str(exc_info.value).lower()


async def test_wrong_audience(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError for wrong audience."""
    token = token_factory(aud="https://wrong-audience.com")

    with pytest.raises(InvalidClaimsError) as exc_info:
        await verifier.verify(token)

    assert "claim" in str(exc_info.value).lower()


async def test_wrong_typ_header(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError for wrong typ header."""
    # Create token with typ="JWT" instead of "at+jwt"
    token = token_factory(typ="JWT")

    with pytest.raises(InvalidClaimsError) as exc_info:
        await verifier.verify(token)

    assert "type" in str(exc_info.value).lower()
    assert "at+jwt" in str(exc_info.value)


async def test_bad_signature(verifier: AuthplaneResource) -> None:
    """Should raise InvalidSignatureError for tokens with bad signatures."""
    # Malformed token
    bad_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6InRlc3Qta2V5LTEifQ.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsInN1YiI6InVzZXIxMjMiLCJjbGllbnRfaWQiOiJjbGllbnQ0NTYiLCJzY29wZSI6InJlYWQ6ZGF0YSB3cml0ZTpkYXRhIiwiZXhwIjoxMjM0NTY3ODkwLCJpYXQiOjEyMzQ1Njc4MDAsImp0aSI6InRva2VuLWlkLTEyMyJ9.badsignaturebadsignaturebadsignature"

    with pytest.raises(InvalidSignatureError):
        await verifier.verify(bad_token)


async def test_alg_none_rejection(verifier: AuthplaneResource) -> None:
    """Should reject tokens with alg:none."""
    # Create a token with alg:none
    import base64
    import json

    header = {"alg": "none", "typ": "at+jwt"}
    payload = {
        "iss": "https://auth.example.com",
        "aud": "https://api.example.com",
        "sub": "user123",
        "client_id": "client456",
        "scope": "read:data",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "jti": "token-id",
    }

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    # alg:none tokens have empty signature
    none_token = f"{header_b64}.{payload_b64}."

    with pytest.raises((InvalidSignatureError, InvalidClaimsError)):
        await verifier.verify(none_token)


async def test_kid_not_in_jwks_force_refresh(
    jwks_keypair: dict[str, Any], token_factory: Callable[..., str]
) -> None:
    """Should force JWKS refresh when kid not found."""
    # Create a verifier with mock that returns JWKS without the key initially
    with respx.mock:
        empty_jwks: dict[str, list[Any]] = {"keys": []}
        full_jwks: Any = jwks_keypair["jwks"]

        metadata_doc = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )

        call_count = 0

        def jwks_response(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return respx.MockResponse(status_code=200, json=empty_jwks)
            else:
                return respx.MockResponse(status_code=200, json=full_jwks)

        respx.get("https://auth.example.com/.well-known/jwks.json").mock(side_effect=jwks_response)

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        verifier = client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
        )

        token = token_factory()

        try:
            # Should fetch JWKS twice (initial + force refresh)
            claims = await verifier.verify(token)
            assert claims.sub == "user123"
            assert call_count == 2
        finally:
            await client.aclose()


async def test_kid_not_found_after_refresh(
    jwks_keypair: dict[str, Any], token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidSignatureError if kid not found after refresh."""
    # Create JWKS without the test key
    with respx.mock:
        empty_jwks: dict[str, list[Any]] = {"keys": []}

        metadata_doc = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(status_code=200, json=empty_jwks)
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        verifier = client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
        )

        token = token_factory()

        try:
            with pytest.raises(InvalidSignatureError) as exc_info:
                await verifier.verify(token)

            assert "kid" in str(exc_info.value).lower()
            assert "test-key-1" in str(exc_info.value)
        finally:
            await client.aclose()


async def test_jwks_fetch_failure_no_cache(token_factory: Callable[..., str]) -> None:
    """Should raise JWKSFetchError if fetch fails with no cache."""
    with respx.mock:
        metadata_doc = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(status_code=200, json={"keys": []})
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        verifier = client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
        )

        try:
            # Now make JWKS endpoint fail
            respx.get("https://auth.example.com/.well-known/jwks.json").mock(
                return_value=respx.MockResponse(status_code=500)
            )
            # Force cache expiration AND clear the cached value so there is no
            # stale fallback -- this is the "no cache" scenario the test describes.
            client.jwks_cache._cache_time = 0  # pyright: ignore[reportPrivateUsage, reportOptionalMemberAccess]
            client.jwks_cache._cache = None  # pyright: ignore[reportPrivateUsage, reportOptionalMemberAccess]

            # Use a real token so header parsing succeeds and we reach JWKS fetch
            token = token_factory()
            with pytest.raises(JWKSFetchError):
                await verifier.verify(token)
        finally:
            await client.aclose()


async def test_jwks_fetch_failure_with_cache(
    verifier: AuthplaneResource, token_factory: Callable[..., str], jwks_keypair: dict[str, Any]
) -> None:
    """Should fall back to stale cache if fetch fails."""
    # First verify to populate cache
    token = token_factory()
    claims = await verifier.verify(token)
    assert claims.sub == "user123"

    # Now make JWKS endpoint fail
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(status_code=500)
        )

        # Force cache expiration by manipulating time
        verifier._client.jwks_cache._cache_time = 0  # pyright: ignore[reportPrivateUsage, reportOptionalMemberAccess]

        # Should still work with stale cache
        token2 = token_factory(jti="token-2")
        claims2 = await verifier.verify(token2)
        assert claims2.sub == "user123"


async def test_cache_ttl_behavior(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should use cache within TTL."""
    # The verifier fixture uses mock_jwks, so JWKS is already cached
    # First verification - this will use the cached JWKS from fixture
    token1 = token_factory(jti="token-1")
    await verifier.verify(token1)

    # Record the JWKS fetch time
    first_fetch_time = verifier._client.jwks_cache._cache_time  # pyright: ignore[reportPrivateUsage, reportOptionalMemberAccess]

    # Second verification - should use same cache
    token2 = token_factory(jti="token-2")
    await verifier.verify(token2)
    second_fetch_time = verifier._client.jwks_cache._cache_time  # pyright: ignore[reportPrivateUsage, reportOptionalMemberAccess]

    # Cache time should be the same (no new fetch)
    assert first_fetch_time == second_fetch_time


async def test_constructor_rejects_none_algorithm() -> None:
    """Constructor should reject 'none' algorithm."""
    with respx.mock:
        metadata_doc = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(status_code=200, json={"keys": []})
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        try:
            with pytest.raises(ValueError) as exc_info:
                client.resource(
                    resource="https://api.example.com",
                    scopes=["read:data"],
                    allowed_algorithms=["none"],
                )

                assert "unsupported algorithms" in str(exc_info.value).lower()
            assert "none" in str(exc_info.value).lower()
        finally:
            await client.aclose()


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
async def test_constructor_rejects_hmac_algorithms(alg: str) -> None:
    """Constructor should reject HMAC algorithms."""
    with respx.mock:
        metadata_doc = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(status_code=200, json={"keys": []})
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        try:
            with pytest.raises(ValueError) as exc_info:
                client.resource(
                    resource="https://api.example.com",
                    scopes=["read:data"],
                    allowed_algorithms=[alg],
                )

                assert "unsupported algorithms" in str(exc_info.value).lower()
        finally:
            await client.aclose()


@pytest.mark.parametrize(
    "kwarg,value",
    [
        ("jwks_refresh_seconds", 0),
        ("jwks_refresh_seconds", -1),
        ("jwks_refresh_seconds", -300),
        ("metadata_refresh_seconds", 0),
        ("metadata_refresh_seconds", -1),
        ("metadata_refresh_seconds", -3600),
    ],
)
async def test_constructor_rejects_non_positive_refresh_seconds(kwarg: str, value: int) -> None:
    """Constructor should reject zero or negative refresh intervals."""
    with pytest.raises(ValueError) as exc_info:
        await AuthplaneClient.create(
            issuer="https://auth.example.com",
            **{kwarg: value},  # pyright: ignore[reportArgumentType]
        )

    assert "must be positive" in str(exc_info.value)


async def test_constructor_accepts_valid_algorithms(mock_jwks: Route) -> None:
    """Constructor should accept RS256 and ES256."""
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    try:
        client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
            allowed_algorithms=["RS256", "ES256"],
        )

        client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
            allowed_algorithms=["ES256"],
        )
    finally:
        await client.aclose()


async def test_kid_field_populated(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """VerifiedClaims should have kid field populated."""
    token = token_factory()
    claims = await verifier.verify(token)

    assert claims.kid == "test-key-1"


async def test_prm_response(verifier: AuthplaneResource) -> None:
    """prm_response should return RFC 9728 compliant document."""
    prm = verifier.prm_response()

    assert prm["resource"] == "https://api.example.com"
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["scopes_supported"] == ("read:data", "write:data")
    assert prm["bearer_methods_supported"] == ["header"]


async def test_prm_url_for_root_resource(verifier: AuthplaneResource) -> None:
    # RFC 9728 §3: well-known suffix is appended directly when the resource
    # has no path component.
    assert verifier.prm_url() == "https://api.example.com/.well-known/oauth-protected-resource"


async def test_prm_url_for_path_resource(client: AuthplaneClient) -> None:
    # RFC 9728 §3: the path component shifts behind the well-known segment.
    resource = client.resource(resource="https://api.example.com/mcp", scopes=["read:data"])
    assert resource.prm_url() == "https://api.example.com/.well-known/oauth-protected-resource/mcp"


async def test_resource_metadata_url_defaults_to_the_derivation(
    client: AuthplaneClient,
) -> None:
    # No option set: the advertised URL is what prm_url() derives, byte for
    # byte — the guarantee every existing deployment relies on.
    resource = client.resource(resource="https://api.example.com/mcp", scopes=["read:data"])
    assert resource.resource_metadata_url() == resource.prm_url()
    assert (
        resource.resource_metadata_url()
        == "https://api.example.com/.well-known/oauth-protected-resource/mcp"
    )


async def test_resource_metadata_url_override_is_returned(client: AuthplaneClient) -> None:
    # The AS-hosted topology: authserver >= 0.2.0 serves the document for the
    # registered Resource, and the SDK only points at it. prm_url() keeps
    # naming the document this SDK itself builds.
    as_hosted = "https://auth.example.com/.well-known/oauth-protected-resource/mcp"
    resource = client.resource(
        resource="https://api.example.com/mcp",
        scopes=["read:data"],
        resource_metadata_url=as_hosted,
    )
    assert resource.resource_metadata_url() == as_hosted
    assert resource.prm_url() == "https://api.example.com/.well-known/oauth-protected-resource/mcp"


async def test_resource_metadata_url_override_reaches_401_and_403_challenges(
    client: AuthplaneClient,
) -> None:
    # Both challenge paths the RFC 9728 §5.1 parameter appears on: the 401 for
    # an unusable token and the 403 for insufficient scope.
    as_hosted = "https://auth.example.com/.well-known/oauth-protected-resource/mcp"
    resource = client.resource(
        resource="https://api.example.com/mcp",
        scopes=["read:data"],
        resource_metadata_url=as_hosted,
    )

    for error, expected_status in (
        (TokenExpiredError("expired"), 401),
        (InsufficientScopeError("nope", required_scopes=("read:data",)), 403),
    ):
        status, headers = response_headers_for(
            error,
            resource_metadata_url=resource.resource_metadata_url(),
        )
        assert status == expected_status
        assert f'resource_metadata="{as_hosted}"' in headers["WWW-Authenticate"]
        assert "api.example.com" not in headers["WWW-Authenticate"]


async def test_resource_rejects_an_invalid_resource_metadata_url(client: AuthplaneClient) -> None:
    # Construction-time, like the identifier itself: the value is advertised to
    # an unauthenticated caller from a 401 path, which is the worst place to
    # discover it is unusable.
    with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
        client.resource(
            resource="https://api.example.com/mcp",
            scopes=["read:data"],
            resource_metadata_url="/.well-known/oauth-protected-resource/mcp",
        )


async def test_prm_omits_dpop_fields_when_inbound_dpop_not_configured(
    client: AuthplaneClient,
) -> None:
    """Without inbound_dpop, PRM must not advertise DPoP fields."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    prm = verifier.prm_response()

    assert "dpop_signing_alg_values_supported" not in prm
    assert "dpop_bound_access_tokens_required" not in prm


async def test_prm_advertises_dpop_with_defaults_when_inbound_dpop_configured(
    client: AuthplaneClient,
) -> None:
    """Passing InboundDPoPOptions() (all defaults) flips PRM advertising on."""
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    prm = verifier.prm_response()

    assert prm["dpop_signing_alg_values_supported"] == ["ES256", "RS256"]
    assert prm["dpop_bound_access_tokens_required"] is False


async def test_aclose_cleanup(mock_jwks: Route) -> None:
    """aclose should clean up resources without raising."""
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )

    assert client.jwks_cache is not None

    # aclose should complete without raising
    await client.aclose()

    # Calling aclose a second time should also be safe
    await client.aclose()


async def test_scopes_split_correctly(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Scopes should be split from space-separated string to list."""
    token = token_factory(scope="read:data write:data admin")
    claims = await verifier.verify(token)

    assert claims.scopes == ("read:data", "write:data", "admin")


async def test_empty_scope_string(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Empty scope string should result in empty list."""
    token = token_factory(scope="")
    claims = await verifier.verify(token)

    assert claims.scopes == ()


async def test_missing_jti_claim(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError if jti is missing."""
    pass  # Implementation verified in code review


async def test_token_with_extra_claims(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should accept tokens with extra claims beyond required ones."""
    token = token_factory(
        custom_claim="custom_value",
        another_claim={"nested": "data"},
    )
    claims = await verifier.verify(token)

    assert claims.sub == "user123"
    assert claims.raw["custom_claim"] == "custom_value"
    assert claims.has_claim("custom_claim", "custom_value")


# ---------------------------------------------------------------------------
# Fix 1 -- sub, client_id, iat required in claims_options
# ---------------------------------------------------------------------------


async def test_missing_sub_claim(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError if sub is missing."""
    token = token_factory(exclude_claims=["sub"])

    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token)


async def test_missing_client_id_claim(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError if client_id is missing."""
    token = token_factory(exclude_claims=["client_id"])

    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token)


async def test_missing_iat_claim(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError if iat is missing."""
    token = token_factory(exclude_claims=["iat"])

    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token)


# ---------------------------------------------------------------------------
# Fix 2 -- nbf required
# ---------------------------------------------------------------------------


async def test_missing_nbf_claim(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """nbf is optional per RFC 9068 S2.1 -- tokens without it must be accepted."""
    token = token_factory(exclude_claims=["nbf"])

    claims = await verifier.verify(token)
    assert claims is not None


async def test_nbf_in_future_beyond_leeway_rejected(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError if nbf is beyond clock_skew_seconds in the future."""
    future_nbf = int(time.time()) + 300  # 5 minutes ahead, well beyond 30 s leeway
    token = token_factory(nbf=future_nbf)

    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token)


async def test_nbf_within_clock_skew_accepted(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should accept a token whose nbf is within clock_skew_seconds in the future."""
    slightly_future_nbf = int(time.time()) + 10  # 10 s ahead, within 30 s leeway
    token = token_factory(nbf=slightly_future_nbf)

    claims = await verifier.verify(token)
    assert claims.sub == "user123"


# ---------------------------------------------------------------------------
# Fix 3 -- alg header validated against allowlist before authlib
# ---------------------------------------------------------------------------


async def test_alg_not_in_allowlist(mock_jwks: Route, token_factory: Callable[..., str]) -> None:
    """Should raise InvalidClaimsError when the token alg is not in allowed_algorithms."""
    # Verifier accepts only RS256; token is signed with ES256.
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        allowed_algorithms=["RS256"],
    )
    try:
        token = token_factory()  # ES256 by default

        with pytest.raises(InvalidClaimsError) as exc_info:
            await verifier.verify(token)

        assert "algorithm" in str(exc_info.value).lower()
        assert "ES256" in str(exc_info.value)
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Fix 4 -- clock_skew_seconds leeway for exp/nbf
# ---------------------------------------------------------------------------


async def test_exp_within_clock_skew_accepted(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should accept a token that expired within clock_skew_seconds ago."""
    exp = int(time.time()) - 10  # Expired 10 s ago, within the default 30 s leeway
    token = token_factory(exp=exp)

    claims = await verifier.verify(token)
    assert claims.sub == "user123"


async def test_clock_skew_seconds_is_configurable(
    mock_jwks: Route, token_factory: Callable[..., str]
) -> None:
    """A token expired 5 s ago should be rejected when clock_skew_seconds=0."""
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        clock_skew_seconds=0,
    )
    try:
        exp = int(time.time()) - 5
        token = token_factory(exp=exp)

        with pytest.raises(TokenExpiredError):
            await verifier.verify(token)
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Fix 5 -- iat must not be in the future
# ---------------------------------------------------------------------------


async def test_future_iat_rejected(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should raise InvalidClaimsError when iat is more than clock_skew_seconds in the future."""
    future_iat = int(time.time()) + 300  # 5 minutes ahead, well beyond 30 s leeway
    token = token_factory(iat=future_iat)

    with pytest.raises(InvalidClaimsError) as exc_info:
        await verifier.verify(token)

    assert "iat" in str(exc_info.value).lower()


async def test_iat_within_clock_skew_accepted(
    verifier: AuthplaneResource, token_factory: Callable[..., str]
) -> None:
    """Should accept a token whose iat is within clock_skew_seconds in the future."""
    slightly_future_iat = int(time.time()) + 10  # 10 s ahead, within 30 s leeway
    token = token_factory(iat=slightly_future_iat)

    claims = await verifier.verify(token)
    assert claims.sub == "user123"


# ---------------------------------------------------------------------------
# RFC 8414 Discovery Tests
# ---------------------------------------------------------------------------


async def test_discovery_mode_successful(
    verifier_with_discovery: AuthplaneResource,
    token_factory: Callable[..., str],
    mock_as_metadata: dict[str, Route],
) -> None:
    """Should successfully discover JWKS URI and verify token."""
    token = token_factory()
    claims = await verifier_with_discovery.verify(token)

    assert claims.sub == "user123"
    assert claims.client_id == "client456"

    # Verify metadata endpoint was called
    assert mock_as_metadata["metadata"].called
    # Verify JWKS endpoint was called
    assert mock_as_metadata["jwks"].called


async def test_discovery_mode_concurrent_verify_single_fetch(
    verifier_with_discovery: AuthplaneResource,
    token_factory: Callable[..., str],
    mock_as_metadata: dict[str, Route],
) -> None:
    """Concurrent verify() calls should all succeed after eager discovery."""
    import asyncio

    token = token_factory()

    # Concurrent verify calls
    results = await asyncio.gather(
        verifier_with_discovery.verify(token),
        verifier_with_discovery.verify(token),
        verifier_with_discovery.verify(token),
    )

    # All should succeed
    assert all(r.sub == "user123" for r in results)

    # Metadata was fetched once at create() time
    assert mock_as_metadata["metadata"].call_count == 1


async def test_metadata_missing_jwks_uri(
    jwks_keypair: dict[str, Any], token_factory: Callable[..., str]
) -> None:
    """Should raise MetadataFetchError if jwks_uri is missing from metadata."""
    with respx.mock:
        # Mock metadata endpoint without jwks_uri
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                status_code=200,
                json={"issuer": "https://auth.example.com"},  # Missing jwks_uri
            )
        )

        with pytest.raises(MetadataFetchError, match="missing required 'jwks_uri' field"):
            await AuthplaneClient.create(
                issuer="https://auth.example.com",
                fetch_settings=FetchSettings(ssrf_protection=False),
            )


async def test_aclose_cleans_up_metadata_cache(
    client_with_discovery: AuthplaneClient, token_factory: Callable[..., str]
) -> None:
    """Should clean up metadata cache and fetcher on aclose."""
    verifier = client_with_discovery.resource(
        resource="https://api.example.com",
        scopes=["read:data", "write:data"],
    )
    token = token_factory()
    await verifier.verify(token)

    # Discovery should have populated these
    assert client_with_discovery.metadata_cache is not None

    # aclose should clean them up
    await client_with_discovery.aclose()

    # Verify cleanup (check that aclose was called on caches)
    # Note: We can't easily verify internal state after aclose, but we verify no errors


async def test_discovery_properties_before_initialization() -> None:
    """Should have configured FetchSettings values."""
    settings = FetchSettings()
    assert settings.ssrf_protection is True
    assert settings.allow_http is False
    assert settings.allow_localhost is False
    assert settings.allow_private_networks is False


@respx.mock
async def test_verification_traffic_follows_a_rotated_jwks_uri(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """Verification alone must re-read AS metadata and follow a rotated jwks_uri.

    A resource server that only verifies tokens never calls an AS endpoint, so
    ``verify()`` is the only thing that can keep metadata warm. Nothing here
    forces a refresh: the test brings the refresh interval forward and then
    sends ordinary verification traffic carrying a token signed by a key
    published *only* at the new URI. Unless the SDK re-read metadata and
    resolved the key set against it on that call, the key is unreachable and
    the verification fails.
    """
    old_jwks_uri = "https://auth.example.com/jwks-v1.json"
    new_jwks_uri = "https://auth.example.com/jwks-v2.json"

    old_key = signing_key_factory("key-v1")
    new_key = signing_key_factory("key-v2")

    metadata_calls = 0

    def metadata_response(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        metadata_calls += 1
        # The AS rotates: every read after the first advertises the new URI.
        uri = old_jwks_uri if metadata_calls == 1 else new_jwks_uri
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "jwks_uri": uri,
                "token_endpoint": "https://auth.example.com/token",
            },
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    old_route = respx.get(old_jwks_uri).mock(
        return_value=respx.MockResponse(200, json=old_key.jwks)
    )
    new_route = respx.get(new_jwks_uri).mock(
        return_value=respx.MockResponse(200, json=new_key.jwks)
    )

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        # Construction read metadata once and fetched keys from the URI it named.
        assert metadata_calls == 1
        assert new_route.call_count == 0

        claims = await verifier.verify(old_key.sign())
        assert claims.kid == "key-v1"
        # Still inside the refresh interval, so no second read: the hop on the
        # verify path is TTL-gated, not a fetch per verification.
        assert metadata_calls == 1

        expire_metadata_interval(client)
        old_route_calls_at_rotation = old_route.call_count

        # Ordinary verification traffic. The token is signed by a key the old
        # URI never served, so this can only pass off the rotated document.
        claims = await verifier.verify(new_key.sign())
        assert claims.kid == "key-v2"

        assert metadata_calls >= 2
        assert new_route.call_count >= 1
        # The withdrawn URI was not fetched again once the rotation was read.
        assert old_route.call_count == old_route_calls_at_rotation

        # Steady state stays on the new URI rather than drifting back.
        claims = await verifier.verify(new_key.sign(jti="second-call"))
        assert claims.kid == "key-v2"
        assert old_route.call_count == old_route_calls_at_rotation
    finally:
        await client.aclose()


@respx.mock
async def test_verification_refresh_keeps_jwks_cache_when_uri_is_unchanged(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """A metadata re-read that leaves jwks_uri alone must not churn the JWKS cache.

    Same production path as the rotation test — the refresh is driven by the
    elapsed interval and ordinary ``verify()`` calls — but here only
    ``token_endpoint`` moves, so the JWKS cache instance must survive and the
    key set must not be refetched.
    """
    jwks_uri = "https://auth.example.com/jwks.json"
    key = signing_key_factory("stable-key")

    metadata_calls = 0

    def metadata_response(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        metadata_calls += 1
        # jwks_uri is constant; only the token endpoint moves.
        endpoint = (
            "https://auth.example.com/token"
            if metadata_calls == 1
            else "https://auth.example.com/token-v2"
        )
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "jwks_uri": jwks_uri,
                "token_endpoint": endpoint,
            },
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    jwks_route = respx.get(jwks_uri).mock(return_value=respx.MockResponse(200, json=key.jwks))

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        original_jwks_cache = client.jwks_cache
        assert await verifier.verify(key.sign()) is not None

        expire_metadata_interval(client)
        jwks_calls_before_refresh = jwks_route.call_count

        assert await verifier.verify(key.sign(jti="second-call")) is not None

        # The refresh did happen on the verify path...
        assert metadata_calls == 2
        # ...but an unchanged jwks_uri leaves the cache instance and its
        # document exactly where they were.
        assert client.jwks_cache is original_jwks_cache
        assert jwks_route.call_count == jwks_calls_before_refresh
    finally:
        await client.aclose()


@respx.mock
async def test_a_rejected_metadata_document_does_not_repoint_key_retrieval(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """A document that fails validation must not decide where keys come from.

    Putting the metadata read on the verification path makes this reachable on
    every request a verify-only resource server serves, so the rejection has to
    happen before the document is cached. Validating on the way out instead
    leaves a rejected document naming the key set: a token minted by the key it
    advertises then verifies, and the token's own ``iss`` claim does not help,
    because whoever supplied the document also mints the token.
    """
    honest_jwks_uri = "https://auth.example.com/jwks.json"
    rogue_jwks_uri = "https://auth.example.com/jwks-rogue.json"
    honest_key = signing_key_factory("key-honest")
    rogue_key = signing_key_factory("key-rogue")

    serve_rogue = False

    def metadata_response(request: httpx.Request) -> httpx.Response:
        if serve_rogue:
            # RFC 8414 §3.3: the issuer is not the configured one, so this
            # document is not about this authorization server at all.
            return httpx.Response(
                200,
                json={
                    "issuer": "https://elsewhere.example.com",
                    "jwks_uri": rogue_jwks_uri,
                },
            )
        return httpx.Response(
            200,
            json={"issuer": "https://auth.example.com", "jwks_uri": honest_jwks_uri},
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    respx.get(honest_jwks_uri).mock(return_value=respx.MockResponse(200, json=honest_key.jwks))
    rogue_route = respx.get(rogue_jwks_uri).mock(
        return_value=respx.MockResponse(200, json=rogue_key.jwks)
    )

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(honest_key.sign())).kid == "key-honest"

        serve_rogue = True
        expire_metadata_interval(client)

        # Minted by the key the rejected document names, but carrying the real
        # issuer — the shape a client presents once the metadata endpoint is
        # under someone else's control.
        with pytest.raises(InvalidSignatureError):
            await verifier.verify(rogue_key.sign())
        assert rogue_route.call_count == 0

        # And the honest key still verifies: rejecting the document left the
        # last accepted one in place rather than emptying anything.
        assert (await verifier.verify(honest_key.sign(jti="after-rejection"))).kid == "key-honest"
    finally:
        await client.aclose()


@respx.mock
async def test_rotation_to_an_unreachable_uri_keeps_the_working_key_set(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """Reading a rotation must not cost the keys that were already verifying.

    The newly advertised URI is dead. Nothing is swapped in on the strength of
    a document alone, so the key set the cache already holds keeps serving and
    tokens that verified a moment ago still verify.
    """
    old_jwks_uri = "https://auth.example.com/jwks-v1.json"
    dead_jwks_uri = "https://auth.example.com/jwks-v2.json"
    old_key = signing_key_factory("key-v1")

    metadata_calls = 0

    def metadata_response(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        metadata_calls += 1
        uri = old_jwks_uri if metadata_calls == 1 else dead_jwks_uri
        return httpx.Response(
            200,
            json={"issuer": "https://auth.example.com", "jwks_uri": uri},
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    respx.get(old_jwks_uri).mock(return_value=respx.MockResponse(200, json=old_key.jwks))
    respx.get(dead_jwks_uri).mock(return_value=respx.MockResponse(503))

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(old_key.sign())).kid == "key-v1"

        expire_metadata_interval(client)

        assert (await verifier.verify(old_key.sign(jti="after-rotation"))).kid == "key-v1"
        assert metadata_calls >= 2

        # Even a forced refetch, which has only the dead URI to go to, leaves
        # the cached key set intact rather than emptying it.
        jwks_cache = client.jwks_cache
        assert jwks_cache is not None
        assert await jwks_cache.contains_kid("key-v1", force_refresh=True) is True
    finally:
        await client.aclose()


@respx.mock
async def test_concurrent_verifications_straddling_a_rotation_all_succeed(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """A rotation read by one caller must not break the others in flight.

    Ten verifications are in flight when the rotation becomes visible. One of
    them wins the metadata read and the key-set refetch that follows it; the
    other nine must be served what that one committed rather than each
    repeating the fetch behind it. None of their tokens has been withdrawn, so
    all ten must verify.

    The rotated location publishes the retired key alongside the new one,
    because that is what an authorization server moving its ``jwks_uri`` has to
    do: the new document is the only one clients will discover from now on, so
    a key still signing live tokens has to be in it. An AS that drops such a
    key from the new document has withdrawn it, and no verifier can be expected
    to keep honouring a key set the AS has stopped publishing —
    ``test_a_key_only_at_the_withdrawn_location_stops_verifying`` pins that
    direction.
    """
    old_jwks_uri = "https://auth.example.com/jwks-v1.json"
    new_jwks_uri = "https://auth.example.com/jwks-v2.json"
    old_key = signing_key_factory("key-v1")
    new_key = signing_key_factory("key-v2")

    metadata_calls = 0

    def metadata_response(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        metadata_calls += 1
        uri = old_jwks_uri if metadata_calls == 1 else new_jwks_uri
        return httpx.Response(
            200,
            json={"issuer": "https://auth.example.com", "jwks_uri": uri},
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    old_route = respx.get(old_jwks_uri).mock(
        return_value=respx.MockResponse(200, json=old_key.jwks)
    )
    new_route = respx.get(new_jwks_uri).mock(
        return_value=respx.MockResponse(
            200, json={"keys": [old_key.jwks["keys"][0], new_key.jwks["keys"][0]]}
        )
    )

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(old_key.sign())).kid == "key-v1"

        expire_metadata_interval(client)
        old_route_calls_at_rotation = old_route.call_count

        # Ten in-flight verifications of tokens the AS has not withdrawn. One
        # of them observes the rotation; none of them may be broken by it.
        results = await asyncio.gather(
            *(verifier.verify(old_key.sign(jti=f"burst-{n}")) for n in range(10))
        )
        assert [claims.kid for claims in results] == ["key-v1"] * 10
        assert metadata_calls >= 2
        # The rotation was followed, and the refetch it triggered was paid for
        # once by the burst rather than ten times. Asserted, not assumed:
        # without the in-lock re-check every one of the ten would refetch.
        assert new_route.call_count == 1
        # And the withdrawn location was not touched again once the rebind
        # happened.
        assert old_route.call_count == old_route_calls_at_rotation
    finally:
        await client.aclose()


@respx.mock
async def test_a_key_only_at_the_withdrawn_location_stops_verifying(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """The cost of following a rotation, stated rather than left to be found.

    Once the rotation is observed, the key set is the rotated document's and
    only its. A key the AS published at the old location and left out of the
    new one no longer verifies anything — the AS stopped publishing it, which
    is what withdrawing a key is, and continuing to honour it would mean
    trusting a document the AS has replaced. Rotating ``jwks_uri`` is therefore
    not a way to move keys gradually: whatever is still signing live tokens has
    to appear at the new location.
    """
    old_jwks_uri = "https://auth.example.com/jwks-v1.json"
    new_jwks_uri = "https://auth.example.com/jwks-v2.json"
    retired_key = signing_key_factory("retired-key")
    new_key = signing_key_factory("new-key")

    rotated = False

    def metadata_response(request: httpx.Request) -> httpx.Response:
        uri = new_jwks_uri if rotated else old_jwks_uri
        return httpx.Response(
            200,
            json={"issuer": "https://auth.example.com", "jwks_uri": uri},
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    # Still reachable, still serving the retired key: the point is that it is
    # no longer consulted, not that it became unreachable.
    respx.get(old_jwks_uri).mock(return_value=respx.MockResponse(200, json=retired_key.jwks))
    respx.get(new_jwks_uri).mock(return_value=respx.MockResponse(200, json=new_key.jwks))

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(retired_key.sign())).kid == "retired-key"

        rotated = True
        expire_metadata_interval(client)

        # The new location's key works.
        assert (await verifier.verify(new_key.sign())).kid == "new-key"
        # The one left behind at the withdrawn location does not.
        with pytest.raises(InvalidSignatureError):
            await verifier.verify(retired_key.sign(jti="after-rotation"))
    finally:
        await client.aclose()


@respx.mock
async def test_a_kid_miss_re_reads_metadata_before_forcing_the_key_set_refresh(
    signing_key_factory: Callable[[str], SigningKey],
) -> None:
    """A kid the cache cannot satisfy makes the cached document suspect too.

    The refresh interval is left at its default and never elapses here, so the
    rotation can only be followed because the miss re-read the document. Were
    the location resolved from the cached document alone, the forced refetch
    would go straight back to the withdrawn URI and the token would be rejected
    until the next interval boundary.
    """
    old_jwks_uri = "https://auth.example.com/jwks-v1.json"
    new_jwks_uri = "https://auth.example.com/jwks-v2.json"
    old_key = signing_key_factory("key-v1")
    new_key = signing_key_factory("key-v2")

    rotated = False
    metadata_calls = 0

    def metadata_response(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        metadata_calls += 1
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "jwks_uri": new_jwks_uri if rotated else old_jwks_uri,
            },
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    respx.get(old_jwks_uri).mock(return_value=respx.MockResponse(200, json=old_key.jwks))
    new_route = respx.get(new_jwks_uri).mock(
        return_value=respx.MockResponse(200, json=new_key.jwks)
    )

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(old_key.sign())).kid == "key-v1"
        metadata_calls_before_rotation = metadata_calls

        rotated = True
        # No interval is brought forward: the only thing that can reveal the
        # rotation is the token itself, whose kid the cached key set lacks.
        assert (await verifier.verify(new_key.sign())).kid == "key-v2"
        assert metadata_calls > metadata_calls_before_rotation
        assert new_route.call_count >= 1
    finally:
        await client.aclose()


@respx.mock
async def test_a_failed_metadata_refresh_does_not_fail_verification(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """The metadata hop must not turn an AS outage into a verification outage.

    Token-level issuer identity is checked against the configured issuer, not
    against the document, so a key set that can still satisfy the token is
    enough. The refresh error is logged and verification continues.
    """
    jwks_uri = "https://auth.example.com/jwks.json"
    key = signing_key_factory("stable-key")

    metadata_broken = False

    def metadata_response(request: httpx.Request) -> httpx.Response:
        if metadata_broken:
            return httpx.Response(503)
        return httpx.Response(
            200,
            json={"issuer": "https://auth.example.com", "jwks_uri": jwks_uri},
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    respx.get(jwks_uri).mock(return_value=respx.MockResponse(200, json=key.jwks))

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(key.sign())).kid == "stable-key"

        metadata_broken = True
        expire_metadata_interval(client)

        assert (await verifier.verify(key.sign(jti="during-outage"))).kid == "stable-key"
    finally:
        await client.aclose()


@respx.mock
async def test_a_rejected_metadata_refresh_displaces_neither_the_document_nor_the_key_source(
    signing_key_factory: Callable[[str], SigningKey],
    expire_metadata_interval: Callable[[AuthplaneClient], None],
) -> None:
    """A metadata document that fails validation must decide nothing.

    RFC 8414 §3.3 issuer identity is the sharpest case: a refresh that answers
    with another issuer's document, pointing ``jwks_uri`` at a key set that
    issuer controls. Checking the document on the way *out* of the cache rather
    than on the way in would let it be committed first and steer key retrieval
    while it sat there — and a token signed by the substituted key set would
    then verify against the configured issuer, which is forgery, not a stale
    read. Rejecting before the commit leaves both the cached document and the
    key source where they were.
    """
    genuine_key = signing_key_factory("genuine-key")
    attacker_key = signing_key_factory("attacker-key")

    hijacked = False

    def metadata_response(request: httpx.Request) -> httpx.Response:
        if hijacked:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://evil.example.com",
                    "jwks_uri": "https://evil.example.com/jwks.json",
                },
            )
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/jwks.json",
            },
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )
    genuine_route = respx.get("https://auth.example.com/jwks.json").mock(
        return_value=respx.MockResponse(200, json=genuine_key.jwks)
    )
    attacker_route = respx.get("https://evil.example.com/jwks.json").mock(
        return_value=respx.MockResponse(200, json=attacker_key.jwks)
    )

    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])

    try:
        assert (await verifier.verify(genuine_key.sign())).kid == "genuine-key"

        hijacked = True
        expire_metadata_interval(client)

        # The key source is untouched, so the genuine key still verifies.
        assert (await verifier.verify(genuine_key.sign(jti="after-rejection"))).kid == "genuine-key"
        assert not attacker_route.called

        # And a token signed by the substituted key set does not verify. The
        # unknown kid drives a forced re-read of both documents, which is the
        # path that would reach that key set had the rejected document been
        # committed.
        with pytest.raises(InvalidSignatureError):
            await verifier.verify(attacker_key.sign())
        assert not attacker_route.called

        # The document still cached is the last one that passed validation.
        metadata_cache = client.metadata_cache
        assert metadata_cache is not None
        assert await metadata_cache.get_jwks_uri() == "https://auth.example.com/jwks.json"
        assert genuine_route.called
    finally:
        await client.aclose()
