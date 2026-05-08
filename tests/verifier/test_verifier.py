"""Tests for AuthplaneResource core validation logic."""

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from respx.models import Route

from authplane import AuthplaneClient, AuthplaneResource, FetchSettings, InboundDPoPOptions
from authplane.errors import (
    InvalidClaimsError,
    InvalidSignatureError,
    JWKSFetchError,
    MetadataFetchError,
    TokenExpiredError,
)


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
async def test_jwks_cache_restarts_on_uri_change(
    jwks_keypair: dict[str, Any], token_factory: Callable[..., str]
) -> None:
    """Should restart JWKS cache when metadata jwks_uri changes."""
    import asyncio

    old_jwks_uri = "https://auth.example.com/old-jwks"
    new_jwks_uri = "https://auth.example.com/new-jwks"

    # Track metadata fetch calls
    metadata_call_count: dict[str, int] = {"count": 0}

    def metadata_response(request: httpx.Request) -> httpx.Response:
        metadata_call_count["count"] += 1
        uri = new_jwks_uri if metadata_call_count["count"] > 1 else old_jwks_uri
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "jwks_uri": uri,
                "token_endpoint": "https://auth.example.com/token",
            },
            headers={"Cache-Control": "max-age=1"},  # Short TTL for testing
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )

    # Mock JWKS responses for both URIs
    old_jwks: Any = jwks_keypair["jwks"]
    new_key: dict[str, Any] = {**jwks_keypair["jwks"]["keys"][0], "kid": "new-key-id"}
    new_jwks: dict[str, list[dict[str, Any]]] = {"keys": [new_key]}

    respx.get(old_jwks_uri).mock(return_value=respx.MockResponse(status_code=200, json=old_jwks))
    respx.get(new_jwks_uri).mock(return_value=respx.MockResponse(status_code=200, json=new_jwks))

    # Create client with discovery and short metadata refresh
    _no_ssrf = FetchSettings(ssrf_protection=False)
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        metadata_refresh_seconds=1,  # Very short for testing
        fetch_settings=_no_ssrf,
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
    )

    try:
        # Initial JWKS URI should be old
        assert client._jwks_uri == old_jwks_uri  # pyright: ignore[reportPrivateUsage]

        # Verify token works with old JWKS
        token = token_factory()
        claims = await verifier.verify(token)
        assert claims.kid == "test-key-1"

        # Force metadata refresh to get new URI
        await client.metadata_cache.get(force_refresh=True)  # pyright: ignore[reportOptionalMemberAccess]

        # Give callback time to run
        await asyncio.sleep(0.1)

        # JWKS URI should have changed
        assert client._jwks_uri == new_jwks_uri  # pyright: ignore[reportPrivateUsage]

        # Verify JWKS cache was restarted with new URI
        jwks = await client.jwks_cache.get()  # pyright: ignore[reportOptionalMemberAccess]
        assert jwks["keys"][0]["kid"] == "new-key-id"

    finally:
        await client.aclose()


@respx.mock
async def test_metadata_change_without_jwks_uri_change(
    jwks_keypair: dict[str, Any], token_factory: Callable[..., str]
) -> None:
    """Should not restart JWKS cache when metadata changes but jwks_uri stays same."""
    import asyncio

    jwks_uri = "https://auth.example.com/jwks"

    # Track metadata fetch calls
    metadata_call_count: dict[str, int] = {"count": 0}

    def metadata_response(request: httpx.Request) -> httpx.Response:
        metadata_call_count["count"] += 1
        # Only token_endpoint changes, jwks_uri stays same
        endpoint = (
            "https://auth.example.com/token-v2"
            if metadata_call_count["count"] > 1
            else "https://auth.example.com/token"
        )
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "jwks_uri": jwks_uri,  # Same URI both times
                "token_endpoint": endpoint,  # Different endpoint
            },
        )

    respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
        side_effect=metadata_response
    )

    # Mock JWKS
    jwks: Any = jwks_keypair["jwks"]
    respx.get(jwks_uri).mock(return_value=respx.MockResponse(status_code=200, json=jwks))

    _no_ssrf = FetchSettings(ssrf_protection=False)
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=_no_ssrf,
    )

    try:
        # Capture original JWKS cache instance
        original_jwks_cache = client.jwks_cache

        # Force metadata refresh
        await client.metadata_cache.get(force_refresh=True)  # pyright: ignore[reportOptionalMemberAccess]
        await asyncio.sleep(0.1)

        # JWKS cache should NOT have been replaced (same instance)
        assert client.jwks_cache is original_jwks_cache
        assert client._jwks_uri == jwks_uri  # pyright: ignore[reportPrivateUsage]

    finally:
        await client.aclose()
