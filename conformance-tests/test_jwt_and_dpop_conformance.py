"""RFC 9068, RFC 8725, RFC 9449, and RFC 9728 conformance tests."""

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, cast
from unittest.mock import patch

import httpx
import pytest
import respx
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from authplane import (
    AuthplaneClient,
    AuthplaneError,
    DPoPBindingMismatchError,
    DPoPKeyMaterial,
    DPoPNotSupportedError,
    DPoPProofMissingError,
    DPoPProvider,
    DPoPReplayDetectedError,
    FetchSettings,
    InboundDPoPOptions,
    InMemoryDPoPReplayStore,
    InsufficientScopeError,
    InvalidClaimsError,
    InvalidDPoPProofError,
    InvalidSignatureError,
    TokenExpiredError,
    www_authenticate,
)
from authplane.dpop_verification import verify_dpop_proof
from authplane.internal.document_cache import JWKSCache
from authplane.internal.fetch_result import FetchResult
from authplane.internal.urls import build_prm_url
from authplane.net.http import form_post
from authplane.net.ssrf import HttpResponse
from authplane.oauth.prm import build_prm

_NO_SSRF = FetchSettings(ssrf_protection=False)


def _stub_ssrf_post(
    responses: list[HttpResponse],
    *,
    capture_headers: list[dict[str, str] | None] | None = None,
) -> Any:
    """Build an async stub for ``authplane.net.http.ssrf_safe_post`` that
    returns ``responses`` in order.  ``capture_headers``, when provided,
    is appended to with each call's ``extra_headers`` so the test can
    assert on what the SDK sent.

    Replaces three near-identical 9-parameter stubs that were inlined into
    the DPoP-nonce conformance tests.
    """
    index = {"i": 0}

    async def fake_post(
        url: str,
        *,
        form_data: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        allow_http: bool = False,
        allow_localhost: bool = False,
        allow_private_networks: bool = False,
        max_size: int = 65536,
        timeout: float = 10.0,
    ) -> HttpResponse:
        del url, form_data, json_data
        del allow_http, allow_localhost, allow_private_networks, max_size, timeout
        if capture_headers is not None:
            capture_headers.append(extra_headers)
        i = index["i"]
        index["i"] = i + 1
        return responses[i]

    return fake_post


@dataclass
class MemoryReplayStore:
    seen_jtis: set[str] = field(default_factory=lambda: set[str]())

    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        if jti in self.seen_jtis:
            return False
        self.seen_jtis.add(jti)
        return True


@dataclass
class SimpleDPoPRequest:
    """Test helper that satisfies DPoPRequestContext."""

    method: str
    url: str
    proof: str | None


def _b64url_json(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _unsigned_jwt(header: dict[str, Any], payload: dict[str, Any]) -> str:
    return f"{_b64url_json(header)}.{_b64url_json(payload)}.sig"


def _decode_jwt_part(part: str) -> dict[str, Any]:
    padding = 4 - (len(part) % 4)
    if padding != 4:
        part += "=" * padding
    return json.loads(base64.urlsafe_b64decode(part))


def _decode_jwt_header(token: str) -> dict[str, Any]:
    return _decode_jwt_part(token.split(".")[0])


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    return _decode_jwt_part(token.split(".")[1])


def _build_signed_dpop_proof(
    private_key: bytes,
    public_jwk: dict[str, Any],
    *,
    header_overrides: dict[str, Any] | None = None,
    claims_overrides: dict[str, Any] | None = None,
) -> str:
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": public_jwk,
    }
    if header_overrides:
        header.update(header_overrides)
    claims = {
        "jti": "proof-jti",
        "htm": "GET",
        "htu": "https://api.example.com/resource",
        "iat": int(time.time()),
        "ath": "ignored",
    }
    if claims_overrides:
        claims.update(claims_overrides)
    token = jwt.encode(header, claims, private_key)  # pyright: ignore[reportUnknownMemberType]
    return token.decode("utf-8")


@pytest.mark.conformance("rfc9068-valid-at-jwt-must-verify")
async def test_rfc9068_valid_at_jwt_must_verify(verifier: Any, token_factory: Any) -> None:
    claims = await verifier.verify(token_factory())
    assert claims.sub == "user123"
    assert claims.issuer == "https://auth.example.com"


@pytest.mark.conformance("rfc9068-typ-must-be-at-jwt")
async def test_rfc9068_typ_must_be_at_jwt(verifier: Any, token_factory: Any) -> None:
    with pytest.raises(InvalidClaimsError, match="at\\+jwt"):
        await verifier.verify(token_factory(typ="JWT"))


@pytest.mark.conformance("rfc9068-issuer-must-match")
async def test_rfc9068_issuer_must_match(verifier: Any, token_factory: Any) -> None:
    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token_factory(iss="https://wrong-issuer.com"))


@pytest.mark.conformance("rfc9068-audience-must-match-resource")
async def test_rfc9068_audience_must_match_resource(verifier: Any, token_factory: Any) -> None:
    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token_factory(aud="https://wrong-audience.com"))


@pytest.mark.conformance("rfc9068-required-claims-must-be-enforced")
async def test_rfc9068_required_claims_must_be_enforced(
    verifier: Any,
    token_factory: Any,
) -> None:
    for missing_claim in ("iss", "exp", "aud", "sub", "client_id", "iat", "jti"):
        with pytest.raises(InvalidClaimsError):
            await verifier.verify(token_factory(exclude_claims=[missing_claim]))


@pytest.mark.conformance("rfc9068-token-header-must-contain-kid")
async def test_rfc9068_token_header_must_contain_kid(
    verifier: Any,
) -> None:
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
    token = _unsigned_jwt({"alg": "ES256", "typ": "at+jwt"}, payload)
    with pytest.raises(InvalidClaimsError, match="kid"):
        await verifier.verify(token)


@pytest.mark.conformance("rfc9068-token-header-must-contain-alg")
async def test_rfc9068_token_header_must_contain_alg(
    verifier: Any,
) -> None:
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
    token = _unsigned_jwt({"typ": "at+jwt", "kid": "test-key-1"}, payload)
    with pytest.raises(InvalidClaimsError, match="alg"):
        await verifier.verify(token)


@pytest.mark.conformance("rfc9068-signature-failure-must-reject-token")
async def test_rfc9068_signature_failure_must_reject_token(verifier: Any) -> None:
    bad_token = (
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6InRlc3Qta2V5LTEifQ."
        "eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsInN1YiI6InVzZXIxMjMiLCJjbGllbnRfaWQiOiJjbGllbnQ0NTYiLCJzY29wZSI6InJlYWQ6ZGF0YSIsImV4cCI6MjUzNDAyMzAwNiwiaWF0IjoxNzQxOTQ1MDA2LCJqdGkiOiJ0b2tlbi1pZCJ9."
        "badsignature"
    )
    with pytest.raises(InvalidSignatureError):
        await verifier.verify(bad_token)


@pytest.mark.conformance("rfc9068-expiration-and-clock-skew-must-be-enforced")
async def test_rfc9068_expiration_and_clock_skew_must_be_enforced(
    verifier: Any,
    token_factory: Any,
) -> None:
    with pytest.raises(AuthplaneError):
        await verifier.verify(token_factory(exp=int(time.time()) - 3600))
    await verifier.verify(token_factory(exp=int(time.time()) - 10))
    with pytest.raises(AuthplaneError):
        await verifier.verify(token_factory(nbf=int(time.time()) + 3600))
    await verifier.verify(token_factory(nbf=int(time.time()) + 10))


@pytest.mark.conformance("rfc9068-iat-future-must-be-rejected-beyond-leeway")
async def test_rfc9068_iat_future_must_be_rejected_beyond_leeway(
    verifier: Any,
    token_factory: Any,
) -> None:
    with pytest.raises(InvalidClaimsError, match="future"):
        await verifier.verify(token_factory(iat=int(time.time()) + 3600))


@pytest.mark.conformance("rfc9068-nbf-must-be-honored-when-present")
async def test_rfc9068_nbf_must_be_honored_when_present(
    verifier: Any,
    token_factory: Any,
) -> None:
    # nbf 5 minutes in the future — well beyond the 30 s clock-skew leeway — must be rejected
    with pytest.raises(InvalidClaimsError, match="nbf"):
        await verifier.verify(token_factory(nbf=int(time.time()) + 300))
    # nbf within clock-skew leeway must be accepted
    await verifier.verify(token_factory(nbf=int(time.time()) + 10))


@pytest.mark.conformance("rfc8725-allowed-jwt-algorithms-must-be-restricted")
async def test_rfc8725_allowed_jwt_algorithms_must_be_restricted(
    verifier: Any,
    token_factory: Any,
) -> None:
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
    token = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        + "."
    )
    with pytest.raises((InvalidClaimsError, InvalidSignatureError)):
        await verifier.verify(token)

    # Reach into the verifier's internal client to assert the SDK rejects
    # HS-family algorithms even when the caller tries to opt back in via
    # the public AuthplaneClient.resource() API.
    client = verifier._client  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(ValueError):
        client.resource(resource="https://api.example.com", allowed_algorithms=["HS256"])


@pytest.mark.conformance("rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss")
async def test_rfc8725_kid_must_resolve_through_jwks_with_single_refresh_on_miss(
    jwks_keypair: dict[str, Any],
    token_factory: Any,
) -> None:
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": "https://auth.example.com",
                    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                },
            )
        )
        calls = 0

        def jwks_response(_: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(200, json={"keys": []})
            return httpx.Response(200, json=jwks_keypair["jwks"])

        respx.get("https://auth.example.com/.well-known/jwks.json").mock(side_effect=jwks_response)

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=_NO_SSRF,
        )
        verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
        try:
            claims = await verifier.verify(token_factory())
            assert claims.sub == "user123"
            assert calls == 2
        finally:
            await client.aclose()

    # ── key_still_missing: reject ──
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": "https://auth.example.com",
                    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                },
            )
        )

        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(200, json={"keys": []})
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=_NO_SSRF,
        )
        verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
        try:
            with pytest.raises(AuthplaneError):
                await verifier.verify(token_factory())
        finally:
            await client.aclose()


@pytest.mark.conformance("rfc8725-jwk-selection-must-honor-use-key-ops-and-alg")
async def test_rfc8725_jwk_selection_must_honor_use_key_ops_and_alg() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "keys": [
                    {"kid": "k1", "kty": "EC", "use": "enc", "alg": "ES256"},
                    {"kid": "k1", "kty": "EC", "key_ops": ["sign"], "alg": "ES256"},
                    {"kid": "k1", "kty": "EC", "use": "sig", "key_ops": ["verify"], "alg": "RS256"},
                ]
            }
        )

    cache = JWKSCache(fetcher)
    key = await cache.get_key_by_kid("k1", algorithm="ES256")
    assert key is None


@pytest.mark.conformance("rfc9449-dpop-provider-must-build-dpop-jwt-header")
async def test_rfc9449_dpop_provider_must_build_dpop_jwt_header(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    headers = provider.build_headers("POST", "https://auth.example.com/oauth/token")
    assert "DPoP" in headers
    # Decode the proof JWT header and verify required fields per RFC 9449
    proof_jwt = headers["DPoP"]
    proof_header = _decode_jwt_header(proof_jwt)
    assert proof_header["typ"] == "dpop+jwt"
    assert proof_header["alg"] == "ES256"
    assert "jwk" in proof_header


@pytest.mark.conformance("rfc9449-generated-dpop-proof-should-include-exp")
async def test_rfc9449_generated_dpop_proof_should_include_exp(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    proof = provider.build_proof("POST", "https://auth.example.com/oauth/token")
    claims = _decode_jwt_payload(proof)
    assert "exp" in claims
    assert int(claims["exp"]) > int(claims["iat"])


@pytest.mark.conformance("rfc9449-dpop-proof-exp-must-be-enforced-when-present")
async def test_rfc9449_dpop_proof_exp_must_be_enforced_when_present(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256"),
        proof_ttl_seconds=30,
    )
    now = 1_700_000_000
    proof = provider.build_proof(
        "GET",
        "https://api.example.com/resource",
        access_token="access-token",
        issued_at=now - 60,
    )

    with (
        patch("authplane.dpop.time.time", return_value=now),
        pytest.raises(InvalidDPoPProofError, match="expired"),
    ):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="access-token",
            expected_jkt=provider.key_material.thumbprint,
            max_age_seconds=300,
            clock_skew_seconds=0,
        )


@pytest.mark.conformance("rfc9449-dpop-proof-header-typ-must-be-dpop-jwt")
async def test_rfc9449_dpop_proof_header_typ_must_be_dpop_jwt(
    jwks_keypair: dict[str, Any],
) -> None:
    key = JsonWebKey.import_key(jwks_keypair["private_key"])  # pyright: ignore[reportArgumentType]
    public_jwk = cast("dict[str, Any]", key.as_dict(is_private=False))  # pyright: ignore[reportUnknownMemberType]
    proof = _build_signed_dpop_proof(
        jwks_keypair["private_key"],
        public_jwk,
        header_overrides={"typ": "JWT"},
    )
    with pytest.raises(InvalidDPoPProofError, match="dpop\\+jwt"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="ignored",
            expected_jkt=DPoPKeyMaterial.from_pem(jwks_keypair["private_key"]).thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-proof-must-carry-public-jwk")
async def test_rfc9449_dpop_proof_must_carry_public_jwk(
    jwks_keypair: dict[str, Any],
) -> None:
    key = JsonWebKey.import_key(jwks_keypair["private_key"])  # pyright: ignore[reportArgumentType]
    public_jwk = cast("dict[str, Any]", key.as_dict(is_private=False))  # pyright: ignore[reportUnknownMemberType]
    proof = _build_signed_dpop_proof(
        jwks_keypair["private_key"],
        public_jwk,
        header_overrides={"jwk": None},
    )
    with pytest.raises(InvalidDPoPProofError, match="missing public `jwk`"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="ignored",
        )


@pytest.mark.conformance("rfc9449-dpop-proof-jwk-must-not-include-private-key-material")
async def test_rfc9449_dpop_proof_jwk_must_not_include_private_key_material(
    jwks_keypair: dict[str, Any],
) -> None:
    private_jwk = cast(
        "dict[str, Any]",
        JsonWebKey.import_key(jwks_keypair["private_key"]).as_dict(is_private=True),  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
    )
    proof = _build_signed_dpop_proof(
        jwks_keypair["private_key"],
        private_jwk,
    )
    with pytest.raises(InvalidDPoPProofError, match="private key material"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="ignored",
        )


@pytest.mark.conformance("rfc9449-dpop-proof-alg-must-be-supported-asymmetric")
async def test_rfc9449_dpop_proof_alg_must_be_supported_asymmetric() -> None:
    header: dict[str, Any] = {"typ": "dpop+jwt", "alg": "HS256", "jwk": {}}
    payload = {
        "jti": "proof-jti",
        "htm": "GET",
        "htu": "https://api.example.com/resource",
        "iat": int(time.time()),
    }
    proof = _unsigned_jwt(header, payload)
    with pytest.raises(InvalidDPoPProofError, match="Unsupported DPoP algorithm"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
        )


@pytest.mark.conformance("rfc9449-dpop-nonce-challenge-must-trigger-single-retry")
async def test_rfc9449_dpop_nonce_challenge_must_trigger_single_retry(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    calls: list[dict[str, str] | None] = []
    fake_post = _stub_ssrf_post(
        [
            HttpResponse(
                body={"error": "use_dpop_nonce"},
                headers={"DPoP-Nonce": "nonce-123"},
                status_code=400,
            ),
            HttpResponse(
                body={"access_token": "ok", "token_type": "Bearer"},
                headers={},
                status_code=200,
            ),
        ],
        capture_headers=calls,
    )

    with patch("authplane.net.http.ssrf_safe_post", side_effect=fake_post):
        result = await form_post(
            "https://auth.example.com/oauth/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
            dpop_provider=provider,
        )
    assert result.status_code == 200
    assert len(calls) == 2
    # Verify the nonce was stored for the endpoint origin
    assert provider.current_nonce("https://auth.example.com/oauth/token") == "nonce-123"


@pytest.mark.conformance("rfc9449-dpop-nonce-on-success-response-should-be-stored")
async def test_rfc9449_dpop_nonce_on_success_response_should_be_stored(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    fake_post = _stub_ssrf_post(
        [
            HttpResponse(
                body={"access_token": "ok", "token_type": "Bearer"},
                headers={"DPoP-Nonce": "nonce-456"},
                status_code=200,
            ),
        ],
    )

    with patch("authplane.net.http.ssrf_safe_post", side_effect=fake_post):
        result = await form_post(
            "https://auth.example.com/oauth/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
            dpop_provider=provider,
        )

    assert result.status_code == 200
    assert provider.current_nonce("https://auth.example.com/oauth/token") == "nonce-456"


@pytest.mark.conformance("rfc9110-rfc9449-dpop-nonce-header-must-be-treated-case-insensitively")
async def test_rfc9110_rfc9449_dpop_nonce_header_must_be_treated_case_insensitively(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    calls: list[dict[str, str] | None] = []
    fake_post = _stub_ssrf_post(
        [
            HttpResponse(
                body={"error": "use_dpop_nonce"},
                # Mixed-case header — the SDK must treat DPoP-Nonce case-insensitively.
                headers={"Dpop-Nonce": "nonce-123"},
                status_code=400,
            ),
            HttpResponse(
                body={"access_token": "ok", "token_type": "Bearer"},
                headers={},
                status_code=200,
            ),
        ],
        capture_headers=calls,
    )

    with patch("authplane.net.http.ssrf_safe_post", side_effect=fake_post):
        result = await form_post(
            "https://auth.example.com/oauth/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
            dpop_provider=provider,
        )

    assert result.status_code == 200
    assert len(calls) == 2
    assert provider.current_nonce("https://auth.example.com/oauth/token") == "nonce-123"


@pytest.mark.conformance("rfc9449-inbound-dpop-proof-must-validate-method-url-and-binding")
async def test_rfc9449_inbound_dpop_proof_must_validate_method_url_and_binding(
    client: Any,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    token = token_factory(cnf={"jkt": provider.key_material.thumbprint})
    proof = provider.build_proof("GET", "https://api.example.com/resource", access_token=token)

    claims = await verifier.verify(
        token,
        dpop_request=SimpleDPoPRequest(
            method="GET",
            url="https://api.example.com/resource",
            proof=proof,
        ),
    )
    assert claims.sub == "user123"
    assert claims.dpop_proof is not None
    assert claims.dpop_proof.key_thumbprint == provider.key_material.thumbprint


@pytest.mark.conformance("rfc9449-dpop-replay-must-be-detected")
async def test_rfc9449_dpop_replay_must_be_detected(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    replay_store = MemoryReplayStore()
    proof = provider.build_proof(
        "GET", "https://api.example.com/resource", access_token="access-token"
    )
    await verify_dpop_proof(
        proof,
        method="GET",
        url="https://api.example.com/resource",
        replay_store=replay_store,
        access_token="access-token",
        expected_jkt=provider.key_material.thumbprint,
    )
    with pytest.raises(DPoPReplayDetectedError):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=replay_store,
            access_token="access-token",
            expected_jkt=provider.key_material.thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-method-mismatch-must-be-rejected")
async def test_rfc9449_dpop_method_mismatch_must_be_rejected(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    replay_store = MemoryReplayStore()
    proof = provider.build_proof(
        "POST", "https://api.example.com/resource", access_token="access-token"
    )
    with pytest.raises(InvalidDPoPProofError, match="method mismatch"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=replay_store,
            access_token="access-token",
            expected_jkt=provider.key_material.thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-url-mismatch-must-be-rejected")
async def test_rfc9449_dpop_url_mismatch_must_be_rejected(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    replay_store = MemoryReplayStore()
    proof = provider.build_proof(
        "GET", "https://api.example.com/other", access_token="access-token"
    )
    with pytest.raises(InvalidDPoPProofError, match="URL mismatch"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource?query=ignored",
            replay_store=replay_store,
            access_token="access-token",
            expected_jkt=provider.key_material.thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-proof-iat-must-not-be-in-the-future-beyond-leeway")
async def test_rfc9449_dpop_proof_iat_must_not_be_in_the_future_beyond_leeway(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    proof = provider.build_proof(
        "GET",
        "https://api.example.com/resource",
        access_token="access-token",
        issued_at=int(time.time()) + 3600,
    )
    with pytest.raises(InvalidDPoPProofError, match="future"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="access-token",
            expected_jkt=provider.key_material.thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-proof-must-not-be-too-old")
async def test_rfc9449_dpop_proof_must_not_be_too_old(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    proof = provider.build_proof(
        "GET",
        "https://api.example.com/resource",
        access_token="access-token",
        issued_at=int(time.time()) - 1000,
    )
    with pytest.raises(InvalidDPoPProofError, match="too old"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="access-token",
            expected_jkt=provider.key_material.thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-proof-required-when-validating-dpop-bound-token")
async def test_rfc9449_dpop_proof_required_when_validating_dpop_bound_token(
    client: Any,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    token = token_factory(cnf={"jkt": provider.key_material.thumbprint})
    with pytest.raises(DPoPProofMissingError):
        await verifier.verify(
            token,
            dpop_request=SimpleDPoPRequest(
                method="GET",
                url="https://api.example.com/resource",
                proof=None,
            ),
        )


@pytest.mark.conformance("rfc9449-dpop-binding-mismatch-must-be-rejected")
async def test_rfc9449_dpop_binding_mismatch_must_be_rejected(
    client: Any,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    provider_a = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    other_private_key = ec.generate_private_key(ec.SECP256R1())
    other_private_pem = other_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    other_key = DPoPKeyMaterial.from_pem(other_private_pem, algorithm="ES256")
    provider_b = DPoPProvider(other_key)
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    token = token_factory(cnf={"jkt": provider_a.key_material.thumbprint})
    proof = provider_b.build_proof("GET", "https://api.example.com/resource", access_token=token)
    with pytest.raises(DPoPBindingMismatchError):
        await verifier.verify(
            token,
            dpop_request=SimpleDPoPRequest(
                method="GET",
                url="https://api.example.com/resource",
                proof=proof,
            ),
        )


@pytest.mark.conformance("rfc9449-dpop-ath-mismatch-must-be-rejected")
async def test_rfc9449_dpop_ath_mismatch_must_be_rejected(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    proof = provider.build_proof(
        "GET", "https://api.example.com/resource", access_token="access-token-b"
    )
    with pytest.raises(InvalidDPoPProofError, match="ath"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="access-token-a",
            expected_jkt=provider.key_material.thumbprint,
        )


@pytest.mark.conformance("rfc9449-dpop-bound-token-must-contain-cnf-jkt")
async def test_rfc9449_dpop_bound_token_must_contain_cnf_jkt(
    client: Any,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    token = token_factory(cnf={})
    proof = provider.build_proof("GET", "https://api.example.com/resource", access_token=token)
    with pytest.raises(InvalidClaimsError, match="cnf"):
        await verifier.verify(
            token,
            dpop_request=SimpleDPoPRequest(
                method="GET",
                url="https://api.example.com/resource",
                proof=proof,
            ),
        )


@pytest.mark.conformance(
    "rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided"
)
async def test_rfc9449_dpop_proof_validation_must_not_skip_binding_when_access_token_is_provided(
    jwks_keypair: dict[str, Any],
) -> None:
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    proof = provider.build_proof(
        "GET", "https://api.example.com/resource", access_token="access-token"
    )
    with pytest.raises((InvalidDPoPProofError, DPoPBindingMismatchError)):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
            access_token="access-token",
            expected_jkt="",
        )


@pytest.mark.conformance(
    "rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer"
)
async def test_rfc9449_bearer_token_with_request_context_and_no_proof_must_still_verify_as_bearer(
    client: Any,
    token_factory: Any,
) -> None:
    """If request context is provided but the access token is not DPoP-bound
    and no DPoP proof is present, verification MUST still succeed as bearer
    token validation."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    token = token_factory()  # no cnf claim → bearer token

    claims = await verifier.verify(
        token,
        dpop_request=SimpleDPoPRequest(
            method="GET",
            url="https://api.example.com/resource",
            proof=None,
        ),
    )
    assert claims.sub == "user123"
    assert claims.dpop_proof is None


@pytest.mark.conformance(
    "rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path"
)
async def test_rfc9449_dpop_bound_token_with_request_context_and_no_proof_must_be_rejected_via_main_verify_path(
    client: Any,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    """If request context is provided and the access token is DPoP-bound,
    the main verify path MUST reject the request when the DPoP proof is
    missing."""
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    token = token_factory(cnf={"jkt": provider.key_material.thumbprint})

    with pytest.raises(DPoPProofMissingError):
        await verifier.verify(
            token,
            dpop_request=SimpleDPoPRequest(
                method="GET",
                url="https://api.example.com/resource",
                proof=None,
            ),
        )


@pytest.mark.conformance("rfc9449-dpop-proof-htu-must-be-normalized-before-comparison")
async def test_rfc9449_dpop_proof_htu_must_be_normalized_before_comparison(
    jwks_keypair: dict[str, Any],
) -> None:
    """Both the request URL and the proof htu must be normalized before
    comparison (scheme/host case, default port, strip query/fragment).

    A third-party client may produce a proof with a non-normalized htu
    (e.g. uppercase scheme, explicit default port).  The verifier must
    normalize BOTH sides — not just its own URL — before comparing.
    """
    key = JsonWebKey.import_key(jwks_keypair["private_key"])  # pyright: ignore[reportArgumentType]
    public_jwk = cast("dict[str, Any]", key.as_dict(is_private=False))  # pyright: ignore[reportUnknownMemberType]

    # Build a proof whose htu is NOT pre-normalized (uppercase scheme, explicit port)
    proof = _build_signed_dpop_proof(
        jwks_keypair["private_key"],
        public_jwk,
        claims_overrides={
            "htu": "HTTPS://API.EXAMPLE.COM:443/resource",
            "htm": "GET",
        },
    )

    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )

    verified = await verify_dpop_proof(
        proof,
        method="GET",
        url="https://api.example.com/resource?query=ignored",
        replay_store=MemoryReplayStore(),
        access_token="",
        expected_jkt=provider.key_material.thumbprint,
    )
    assert verified.key_thumbprint == provider.key_material.thumbprint


@pytest.mark.conformance("rfc9449-dpop-proof-htu-must-strip-query-and-fragment")
async def test_rfc9449_dpop_proof_htu_must_strip_query_and_fragment(
    jwks_keypair: dict[str, Any],
) -> None:
    """RFC 9449 §4.3: the client-generated DPoP proof htu claim MUST exclude
    query and fragment parts of the target URI."""
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    proof = provider.build_proof(
        "GET",
        "https://api.example.com/resource?page=1&size=10#section",
    )
    claims = _decode_jwt_payload(proof)
    assert claims["htu"] == "https://api.example.com/resource"


@pytest.mark.conformance(
    "rfc9449-dpop-proof-htm-must-be-case-sensitive",
    note="verify_dpop_proof uppercases the expected method before comparison rather than comparing both sides literally; lowercase htm is correctly rejected.",
)
async def test_rfc9449_dpop_proof_htm_must_be_case_sensitive(
    jwks_keypair: dict[str, Any],
) -> None:
    """DPoP proof htm comparison must be case-sensitive per RFC 9110 §9.1.
    A proof with htm='get' must be rejected when the request method is 'GET'."""
    key = JsonWebKey.import_key(jwks_keypair["private_key"])  # pyright: ignore[reportArgumentType]
    public_jwk = cast("dict[str, Any]", key.as_dict(is_private=False))  # pyright: ignore[reportUnknownMemberType]
    proof = _build_signed_dpop_proof(
        jwks_keypair["private_key"],
        public_jwk,
        claims_overrides={
            "htm": "get",  # lowercase — should not match "GET"
            "htu": "https://api.example.com/resource",
        },
    )
    with pytest.raises(InvalidDPoPProofError, match="method mismatch"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=MemoryReplayStore(),
        )


@pytest.mark.conformance("rfc9449-dpop-replay-store-must-evict-expired-entries")
async def test_rfc9449_dpop_replay_store_must_evict_expired_entries() -> None:
    """The replay store should evict expired entries so memory does not grow
    unbounded under sustained traffic."""
    store = InMemoryDPoPReplayStore()
    # Store an entry that has already expired
    await store.check_and_store("proof-1", expires_at=0)
    # Store a live entry
    await store.check_and_store("proof-2", expires_at=int(time.time()) + 3600)
    # After eviction, proof-1 should no longer occupy storage
    assert await store.check_and_store("proof-1", expires_at=int(time.time()) + 3600)


@pytest.mark.conformance(
    "rfc9449-dpop-inbound-nonce-must-be-validated-when-required",
    note="Not implemented: the SDK has no nonce generation, DPoP-Nonce challenge emission, or challenge-retry lifecycle for resource servers.",
)
async def test_rfc9449_dpop_inbound_nonce_must_be_validated_when_required(
    jwks_keypair: dict[str, Any],
) -> None:
    """Full resource-server nonce challenge-retry flow:
    1. Client sends proof without nonce.
    2. Resource server responds 401 + DPoP-Nonce: <fresh-nonce>.
    3. Client retries with the issued nonce in the proof.
    4. Resource server verifies the nonce matches and accepts.

    The SDK must own the nonce lifecycle: generation, DPoP-Nonce header
    emission on rejection, and validation on retry. None of this is
    currently implemented."""
    pytest.xfail(
        "Not implemented: SDK lacks nonce generation, DPoP-Nonce challenge "
        "emission, and the challenge-retry lifecycle for resource servers."
    )


@pytest.mark.conformance("rfc9728-well-known-path-must-derive-from-resource-uri")
async def test_rfc9728_well_known_path_must_derive_from_resource_uri() -> None:
    # RFC 9728 §3: /.well-known/oauth-protected-resource is inserted between
    # the host and the path, not appended to the end of the resource URI.
    assert (
        build_prm_url("https://api.example.com")
        == "https://api.example.com/.well-known/oauth-protected-resource"
    )
    assert (
        build_prm_url("https://api.example.com/mcp")
        == "https://api.example.com/.well-known/oauth-protected-resource/mcp"
    )
    assert (
        build_prm_url("https://api.example.com/v2/mcp")
        == "https://api.example.com/.well-known/oauth-protected-resource/v2/mcp"
    )


@pytest.mark.conformance("rfc9728-prm-must-contain-required-fields")
async def test_rfc9728_prm_must_contain_required_fields() -> None:
    prm = build_prm(
        "https://auth.example.com", "https://api.example.com", ["read:data", "write:data"]
    )
    assert {
        "resource",
        "authorization_servers",
        "bearer_methods_supported",
        "scopes_supported",
    }.issubset(prm.keys())


@pytest.mark.conformance("rfc9728-prm-authorization-servers-must-list-the-issuer")
async def test_rfc9728_prm_authorization_servers_must_list_the_issuer() -> None:
    prm = build_prm(
        "https://auth.example.com", "https://api.example.com", ["read:data", "write:data"]
    )
    assert prm["authorization_servers"] == ["https://auth.example.com"]


@pytest.mark.conformance("rfc9728-prm-supported-bearer-methods-should-be-stable")
async def test_rfc9728_prm_supported_bearer_methods_should_be_stable() -> None:
    prm = build_prm(
        "https://auth.example.com", "https://api.example.com", ["read:data", "write:data"]
    )
    assert prm["bearer_methods_supported"] == ["header"]


# ---------------------------------------------------------------------------
# Authplane first-class claim fields
# ---------------------------------------------------------------------------


@pytest.mark.conformance("authplane-agent-id-must-be-exposed-as-first-class-field")
async def test_authplane_agent_id_must_be_exposed_as_first_class_field(
    verifier: Any,
    token_factory: Any,
) -> None:
    """VerifiedClaims.agent_id surfaces the agent_id claim as a str when present,
    and defaults to '' when absent."""
    claims_present = await verifier.verify(token_factory(agent_id="agent-007"))
    assert claims_present.agent_id == "agent-007"

    claims_absent = await verifier.verify(token_factory())
    assert claims_absent.agent_id == ""


@pytest.mark.conformance("authplane-agent-chain-must-be-exposed-as-first-class-field")
async def test_authplane_agent_chain_must_be_exposed_as_first_class_field(
    verifier: Any,
    token_factory: Any,
) -> None:
    """VerifiedClaims.agent_chain surfaces the agent_chain claim as a tuple when
    present, and defaults to () when absent."""
    claims_present = await verifier.verify(
        token_factory(agent_chain=["agent-1", "agent-2", "agent-3"])
    )
    assert claims_present.agent_chain == ("agent-1", "agent-2", "agent-3")

    claims_absent = await verifier.verify(token_factory())
    assert claims_absent.agent_chain == ()


@pytest.mark.conformance("authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims")
async def test_authplane_nbf_must_be_exposed_as_typed_field_on_verified_claims(
    verifier: Any,
    token_factory: Any,
) -> None:
    """VerifiedClaims.not_before surfaces the nbf claim as an int when present,
    and defaults to 0 when absent."""
    now = int(time.time())
    claims_present = await verifier.verify(token_factory(nbf=now))
    assert claims_present.not_before == now

    claims_absent = await verifier.verify(token_factory(exclude_claims=["nbf"]))
    assert claims_absent.not_before == 0


# ---------------------------------------------------------------------------
# RFC 6750 §3 — WWW-Authenticate error response helper
# ---------------------------------------------------------------------------


@pytest.mark.conformance("rfc6750-error-response-must-map-error-codes")
async def test_rfc6750_error_response_must_map_error_codes() -> None:
    """SDK must provide a www_authenticate() helper that maps errors to
    RFC 6750 §3.1 error codes (invalid_token, insufficient_scope)."""
    # Authentication failures → "invalid_token"
    result = www_authenticate(TokenExpiredError("expired"))
    assert result.startswith("Bearer ")
    assert 'error="invalid_token"' in result

    result = www_authenticate(InvalidSignatureError("bad sig"))
    assert result.startswith("Bearer ")
    assert 'error="invalid_token"' in result

    # Authorization failure → "insufficient_scope"
    result = www_authenticate(InsufficientScopeError("need admin"))
    assert result.startswith("Bearer ")
    assert 'error="insufficient_scope"' in result

    # DPoP errors → DPoP scheme with "invalid_token"
    result = www_authenticate(InvalidDPoPProofError("bad proof"))
    assert result.startswith("DPoP ")
    assert 'error="invalid_token"' in result


@pytest.mark.conformance("rfc6750-error-response-realm-should-be-included")
async def test_rfc6750_error_response_realm_should_be_included() -> None:
    """When realm is provided, the WWW-Authenticate header must include it."""
    result = www_authenticate(TokenExpiredError("expired"), realm="https://api.example.com")
    assert 'realm="https://api.example.com"' in result


# ---------------------------------------------------------------------------
# RFC 9728 §2 — PRM DPoP metadata fields
# ---------------------------------------------------------------------------


@pytest.mark.conformance("rfc9728-prm-dpop-fields-should-be-advertised-when-dpop-is-supported")
async def test_rfc9728_prm_dpop_fields_should_be_advertised() -> None:
    """When dpop_algs is provided, PRM must include DPoP metadata fields."""
    prm = build_prm(
        "https://auth.example.com",
        "https://api.example.com",
        ["read:data"],
        dpop_algs=["ES256", "RS256"],
    )
    assert prm["dpop_signing_alg_values_supported"] == ["ES256", "RS256"]
    assert "dpop_bound_access_tokens_required" in prm


@pytest.mark.conformance("rfc9728-prm-must-advertise-dpop-required-when-resource-requires-dpop")
async def test_rfc9728_prm_must_advertise_dpop_required_when_resource_requires_dpop() -> None:
    """When the resource requires DPoP, PRM must advertise dpop_bound_access_tokens_required=true."""
    prm = build_prm(
        "https://auth.example.com",
        "https://api.example.com",
        ["read:data"],
        dpop_algs=["ES256", "RS256"],
        dpop_required=True,
    )
    assert prm["dpop_bound_access_tokens_required"] is True


@pytest.mark.conformance(
    "rfc9449-verifier-must-reject-bearer-only-token-when-resource-requires-dpop"
)
async def test_rfc9449_verifier_must_reject_bearer_only_token_when_resource_requires_dpop(
    client: Any,
    token_factory: Any,
) -> None:
    """A resource configured with required=True must reject bearer-only tokens at verify time."""
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(required=True),
    )
    bearer_only_token = token_factory()  # no cnf.jkt
    with pytest.raises(DPoPBindingMismatchError, match="DPoP-bound"):
        await verifier.verify(bearer_only_token)


@pytest.mark.conformance(
    "rfc9449-verifier-must-reject-dpop-bound-token-when-resource-does-not-support-dpop"
)
async def test_rfc9449_verifier_must_reject_dpop_bound_token_when_resource_does_not_support_dpop(
    client: AuthplaneClient,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    """A resource without inbound_dpop must reject DPoP-bound tokens regardless of proof presence."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    bound_token = token_factory(cnf={"jkt": provider.key_material.thumbprint})
    proof = provider.build_proof(
        "GET", "https://api.example.com/resource", access_token=bound_token
    )
    with pytest.raises(DPoPNotSupportedError):
        await verifier.verify(
            bound_token,
            dpop_request=SimpleDPoPRequest(
                method="GET",
                url="https://api.example.com/resource",
                proof=proof,
            ),
        )


@pytest.mark.conformance(
    "rfc9449-verifier-must-reject-dpop-proof-when-access-token-is-not-dpop-bound"
)
async def test_rfc9449_verifier_must_reject_dpop_proof_when_access_token_is_not_dpop_bound(
    client: AuthplaneClient,
    token_factory: Any,
    jwks_keypair: dict[str, Any],
) -> None:
    """A bearer-only access token combined with a DPoP proof in the request is malformed."""
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    provider = DPoPProvider(
        DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256")
    )
    bearer_token = token_factory()  # no cnf.jkt
    proof = provider.build_proof(
        "GET", "https://api.example.com/resource", access_token=bearer_token
    )
    with pytest.raises(DPoPBindingMismatchError):
        await verifier.verify(
            bearer_token,
            dpop_request=SimpleDPoPRequest(
                method="GET",
                url="https://api.example.com/resource",
                proof=proof,
            ),
        )
