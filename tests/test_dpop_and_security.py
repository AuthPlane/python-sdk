"""Regression tests for DPoP and newly hardened security behavior."""

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import pytest
import respx

from authplane import (
    AuthplaneClient,
    DPoPBindingMismatchError,
    DPoPKeyMaterial,
    DPoPNotSupportedError,
    DPoPProvider,
    FetchSettings,
    InboundDPoPOptions,
    InMemoryDPoPNonceStore,
)
from authplane.dpop_verification import verify_dpop_proof
from authplane.errors import (
    DPoPReplayDetectedError,
    InvalidDPoPProofError,
    MetadataFetchError,
    MissingMetadataEndpointError,
    ProtocolError,
)
from authplane.internal.document_cache import JWKSCache
from authplane.internal.fetch_result import FetchResult
from authplane.net.http import FormPostResponse, form_post
from authplane.net.ssrf import HttpResponse
from authplane.oauth.client_credentials import client_credentials_grant


def _decode_header(token: str) -> dict[str, Any]:
    header_b64 = token.split(".")[0]
    padding = 4 - (len(header_b64) % 4)
    if padding != 4:
        header_b64 += "=" * padding
    return json.loads(base64.urlsafe_b64decode(header_b64))


@dataclass
class MemoryReplayStore:
    seen_jtis: set[str] = field(default_factory=lambda: set())

    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        if jti in self.seen_jtis:
            return False
        self.seen_jtis.add(jti)
        return True


@pytest.fixture
def dpop_provider(jwks_keypair: dict[str, Any]) -> DPoPProvider:
    return DPoPProvider(DPoPKeyMaterial.from_pem(jwks_keypair["private_key"], algorithm="ES256"))


async def test_dpop_provider_builds_proof_header(dpop_provider: DPoPProvider) -> None:
    headers = dpop_provider.build_headers("POST", "https://auth.example.com/oauth/token")
    assert "DPoP" in headers
    header = _decode_header(headers["DPoP"])
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "jwk" in header


async def test_dpop_provider_builds_exp_claim(dpop_provider: DPoPProvider) -> None:
    proof = dpop_provider.build_proof("POST", "https://auth.example.com/oauth/token")
    payload_b64 = proof.split(".")[1]
    padding = 4 - (len(payload_b64) % 4)
    if padding != 4:
        payload_b64 += "=" * padding
    claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert claims["exp"] > claims["iat"]


@pytest.mark.parametrize("alg", ["none", "HS256", "HS384", "HS512", "RS512"])
def test_inbound_dpop_options_rejects_unsafe_proof_algorithms(alg: str) -> None:
    with pytest.raises(ValueError, match="Unsupported DPoP proof algorithms"):
        InboundDPoPOptions(allowed_proof_algorithms=(alg,))


def test_inbound_dpop_options_rejects_empty_proof_algorithms() -> None:
    with pytest.raises(ValueError, match="must be non-empty"):
        InboundDPoPOptions(allowed_proof_algorithms=())


def test_inbound_dpop_options_accepts_supported_proof_algorithms() -> None:
    opts = InboundDPoPOptions(allowed_proof_algorithms=("ES256", "RS256"))
    assert opts.allowed_proof_algorithms == ("ES256", "RS256")


def test_inbound_dpop_options_normalizes_list_to_tuple() -> None:
    """A list passed in by the caller is normalized to a tuple so a retained
    reference cannot mutate the configuration after construction."""
    algs = ["ES256", "RS256"]
    opts = InboundDPoPOptions(allowed_proof_algorithms=algs)
    assert isinstance(opts.allowed_proof_algorithms, tuple)
    algs.clear()
    assert opts.allowed_proof_algorithms == ("ES256", "RS256")


def test_in_memory_dpop_nonce_store_evicts_oldest_entry() -> None:
    store = InMemoryDPoPNonceStore(max_entries=2)
    store.put("https://one.example.com:443", "nonce-1")
    store.put("https://two.example.com:443", "nonce-2")
    store.put("https://three.example.com:443", "nonce-3")

    assert store.get("https://one.example.com:443") == ""
    assert store.get("https://two.example.com:443") == "nonce-2"
    assert store.get("https://three.example.com:443") == "nonce-3"


async def test_in_memory_replay_store_concurrent_same_jti() -> None:
    """Concurrent check_and_store calls with the same jti must only succeed once."""
    import asyncio

    from authplane.dpop import InMemoryDPoPReplayStore

    store = InMemoryDPoPReplayStore()
    expires_at = int(time.time()) + 300

    results = await asyncio.gather(
        store.check_and_store("same-jti", expires_at),
        store.check_and_store("same-jti", expires_at),
        store.check_and_store("same-jti", expires_at),
    )
    # Exactly one call should succeed (return True)
    assert sum(results) == 1


async def test_form_post_retries_once_with_dpop_nonce(dpop_provider: DPoPProvider) -> None:
    calls: list[dict[str, str] | None] = []

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
        calls.append(extra_headers)
        if len(calls) == 1:
            return HttpResponse(
                body={"error": "use_dpop_nonce"},
                headers={"DPoP-Nonce": "nonce-123"},
                status_code=400,
            )
        return HttpResponse(
            body={"access_token": "ok", "token_type": "Bearer"}, headers={}, status_code=200
        )

    from unittest.mock import patch

    with patch("authplane.net.http.ssrf_safe_post", side_effect=fake_post):
        response = await form_post(
            "https://auth.example.com/oauth/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
            dpop_provider=dpop_provider,
        )

    assert response.status_code == 200
    assert len(calls) == 2
    assert dpop_provider.current_nonce("https://auth.example.com/oauth/token") == "nonce-123"


async def test_form_post_stores_dpop_nonce_from_success_response(
    dpop_provider: DPoPProvider,
) -> None:
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
        del (
            form_data,
            json_data,
            extra_headers,
            allow_http,
            allow_localhost,
            allow_private_networks,
            max_size,
            timeout,
        )
        return HttpResponse(
            body={"access_token": "ok", "token_type": "Bearer"},
            headers={"DPoP-Nonce": "next-nonce"},
            status_code=200,
        )

    from unittest.mock import patch

    with patch("authplane.net.http.ssrf_safe_post", side_effect=fake_post):
        response = await form_post(
            "https://auth.example.com/oauth/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
            dpop_provider=dpop_provider,
        )

    assert response.status_code == 200
    assert dpop_provider.current_nonce("https://auth.example.com/oauth/token") == "next-nonce"


async def test_verify_dpop_proof_success(
    dpop_provider: DPoPProvider,
) -> None:
    replay_store = MemoryReplayStore()
    proof = dpop_provider.build_proof(
        "GET", "https://api.example.com/resource", access_token="access-token"
    )

    verified = await verify_dpop_proof(
        proof,
        method="GET",
        url="https://api.example.com/resource?query=ignored",
        replay_store=replay_store,
        access_token="access-token",
        expected_jkt=dpop_provider.key_material.thumbprint,
    )

    assert verified.htu == "https://api.example.com/resource"
    assert verified.key_thumbprint == dpop_provider.key_material.thumbprint


async def test_verify_dpop_proof_replay_detected(dpop_provider: DPoPProvider) -> None:
    replay_store = MemoryReplayStore()
    proof = dpop_provider.build_proof(
        "GET", "https://api.example.com/resource", access_token="access-token"
    )

    await verify_dpop_proof(
        proof,
        method="GET",
        url="https://api.example.com/resource",
        replay_store=replay_store,
        access_token="access-token",
        expected_jkt=dpop_provider.key_material.thumbprint,
    )

    with pytest.raises(DPoPReplayDetectedError):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=replay_store,
            access_token="access-token",
            expected_jkt=dpop_provider.key_material.thumbprint,
        )


async def test_verify_dpop_proof_method_mismatch(dpop_provider: DPoPProvider) -> None:
    replay_store = MemoryReplayStore()
    proof = dpop_provider.build_proof(
        "POST", "https://api.example.com/resource", access_token="access-token"
    )

    with pytest.raises(InvalidDPoPProofError, match="method mismatch"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=replay_store,
            access_token="access-token",
            expected_jkt=dpop_provider.key_material.thumbprint,
        )


async def test_verify_dpop_proof_rejects_expired_exp_claim(dpop_provider: DPoPProvider) -> None:
    replay_store = MemoryReplayStore()
    now = 1_700_000_000
    short_ttl_provider = DPoPProvider(
        dpop_provider.key_material,
        proof_ttl_seconds=30,
    )
    proof = short_ttl_provider.build_proof(
        "GET",
        "https://api.example.com/resource",
        access_token="access-token",
        issued_at=now - 60,
    )

    from unittest.mock import patch

    with (
        patch("authplane.dpop.time.time", return_value=now),
        pytest.raises(InvalidDPoPProofError, match="expired"),
    ):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=replay_store,
            access_token="access-token",
            expected_jkt=short_ttl_provider.key_material.thumbprint,
            max_age_seconds=300,
            clock_skew_seconds=0,
        )


async def test_verify_dpop_proof_requires_binding_when_access_token_present(
    dpop_provider: DPoPProvider,
) -> None:
    replay_store = MemoryReplayStore()
    proof = dpop_provider.build_proof(
        "GET", "https://api.example.com/resource", access_token="access-token"
    )

    with pytest.raises(DPoPBindingMismatchError, match="expected_jkt"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example.com/resource",
            replay_store=replay_store,
            access_token="access-token",
        )


async def test_client_create_rejects_metadata_issuer_mismatch(jwks_keypair: dict[str, Any]) -> None:
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": "https://evil.example.com",
                    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                },
            )
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )

        with pytest.raises(MetadataFetchError, match="issuer mismatch"):
            await AuthplaneClient.create(
                issuer="https://auth.example.com",
                fetch_settings=FetchSettings(ssrf_protection=False),
            )


async def test_client_introspect_requires_discovered_endpoint(jwks_keypair: dict[str, Any]) -> None:
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
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        try:
            with pytest.raises(MissingMetadataEndpointError, match="introspection_endpoint"):
                await client.introspect("token")
        finally:
            await client.aclose()


async def test_client_credentials_rejects_malformed_success_response() -> None:
    from unittest.mock import AsyncMock, patch

    with (
        patch(
            "authplane.oauth.client_credentials.form_post",
            new_callable=AsyncMock,
            return_value=FormPostResponse(
                status_code=200, body={"token_type": "Bearer"}, headers={}
            ),
        ),
        pytest.raises(ProtocolError, match="access_token"),
    ):
        await client_credentials_grant(
            "https://auth.example.com/oauth/token",
            {},
            FetchSettings(ssrf_protection=False),
        )


async def test_verifier_verify_dpop_success(
    client: AuthplaneClient,
    token_factory: Any,
    dpop_provider: DPoPProvider,
) -> None:
    replay_store = MemoryReplayStore()
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(replay_store=replay_store),
    )
    token = token_factory(cnf={"jkt": dpop_provider.key_material.thumbprint})
    proof_str = dpop_provider.build_proof(
        "GET", "https://api.example.com/resource", access_token=token
    )

    @dataclass
    class Ctx:
        method: str
        url: str
        proof: str | None

    claims = await verifier.verify(
        token,
        dpop_request=Ctx(
            method="GET",
            url="https://api.example.com/resource",
            proof=proof_str,
        ),
    )

    assert claims.sub == "user123"
    assert claims.dpop_proof is not None
    assert claims.dpop_proof.key_thumbprint == dpop_provider.key_material.thumbprint


async def test_jwks_lookup_filters_non_signature_keys() -> None:
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


# ---------------------------------------------------------------------------
# DPoP enforcement modes — Mode 1 (required), Mode 2 (supported), Mode 3 (not configured)
# ---------------------------------------------------------------------------


@dataclass
class _DPoPCtx:
    method: str
    url: str
    proof: str | None


async def test_mode2_supported_accepts_bearer_only_without_proof(
    client: AuthplaneClient,
    token_factory: Any,
) -> None:
    """Mode 2 (supported, not required): plain bearer token without proof is accepted."""
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    bearer = token_factory()
    claims = await verifier.verify(bearer)
    assert claims.dpop_proof is None


async def test_mode2_supported_rejects_bearer_only_with_proof(
    client: AuthplaneClient,
    token_factory: Any,
    dpop_provider: DPoPProvider,
) -> None:
    """Mode 2: a bearer-only token presented with a DPoP proof is a malformed request."""
    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    bearer = token_factory()
    proof = dpop_provider.build_proof(
        "GET", "https://api.example.com/resource", access_token=bearer
    )
    with pytest.raises(DPoPBindingMismatchError):
        await verifier.verify(
            bearer,
            dpop_request=_DPoPCtx(
                method="GET", url="https://api.example.com/resource", proof=proof
            ),
        )


async def test_mode3_not_configured_accepts_bearer_only_without_proof(
    client: AuthplaneClient,
    token_factory: Any,
) -> None:
    """Mode 3 (not configured): plain bearer token is accepted (DPoP off, bearer flow only)."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    bearer = token_factory()
    claims = await verifier.verify(bearer)
    assert claims.dpop_proof is None


async def test_mode3_not_configured_rejects_bound_token_without_request_context(
    client: AuthplaneClient,
    token_factory: Any,
    dpop_provider: DPoPProvider,
) -> None:
    """Mode 3: a DPoP-bound token (cnf.jkt) at a non-supporting resource is rejected upfront."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    bound = token_factory(cnf={"jkt": dpop_provider.key_material.thumbprint})
    with pytest.raises(DPoPNotSupportedError):
        await verifier.verify(bound)


async def test_mode3_not_configured_rejects_bound_token_even_with_valid_proof(
    client: AuthplaneClient,
    token_factory: Any,
    dpop_provider: DPoPProvider,
) -> None:
    """Mode 3: a bound token + a valid proof must still be rejected — resource has not opted in."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    bound = token_factory(cnf={"jkt": dpop_provider.key_material.thumbprint})
    proof = dpop_provider.build_proof("GET", "https://api.example.com/resource", access_token=bound)
    with pytest.raises(DPoPNotSupportedError):
        await verifier.verify(
            bound,
            dpop_request=_DPoPCtx(
                method="GET", url="https://api.example.com/resource", proof=proof
            ),
        )


async def test_mode3_not_configured_rejects_bearer_with_proof(
    client: AuthplaneClient,
    token_factory: Any,
    dpop_provider: DPoPProvider,
) -> None:
    """Mode 3: a bearer-only token + a proof header is rejected — the resource doesn't support DPoP."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    bearer = token_factory()
    proof = dpop_provider.build_proof(
        "GET", "https://api.example.com/resource", access_token=bearer
    )
    with pytest.raises(DPoPNotSupportedError):
        await verifier.verify(
            bearer,
            dpop_request=_DPoPCtx(
                method="GET", url="https://api.example.com/resource", proof=proof
            ),
        )


async def test_mode3_not_configured_does_not_allocate_replay_store(
    client: AuthplaneClient,
) -> None:
    """Mode 3: when no inbound_dpop is configured, no in-memory replay store should be allocated."""
    verifier = client.resource(resource="https://api.example.com", scopes=["read:data"])
    # Internal attribute: confirms the load-bearing optimisation that nothing is
    # allocated when DPoP is not in use.
    assert verifier._dpop_replay_store is None  # type: ignore[reportPrivateUsage]
