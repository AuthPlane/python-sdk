"""Coverage-oriented tests for protocol parsing, HTTP helpers, and client edges."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from authplane import AuthplaneClient, DPoPKeyMaterial, DPoPProvider, FetchSettings
from authplane.dpop import (
    _decode_jwt_header,  # pyright: ignore[reportPrivateUsage]
    jwk_thumbprint,
    normalize_dpop_htu,
)
from authplane.errors import DPoPError, InvalidDPoPProofError, MetadataFetchError, ProtocolError
from authplane.net.http import FormPostResponse, form_post
from authplane.net.ssrf import HttpResponse, SSRFError
from authplane.oauth.parsing import parse_token_response


def test_parse_token_response_rejects_unsupported_token_type() -> None:
    with pytest.raises(ProtocolError, match="unsupported token_type"):
        parse_token_response(
            {"access_token": "tok", "token_type": "N_A"},
            allow_issued_token_type=False,
        )


def test_parse_token_response_accepts_dpop_token_type() -> None:
    result = parse_token_response(
        {"access_token": "tok", "token_type": "DPoP"},
        allow_issued_token_type=False,
    )
    assert result.token_type == "DPoP"


def test_parse_token_response_rejects_negative_expires_in() -> None:
    with pytest.raises(ProtocolError, match="non-negative"):
        parse_token_response(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": -1},
            allow_issued_token_type=False,
        )


def test_parse_token_response_absent_expires_in_is_none() -> None:
    # An AS that omits expires_in must parse to None, not 0, so the cache
    # can later apply default_ttl rather than treat the token as one-shot.
    result = parse_token_response(
        {"access_token": "tok", "token_type": "Bearer"},
        allow_issued_token_type=False,
    )
    assert result.expires_in is None


def test_parse_token_response_explicit_zero_expires_in_preserved() -> None:
    # An AS that issues a deliberately one-shot token (RFC 6749 §5.1 permits
    # expires_in: 0) must parse to 0, not None. Downstream the cache treats
    # 0 as "already expired, refuse to store" — it is *not* an absent value.
    result = parse_token_response(
        {"access_token": "tok", "token_type": "Bearer", "expires_in": 0},
        allow_issued_token_type=False,
    )
    assert result.expires_in == 0


def test_parse_token_response_positive_expires_in_preserved() -> None:
    result = parse_token_response(
        {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
        allow_issued_token_type=False,
    )
    assert result.expires_in == 3600


def test_parse_token_response_rejects_invalid_issued_token_type() -> None:
    with pytest.raises(ProtocolError, match="unsupported issued_token_type"):
        parse_token_response(
            {
                "access_token": "tok",
                "token_type": "Bearer",
                "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
            },
            allow_issued_token_type=True,
        )


def test_parse_token_response_extracts_cnf_jkt() -> None:
    result = parse_token_response(
        {
            "access_token": "tok",
            "token_type": "Bearer",
            "cnf": {"jkt": "thumb"},
        },
        allow_issued_token_type=False,
    )
    assert result.cnf_jkt == "thumb"


async def test_form_post_ssrf_success_uses_real_status_code() -> None:
    with patch(
        "authplane.net.http.ssrf_safe_post",
        new=AsyncMock(
            return_value=HttpResponse(body={"ok": True}, headers={"x": "y"}, status_code=201)
        ),
    ):
        result = await form_post(
            "https://auth.example.com/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
        )

    assert result == FormPostResponse(status_code=201, body={"ok": True}, headers={"x": "y"})


async def test_form_post_ssrf_passes_through_4xx_body_and_headers() -> None:
    # ssrf_safe_post no longer raises on 4xx — it returns the HttpResponse
    # with the body intact so OAuth callers can map error_description /
    # consent_url / cause fields onto typed errors. form_post must surface
    # the same body and headers (DPoP-Nonce in particular) on 4xx.
    response = HttpResponse(
        body={"error": "invalid_request"},
        headers={"DPoP-Nonce": "abc"},
        status_code=400,
    )

    with patch("authplane.net.http.ssrf_safe_post", new=AsyncMock(return_value=response)):
        result = await form_post(
            "https://auth.example.com/token",
            {"grant_type": "client_credentials"},
            FetchSettings(),
        )

    assert result.status_code == 400
    assert result.body == {"error": "invalid_request"}
    assert result.headers["dpop-nonce"] == "abc"


async def test_form_post_ssrf_preserves_consent_required_body() -> None:
    # Regression test: previously the SSRF streaming path called
    # response.raise_for_status() before reading the body, so the AS's
    # consent_required response (with consent_url) was dropped on the floor
    # and the SDK surfaced a generic AuthError("HTTP 400"). This test pins
    # that the body — including consent_url — reaches form_post's caller.
    response = HttpResponse(
        body={
            "error": "consent_required",
            "error_description": "Authorize access to calculator-mcp-demo",
            "consent_url": "http://localhost:9000/authorize?resource=calculator-mcp-demo",
            "cause": "consent_missing",
        },
        headers={},
        status_code=400,
    )

    with patch("authplane.net.http.ssrf_safe_post", new=AsyncMock(return_value=response)):
        result = await form_post(
            "https://auth.example.com/token",
            {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"},
            FetchSettings(),
        )

    assert result.status_code == 400
    assert result.body["error"] == "consent_required"
    assert (
        result.body["consent_url"] == "http://localhost:9000/authorize?resource=calculator-mcp-demo"
    )
    assert result.body["cause"] == "consent_missing"


async def test_form_post_direct_mode_handles_non_json_body() -> None:
    response = MagicMock()
    response.status_code = 200
    response.content = b"not-json"
    response.json.side_effect = ValueError("bad json")
    response.headers = {}

    client = AsyncMock()
    client.post.return_value = response
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None

    with patch("authplane.net.http.httpx.AsyncClient", return_value=client):
        result = await form_post(
            "https://auth.example.com/token",
            {"grant_type": "client_credentials"},
            FetchSettings(ssrf_protection=False),
        )

    assert result.status_code == 200
    assert result.body == {}


def test_decode_jwt_header_rejects_non_object() -> None:
    token = "W10.sig.sig"  # decodes to []
    with pytest.raises(InvalidDPoPProofError, match="JSON object"):
        _decode_jwt_header(token)


def test_normalize_dpop_htu_rejects_relative_url() -> None:
    with pytest.raises(InvalidDPoPProofError):
        normalize_dpop_htu("/relative")


def test_jwk_thumbprint_rejects_unknown_kty() -> None:
    with pytest.raises(InvalidDPoPProofError):
        jwk_thumbprint({"kty": "oct"})


def test_dpop_key_material_rejects_invalid_algorithm() -> None:
    with pytest.raises(ValueError, match="DPoP algorithm"):
        DPoPKeyMaterial(private_key="pem", public_jwk={}, algorithm="HS256")


async def test_client_get_endpoint_without_metadata_cache_raises() -> None:
    client = AuthplaneClient()
    with pytest.raises(MetadataFetchError):
        await client._get_token_endpoint()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MetadataFetchError):
        await client._get_introspection_endpoint()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MetadataFetchError):
        await client._get_revocation_endpoint()  # pyright: ignore[reportPrivateUsage]


def test_client_handle_failure_distinguishes_ssrf_and_transport() -> None:
    client = AuthplaneClient()
    client._circuit_breaker = MagicMock()  # type: ignore[assignment, reportPrivateUsage]

    client._handle_failure(SSRFError("blocked"))  # pyright: ignore[reportPrivateUsage]
    client._circuit_breaker.record_failure.assert_not_called()  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]

    client._handle_failure(httpx.ConnectError("down"))  # pyright: ignore[reportPrivateUsage]
    client._circuit_breaker.record_failure.assert_called_once()  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]


def test_client_dpop_headers_requires_provider() -> None:
    client = AuthplaneClient()
    with pytest.raises(DPoPError, match="no DPoP provider"):
        client.dpop_headers("GET", "https://api.example.com")


def test_client_dpop_headers_uses_provider(jwks_keypair: dict[str, Any]) -> None:
    client = AuthplaneClient()
    client._dpop = DPoPProvider(DPoPKeyMaterial.from_pem(jwks_keypair["private_key"]))  # pyright: ignore[reportPrivateUsage]
    headers = client.dpop_headers("GET", "https://api.example.com")
    assert "DPoP" in headers
