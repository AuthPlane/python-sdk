"""RFC 6749, RFC 7009, RFC 7662, RFC 8693, and RFC 8707 conformance tests."""

import base64
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from authplane import AuthplaneClient, FetchSettings, IntrospectionRevocation
from authplane.errors import (
    InvalidClientError,
    InvalidGrantError,
    ProtocolError,
    ServerError,
    TokenRevokedError,
)
from authplane.net.http import FormPostResponse, build_basic_auth_header
from authplane.oauth.client_credentials import client_credentials_grant
from authplane.oauth.introspection import introspect_token
from authplane.oauth.parsing import parse_token_response
from authplane.oauth.revocation import revoke_token
from authplane.oauth.token_exchange import exchange_token
from authplane.oauth.types import IntrospectionResponse, TokenExchangeOptions

_NO_SSRF = FetchSettings(ssrf_protection=False)
_ISSUER = "https://auth.example.com"
_JWKS_URL = f"{_ISSUER}/.well-known/jwks.json"
_METADATA_URL = f"{_ISSUER}/.well-known/oauth-authorization-server"
_TOKEN_URL = f"{_ISSUER}/oauth/token"
_INTROSPECTION_URL = f"{_ISSUER}/oauth/introspect"
_REVOKE_URL = f"{_ISSUER}/oauth/revoke"
_EXCHANGE_SUCCESS_BODY: dict[str, object] = {
    "access_token": "tok",
    "token_type": "Bearer",
    "expires_in": 3600,
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
}


@pytest.mark.conformance("rfc6749-client-credentials-success-response")
async def test_rfc6749_client_credentials_success_response() -> None:
    with patch(
        "authplane.oauth.client_credentials.form_post",
        new_callable=AsyncMock,
        return_value=FormPostResponse(
            status_code=200,
            body={
                "access_token": "new_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read",
            },
            headers={},
        ),
    ):
        result = await client_credentials_grant(
            _TOKEN_URL,
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            _NO_SSRF,
            scopes=["read"],
        )
    assert result.access_token == "new_token"
    assert result.token_type == "Bearer"


@pytest.mark.conformance("rfc6749-basic-auth-credentials-must-be-form-urlencoded-before-base64")
async def test_rfc6749_basic_auth_credentials_must_be_form_urlencoded_before_base64() -> None:
    header = build_basic_auth_header("http://localhost:8080/mcp", "s3cret")
    decoded = base64.b64decode(header["Authorization"][6:]).decode()
    assert decoded == "http%3A%2F%2Flocalhost%3A8080%2Fmcp:s3cret"


@pytest.mark.conformance("rfc6749-token-response-must-contain-access-token")
async def test_rfc6749_token_response_must_contain_access_token() -> None:
    with pytest.raises(ProtocolError, match="access_token"):
        parse_token_response({"token_type": "Bearer"}, allow_issued_token_type=False)


@pytest.mark.conformance("rfc6749-token-response-token-type-must-be-supported")
async def test_rfc6749_token_response_token_type_must_be_supported() -> None:
    with pytest.raises(ProtocolError, match="unsupported token_type"):
        parse_token_response(
            {"access_token": "tok", "token_type": "N_A"},
            allow_issued_token_type=False,
        )


@pytest.mark.conformance("rfc9449-token-response-token-type-dpop-must-be-accepted")
async def test_rfc9449_token_response_token_type_dpop_must_be_accepted() -> None:
    result = parse_token_response(
        {"access_token": "tok", "token_type": "DPoP"},
        allow_issued_token_type=False,
    )
    assert result.token_type == "DPoP"


@pytest.mark.conformance("rfc9449-dpop-grant-token-type-must-be-dpop")
async def test_rfc9449_dpop_grant_token_type_must_be_dpop() -> None:
    # RFC 9449 §5: when a DPoP proof was sent with the token request, the
    # response token_type MUST be "DPoP".  A "Bearer" response means the AS
    # ignored the proof and the token is NOT sender-constrained.
    with pytest.raises(ProtocolError, match=r"(?i)dpop.*token_type|token_type.*dpop"):
        parse_token_response(
            {"access_token": "tok", "token_type": "Bearer"},
            allow_issued_token_type=False,
            expect_dpop=True,
        )


@pytest.mark.conformance("rfc6749-token-response-expires-in-must-be-non-negative-integer")
async def test_rfc6749_token_response_expires_in_must_be_non_negative_integer() -> None:
    with pytest.raises(ProtocolError, match="non-negative"):
        parse_token_response(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": -1},
            allow_issued_token_type=False,
        )


@pytest.mark.conformance("rfc6749-invalid-client-must-map-to-authentication-failure")
async def test_rfc6749_invalid_client_must_map_to_authentication_failure() -> None:
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
            _TOKEN_URL,
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            _NO_SSRF,
        )


@pytest.mark.conformance("rfc7009-revocation-200-is-success-even-for-already-invalid-token")
async def test_rfc7009_revocation_200_is_success_even_for_already_invalid_token() -> None:
    with patch(
        "authplane.oauth.revocation.form_post",
        new_callable=AsyncMock,
        return_value=FormPostResponse(status_code=200, body={}, headers={}),
    ):
        await revoke_token(
            _REVOKE_URL, "token_to_revoke", {"Authorization": "Basic dGVzdDpzZWNyZXQ="}, _NO_SSRF
        )


@pytest.mark.conformance("rfc7009-revocation-server-errors-must-surface")
async def test_rfc7009_revocation_server_errors_must_surface() -> None:
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
            _REVOKE_URL,
            "token_to_revoke",
            {"Authorization": "Basic dGVzdDpzZWNyZXQ="},
            _NO_SSRF,
        )


@respx.mock
@pytest.mark.conformance("rfc7009-revocation-request-must-post-token-and-token-type-hint")
async def test_rfc7009_revocation_request_must_post_token_and_token_type_hint() -> None:
    route = respx.post(_REVOKE_URL).mock(return_value=httpx.Response(200, json={}))
    await revoke_token(_REVOKE_URL, "token_to_revoke", {}, _NO_SSRF)
    body = route.calls.last.request.content.decode()
    assert "token=token_to_revoke" in body
    assert "token_type_hint=access_token" in body


@respx.mock
@pytest.mark.conformance("rfc7662-introspection-request-must-post-token-and-access-token-hint")
async def test_rfc7662_introspection_request_must_post_token_and_access_token_hint() -> None:
    route = respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    await introspect_token(_INTROSPECTION_URL, "my.raw.token", {}, _NO_SSRF)

    body = route.calls.last.request.content.decode()
    assert "token=my.raw.token" in body
    assert "token_type_hint=access_token" in body


@respx.mock
@pytest.mark.conformance(
    "rfc7662-introspection-without-credentials-must-not-send-authorization-header"
)
async def test_rfc7662_introspection_without_credentials_must_not_send_authorization_header() -> (
    None
):
    route = respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    await introspect_token(_INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert "authorization" not in route.calls.last.request.headers


@respx.mock
@pytest.mark.conformance("rfc7662-introspection-basic-auth-must-be-supported")
async def test_rfc7662_introspection_basic_auth_must_be_supported() -> None:
    route = respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": True})
    )
    auth_header = build_basic_auth_header("my-client-id", "my-client-secret")
    await introspect_token(_INTROSPECTION_URL, "raw-token", auth_header, _NO_SSRF)
    assert route.calls.last.request.headers["authorization"].startswith("Basic ")


@respx.mock
@pytest.mark.conformance("rfc7662-introspection-active-false-must-parse-as-inactive")
async def test_rfc7662_introspection_active_false_must_parse_as_inactive() -> None:
    respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"active": False})
    )
    result = await introspect_token(_INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert result.active is False


@respx.mock
@pytest.mark.conformance("rfc7662-introspection-missing-active-must-default-to-inactive")
async def test_rfc7662_introspection_missing_active_must_default_to_inactive() -> None:
    respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(200, json={"error": "invalid_token"})
    )
    result = await introspect_token(_INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert result.active is False


@respx.mock
@pytest.mark.conformance("rfc7662-introspection-standard-fields-must-round-trip")
async def test_rfc7662_introspection_standard_fields_must_round_trip() -> None:
    respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "active": True,
                "scope": "read:data write:data",
                "client_id": "client456",
                "sub": "user123",
                "token_type": "access_token",
                "iss": _ISSUER,
                "exp": 1234567890,
                "iat": 1234567800,
                "jti": "token-id-123",
            },
        )
    )
    result = await introspect_token(_INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert result == IntrospectionResponse(
        active=True,
        scope="read:data write:data",
        client_id="client456",
        sub="user123",
        token_type="access_token",
        iss=_ISSUER,
        exp=1234567890,
        iat=1234567800,
        jti="token-id-123",
    )


@respx.mock
@pytest.mark.conformance("rfc7662-introspection-audience-must-parse-string-or-array")
async def test_rfc7662_introspection_audience_must_parse_string_or_array() -> None:
    # RFC 7519 §4.1.3: aud may be a single string or an array of strings.
    # The SDK must preserve both forms so callers can inspect the value.
    respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(
            200, json={"active": True, "aud": "https://api.example.com"}
        )
    )
    result_string = await introspect_token(_INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert result_string.active is True
    assert result_string.aud == "https://api.example.com"

    respx.post(_INTROSPECTION_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={"active": True, "aud": ["https://api.example.com", "https://other.example.com"]},
        )
    )
    result_array = await introspect_token(_INTROSPECTION_URL, "raw-token", {}, _NO_SSRF)
    assert result_array.active is True
    assert result_array.aud == ["https://api.example.com", "https://other.example.com"]


@pytest.mark.conformance("rfc7662-verifier-active-false-must-reject-token")
async def test_rfc7662_verifier_active_false_must_reject_token(
    jwks_keypair: dict[str, Any],
    token_factory: Any,
) -> None:
    with respx.mock:
        respx.get(_METADATA_URL).mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": _ISSUER,
                    "jwks_uri": _JWKS_URL,
                    "introspection_endpoint": _INTROSPECTION_URL,
                },
            )
        )
        respx.get(_JWKS_URL).mock(return_value=respx.MockResponse(200, json=jwks_keypair["jwks"]))
        respx.post(_INTROSPECTION_URL).mock(
            return_value=respx.MockResponse(200, json={"active": False})
        )

        client = await AuthplaneClient.create(
            issuer=_ISSUER,
            fetch_settings=_NO_SSRF,
        )
        verifier = client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
            revocation_checker=IntrospectionRevocation(),
        )
        try:
            with pytest.raises(TokenRevokedError):
                await verifier.verify(token_factory())
        finally:
            await client.aclose()


@pytest.mark.conformance("rfc7662-introspection-fail-open-policy-must-be-explicitly-tested")
async def test_rfc7662_introspection_fail_open_policy_must_be_explicitly_tested(
    jwks_keypair: dict[str, Any],
    token_factory: Any,
) -> None:
    with respx.mock:
        respx.get(_METADATA_URL).mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": _ISSUER,
                    "jwks_uri": _JWKS_URL,
                    "introspection_endpoint": _INTROSPECTION_URL,
                },
            )
        )
        respx.get(_JWKS_URL).mock(return_value=respx.MockResponse(200, json=jwks_keypair["jwks"]))
        respx.post(_INTROSPECTION_URL).mock(
            return_value=respx.MockResponse(500, json={"error": "server_error"})
        )

        client = await AuthplaneClient.create(
            issuer=_ISSUER,
            fetch_settings=_NO_SSRF,
        )
        verifier = client.resource(
            resource="https://api.example.com",
            scopes=["read:data"],
            revocation_checker=IntrospectionRevocation(),
        )
        try:
            claims = await verifier.verify(token_factory())
            assert claims.sub == "user123"
        finally:
            await client.aclose()


@respx.mock
@pytest.mark.conformance("rfc8693-grant-type-must-be-token-exchange")
async def test_rfc8693_grant_type_must_be_token_exchange() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(_TOKEN_URL, TokenExchangeOptions(subject_token="subject"), {}, _NO_SSRF)
    body = route.calls.last.request.content.decode()
    assert "grant_type=" in body
    assert "token-exchange" in body


@pytest.mark.conformance("rfc8693-subject-token-is-required")
async def test_rfc8693_subject_token_is_required() -> None:
    with pytest.raises(ValueError, match="subject_token is required"):
        await exchange_token(_TOKEN_URL, TokenExchangeOptions(subject_token=""), {}, _NO_SSRF)


@respx.mock
@pytest.mark.conformance("rfc8693-default-subject-token-type-is-access-token")
async def test_rfc8693_default_subject_token_type_is_access_token() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(_TOKEN_URL, TokenExchangeOptions(subject_token="subject"), {}, _NO_SSRF)
    assert (
        "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
        in route.calls.last.request.content.decode()
    )


@respx.mock
@pytest.mark.conformance("rfc8693-actor-token-type-defaults-when-actor-token-is-present")
async def test_rfc8693_actor_token_type_defaults_when_actor_token_is_present() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(
        _TOKEN_URL,
        TokenExchangeOptions(subject_token="subject", actor_token="actor"),
        {},
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert "actor_token=" in body
    assert "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token" in body


@respx.mock
@pytest.mark.conformance("rfc8693-resource-parameter-must-be-sent-when-configured")
async def test_rfc8693_resource_parameter_must_be_sent_when_configured() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(
        _TOKEN_URL,
        TokenExchangeOptions(subject_token="subject", resources=("https://mcp.example.com/",)),
        {},
        _NO_SSRF,
    )
    assert "resource=" in route.calls.last.request.content.decode()


@respx.mock
@pytest.mark.conformance("rfc8693-multiple-resource-parameters-must-be-emitted")
async def test_rfc8693_multiple_resource_parameters_must_be_emitted() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(
        _TOKEN_URL,
        TokenExchangeOptions(
            subject_token="subject",
            resources=("https://api-one.example.com", "https://api-two.example.com"),
        ),
        {},
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert body.count("resource=") == 2
    assert "api-one.example.com" in body
    assert "api-two.example.com" in body


@respx.mock
@pytest.mark.conformance("rfc8693-audience-parameter-must-be-sent-when-configured")
async def test_rfc8693_audience_parameter_must_be_sent_when_configured() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(
        _TOKEN_URL,
        TokenExchangeOptions(subject_token="subject", audiences=("https://api.example.com",)),
        {},
        _NO_SSRF,
    )
    assert "audience=https%3A%2F%2Fapi.example.com" in route.calls.last.request.content.decode()


@respx.mock
@pytest.mark.conformance("rfc8693-multiple-audience-parameters-must-be-emitted")
async def test_rfc8693_multiple_audience_parameters_must_be_emitted() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(
        _TOKEN_URL,
        TokenExchangeOptions(
            subject_token="subject",
            audiences=("https://api-one.example.com", "https://api-two.example.com"),
        ),
        {},
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert body.count("audience=") == 2
    assert "api-one.example.com" in body
    assert "api-two.example.com" in body


@respx.mock
@pytest.mark.conformance("rfc8693-empty-resource-and-audience-values-must-be-omitted")
async def test_rfc8693_empty_resource_and_audience_values_must_be_omitted() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_EXCHANGE_SUCCESS_BODY)
    )
    await exchange_token(
        _TOKEN_URL,
        TokenExchangeOptions(subject_token="subject", resources=("",), audiences=("",)),
        {},
        _NO_SSRF,
    )
    body = route.calls.last.request.content.decode()
    assert "resource=" not in body
    assert "audience=" not in body


@pytest.mark.conformance(
    "rfc8693-success-response-must-use-access-token-issued-token-type-when-present"
)
async def test_rfc8693_success_response_must_use_access_token_issued_token_type_when_present() -> (
    None
):
    # The catalog requires the SDK to (a) accept `access_token` as the issued
    # type and (b) surface it unchanged to callers. Verifying the accept-and-
    # preserve contract:
    response = parse_token_response(
        {
            "access_token": "tok",
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
        allow_issued_token_type=True,
    )
    assert response.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"

    # Any other issued_token_type must be rejected (kept from the original
    # test — exercises the matching reject path).
    with pytest.raises(ProtocolError, match="unsupported issued_token_type"):
        parse_token_response(
            {
                "access_token": "tok",
                "token_type": "Bearer",
                "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
            },
            allow_issued_token_type=True,
        )


@respx.mock
@pytest.mark.conformance("rfc8693-error-mapping-invalid-grant")
async def test_rfc8693_error_mapping_invalid_grant() -> None:
    respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "token expired"}
        )
    )
    with pytest.raises(InvalidGrantError, match="token expired"):
        await exchange_token(
            _TOKEN_URL, TokenExchangeOptions(subject_token="subject"), {}, _NO_SSRF
        )


@respx.mock
@pytest.mark.conformance("rfc8707-client-credentials-resource-parameter-should-be-supported")
async def test_rfc8707_client_credentials_resource_parameter_should_be_supported() -> None:
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(
            200, json={"access_token": "tok", "token_type": "Bearer", "expires_in": 3600}
        )
    )
    await client_credentials_grant(_TOKEN_URL, {}, _NO_SSRF, resources=["https://api.example.com"])
    assert "resource=https%3A%2F%2Fapi.example.com" in route.calls.last.request.content.decode()


@respx.mock
@pytest.mark.conformance("rfc8707-client-credentials-multiple-resource-parameters-must-be-emitted")
async def test_rfc8707_client_credentials_multiple_resource_parameters_must_be_emitted() -> None:
    """RFC 8707 requires one 'resource' form parameter per resource indicator."""
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(
            200, json={"access_token": "tok", "token_type": "Bearer", "expires_in": 3600}
        )
    )
    await client_credentials_grant(
        _TOKEN_URL,
        {},
        _NO_SSRF,
        resources=["https://api.example.com", "https://other.example.com"],
    )
    body = route.calls.last.request.content.decode()
    assert body.count("resource=") == 2
    assert "resource=https%3A%2F%2Fapi.example.com" in body
    assert "resource=https%3A%2F%2Fother.example.com" in body


@respx.mock
@pytest.mark.conformance("rfc6749-client-credentials-scopes-must-support-multiple-values")
async def test_rfc6749_client_credentials_scopes_must_support_multiple_values() -> None:
    """Multiple scopes must be joined with a space into a single 'scope' parameter."""
    route = respx.post(_TOKEN_URL).mock(
        return_value=httpx.Response(
            200, json={"access_token": "tok", "token_type": "Bearer", "expires_in": 3600}
        )
    )
    await client_credentials_grant(
        _TOKEN_URL,
        {},
        _NO_SSRF,
        scopes=["read", "write", "admin"],
    )
    body = route.calls.last.request.content.decode()
    assert "scope=read+write+admin" in body


@pytest.mark.conformance("rfc8707-verifier-must-accept-resource-when-present-in-aud-array")
async def test_rfc8707_verifier_must_accept_resource_when_present_in_aud_array(
    verifier: Any,
    token_factory: Any,
) -> None:
    claims = await verifier.verify(
        token_factory(aud=["https://api.example.com", "https://other.example.com"])
    )  # type: ignore[arg-type]
    assert "https://api.example.com" in claims.audience


# ---------------------------------------------------------------------------
# RFC 8693 §2.2.1 — issued_token_type required in exchange responses
# ---------------------------------------------------------------------------


@pytest.mark.conformance("rfc8693-token-exchange-response-must-contain-issued-token-type")
async def test_rfc8693_token_exchange_response_must_contain_issued_token_type() -> None:
    """Token exchange responses MUST include issued_token_type per RFC 8693 §2.2.1."""
    with pytest.raises(ProtocolError, match="issued_token_type"):
        parse_token_response(
            {
                "access_token": "exchanged_token",
                "token_type": "Bearer",
                # issued_token_type deliberately absent
            },
            allow_issued_token_type=True,
        )
