"""Tests for Authplane error hierarchy guarantees."""

import pytest

from authplane.errors import (
    AuthError,
    AuthplaneError,
    CircuitOpenError,
    ConsentRequiredError,
    DPoPBindingMismatchError,
    DPoPError,
    DPoPMultipleProofsError,
    DPoPNotSupportedError,
    DPoPProofMissingError,
    DPoPReplayDetectedError,
    InsufficientScopeError,
    InvalidClaimsError,
    InvalidClientError,
    InvalidDPoPProofError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    InvalidSignatureError,
    JWKSFetchError,
    MetadataFetchError,
    ProtocolError,
    ServerError,
    TokenExpiredError,
    TokenMissingError,
    TokenRevokedError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
    VerifierRuntimeError,
    http_status,
    response_headers_for,
    www_authenticate,
)


@pytest.mark.parametrize(
    ("error_type", "is_auth_error"),
    [
        (AuthError, True),
        (InvalidClientError, True),
        (UnauthorizedClientError, True),
        (InvalidScopeError, True),
        (InvalidGrantError, True),
        (UnsupportedGrantTypeError, True),
        (InvalidRequestError, True),
        (ServerError, True),
        (CircuitOpenError, True),
        (ConsentRequiredError, True),
        (InsufficientScopeError, False),
        (DPoPError, False),
        (DPoPProofMissingError, False),
        (InvalidDPoPProofError, False),
        (DPoPMultipleProofsError, False),
        (DPoPReplayDetectedError, False),
        (DPoPBindingMismatchError, False),
    ],
)
def test_error_hierarchy_contract(error_type: type[Exception], is_auth_error: bool) -> None:
    error = error_type("message")
    assert isinstance(error, AuthplaneError)
    assert issubclass(error_type, AuthplaneError)
    assert isinstance(error, AuthError) is is_auth_error


def test_auth_error_preserves_message_code_and_status() -> None:
    error = InvalidClientError("bad credentials", code="invalid_client", status_code=401)
    assert str(error) == "bad credentials"
    assert error.code == "invalid_client"
    assert error.status_code == 401


def test_consent_required_error_preserves_metadata() -> None:
    error = ConsentRequiredError(
        "consent required",
        service_id="calendar",
        cause_detail="missing_user_consent",
        consent_url="https://as.example.com/consent?service=calendar",
        code="consent_required",
        status_code=400,
    )
    assert str(error) == "consent required"
    assert error.code == "consent_required"
    assert error.status_code == 400
    assert error.service_id == "calendar"
    assert error.cause_detail == "missing_user_consent"
    assert error.consent_url == "https://as.example.com/consent?service=calendar"


def test_consent_required_error_describe_full() -> None:
    error = ConsentRequiredError(
        "consent required",
        service_id="calendar",
        cause_detail="missing_user_consent",
    )
    assert error.describe() == "consent required (calendar: missing_user_consent)"


def test_consent_required_error_describe_defaults_service_id() -> None:
    # An explicitly-empty service_id falls back to "unknown_service".
    error = ConsentRequiredError(
        "consent required",
        service_id="",
        cause_detail="missing_user_consent",
    )
    assert error.describe() == "consent required (unknown_service: missing_user_consent)"


def test_consent_required_error_describe_defaults_cause_detail_to_message() -> None:
    # cause_detail falls back to message when not provided. The constructor
    # already coerces empty cause_detail to message, so describe() repeats
    # the message as the cause.
    error = ConsentRequiredError("consent required", service_id="calendar")
    assert error.describe() == "consent required (calendar: consent required)"


def test_insufficient_scope_is_not_an_auth_error() -> None:
    error = InsufficientScopeError("scope missing")
    assert isinstance(error, AuthplaneError)
    assert not isinstance(error, AuthError)
    assert str(error) == "scope missing"


def test_insufficient_scope_required_scopes_default_empty() -> None:
    # Backwards-compatible default: callers passing only a message still work
    # and required_scopes is the empty tuple.
    error = InsufficientScopeError("scope missing")
    assert error.required_scopes == ()


def test_insufficient_scope_required_scopes_preserved() -> None:
    error = InsufficientScopeError("scope missing", required_scopes=("read", "write"))
    assert error.required_scopes == ("read", "write")


# ---------------------------------------------------------------------------
# www_authenticate() — wire-format guarantees
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected_scheme", "expected_error_code"),
    [
        (TokenMissingError("missing"), "Bearer", "invalid_token"),
        (TokenExpiredError("expired"), "Bearer", "invalid_token"),
        (InvalidSignatureError("bad sig"), "Bearer", "invalid_token"),
        (InvalidClaimsError("bad claims"), "Bearer", "invalid_token"),
        (TokenRevokedError("revoked"), "Bearer", "invalid_token"),
        (InsufficientScopeError("need scope"), "Bearer", "insufficient_scope"),
        (DPoPProofMissingError("no proof"), "DPoP", "invalid_token"),
        (InvalidDPoPProofError("bad proof"), "DPoP", "invalid_token"),
        # RFC 9449 §7.1: §4.3 cardinality rejections get invalid_dpop_proof,
        # not the SDK's historical invalid_token used by the other DPoP shapes.
        (DPoPMultipleProofsError("two proofs"), "DPoP", "invalid_dpop_proof"),
        (DPoPReplayDetectedError("replay"), "DPoP", "invalid_token"),
        (DPoPBindingMismatchError("binding"), "DPoP", "invalid_token"),
    ],
)
def test_www_authenticate_scheme_and_error_code(
    error: AuthplaneError, expected_scheme: str, expected_error_code: str
) -> None:
    header = www_authenticate(error)
    assert header.startswith(f"{expected_scheme} ")
    assert f'error="{expected_error_code}"' in header


def test_www_authenticate_dpop_not_supported_uses_bearer_scheme() -> None:
    # Regression: DPoPNotSupportedError subclasses DPoPError
    # but the resource is bearer-only, so the challenge must advertise Bearer
    # (a DPoP retry would just fail again).
    header = www_authenticate(DPoPNotSupportedError("not supported"))
    assert header.startswith("Bearer ")
    assert "DPoP" not in header.split(" ", 1)[0]


def test_www_authenticate_includes_realm_when_provided() -> None:
    header = www_authenticate(TokenExpiredError("expired"), realm="api.example.com")
    assert 'realm="api.example.com"' in header


def test_www_authenticate_omits_realm_when_empty() -> None:
    header = www_authenticate(TokenExpiredError("expired"))
    assert "realm=" not in header


def test_www_authenticate_includes_resource_metadata_when_provided() -> None:
    url = "https://resource.example.com/.well-known/oauth-protected-resource"
    header = www_authenticate(TokenExpiredError("expired"), resource_metadata_url=url)
    assert f'resource_metadata="{url}"' in header


def test_www_authenticate_omits_resource_metadata_when_absent() -> None:
    header = www_authenticate(TokenExpiredError("expired"))
    assert "resource_metadata=" not in header


def test_www_authenticate_explicit_scope_round_trips() -> None:
    header = www_authenticate(InsufficientScopeError("need scopes"), scope=["read", "write"])
    assert 'scope="read write"' in header


def test_www_authenticate_scope_omitted_when_empty_list() -> None:
    header = www_authenticate(InsufficientScopeError("need scopes"), scope=[])
    assert "scope=" not in header


def test_www_authenticate_auto_populates_scope_from_required_scopes() -> None:
    # When the caller doesn't pass scope= but the error carries required_scopes,
    # the helper emits scope= automatically.
    error = InsufficientScopeError("missing 'admin'", required_scopes=("admin",))
    header = www_authenticate(error)
    assert 'scope="admin"' in header


def test_www_authenticate_explicit_scope_overrides_required_scopes() -> None:
    error = InsufficientScopeError("missing 'admin'", required_scopes=("admin",))
    header = www_authenticate(error, scope=["read", "write"])
    assert 'scope="read write"' in header
    assert 'scope="admin"' not in header


def test_www_authenticate_no_scope_when_required_scopes_empty() -> None:
    error = InsufficientScopeError("scope missing")
    header = www_authenticate(error)
    assert "scope=" not in header


@pytest.mark.parametrize(
    "message",
    [
        'evil", error="invalid_token',  # quote breaks out of param
        "evil\r\nSet-Cookie: pwned=1",  # CRLF header injection
        "evil\nX-Injected: 1",  # LF only
        'mix " and \\ chars',  # quote + backslash combo
    ],
)
def test_www_authenticate_sanitizes_error_description(message: str) -> None:
    # Regression: error message must not break out of the
    # quoted error_description parameter or inject additional headers.
    header = www_authenticate(InvalidClaimsError(message))
    # CR/LF/quote/backslash are stripped from the emitted header value.
    assert "\r" not in header
    assert "\n" not in header
    assert "\\" not in header
    # Exactly one error_description parameter (no premature termination + reopen).
    assert header.count('error_description="') == 1
    # The wire form keeps the quotes that bound our parameters, but no extras.
    # 4 quote chars: error="...", error_description="..."
    assert header.count('"') == 4


def test_www_authenticate_sanitizes_realm() -> None:
    header = www_authenticate(TokenExpiredError("expired"), realm='bad", error="injected')
    assert '", error="injected' not in header
    assert header.count('realm="') == 1


def test_www_authenticate_sanitizes_resource_metadata_url() -> None:
    header = www_authenticate(
        TokenExpiredError("expired"),
        resource_metadata_url='https://x.example/.well-known/r"\r\nX: 1',
    )
    assert "\r" not in header
    assert "\n" not in header
    assert header.count('resource_metadata="') == 1


def test_www_authenticate_sanitizes_scope_values() -> None:
    header = www_authenticate(
        InsufficientScopeError("nope"),
        scope=['evil"', "ok"],
    )
    assert '"' not in header.split('scope="', 1)[1].split('"', 1)[0]


# ---------------------------------------------------------------------------
# http_status()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (InsufficientScopeError("nope"), 403),
        (JWKSFetchError("jwks"), 503),
        (MetadataFetchError("meta"), 503),
        (CircuitOpenError("circuit open"), 503),
        (TokenMissingError("missing"), 401),
        (TokenExpiredError("expired"), 401),
        (InvalidSignatureError("sig"), 401),
        (InvalidClaimsError("claims"), 401),
        (TokenRevokedError("revoked"), 401),
        (DPoPProofMissingError("no proof"), 401),
        (InvalidDPoPProofError("bad proof"), 401),
        (DPoPReplayDetectedError("replay"), 401),
        (DPoPBindingMismatchError("binding"), 401),
        (DPoPNotSupportedError("not supported"), 401),
        (ProtocolError("protocol"), 500),
        (VerifierRuntimeError("runtime"), 500),
    ],
)
def test_http_status_mapping(error: AuthplaneError, expected_status: int) -> None:
    assert http_status(error) == expected_status


def test_http_status_unknown_authplane_error_defaults_to_500() -> None:
    class _CustomError(AuthplaneError):
        pass

    assert http_status(_CustomError("custom")) == 500


# ---------------------------------------------------------------------------
# response_headers_for() — bundled helper
# ---------------------------------------------------------------------------


def test_response_headers_for_returns_status_and_challenge() -> None:
    status, headers = response_headers_for(TokenExpiredError("expired"))
    assert status == 401
    assert set(headers.keys()) == {"WWW-Authenticate"}
    assert headers["WWW-Authenticate"].startswith("Bearer ")
    assert 'error="invalid_token"' in headers["WWW-Authenticate"]


def test_response_headers_for_forwards_keyword_arguments() -> None:
    status, headers = response_headers_for(
        InsufficientScopeError("need", required_scopes=("admin",)),
        realm="api",
        resource_metadata_url="https://x/.well-known/oauth-protected-resource",
        scope=["read", "write"],  # explicit override of required_scopes
    )
    assert status == 403
    challenge = headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'realm="api"' in challenge
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="read write"' in challenge
    assert 'resource_metadata="https://x/.well-known/oauth-protected-resource"' in challenge


def test_response_headers_for_dpop_error_uses_dpop_scheme() -> None:
    status, headers = response_headers_for(InvalidDPoPProofError("bad"))
    assert status == 401
    assert headers["WWW-Authenticate"].startswith("DPoP ")
