"""Tests for Authplane error hierarchy guarantees."""

import contextlib
import logging
import re
from collections.abc import Generator

import pytest

from authplane.dpop import SUPPORTED_DPOP_ALGORITHMS, InboundDPoPOptions
from authplane.errors import (
    AccessDeniedError,
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
    InvalidTargetError,
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
    _description_for,  # pyright: ignore[reportPrivateUsage]
    http_status,
    response_headers_for,
    www_authenticate,
    www_authenticate_challenges,
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
        (AccessDeniedError, True),
        (InvalidTargetError, True),
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


@contextlib.contextmanager
def caplog_at_debug() -> Generator[list[logging.LogRecord]]:
    """Capture only ``authplane.errors`` DEBUG records, scoped to the block."""
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("authplane.errors")
    handler = _Collect()
    previous_level, previous_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate


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
    # verbose_description=True is the only path that still interpolates the
    # exception message, so it is the path the sanitizer has to hold on.
    header = www_authenticate(InvalidClaimsError(message), verbose_description=True)
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
    # Kept as a backstop, not as the guarantee. Substituting a space for a `"`
    # leaves the header parseable while advertising a URL that no longer
    # matches the one a client derives from the identifier this SDK also serves
    # as the PRM document's `resource` member — the RFC 9728 §3.3 mismatch by
    # another route. A host-borne delimiter can no longer reach it:
    # `internal/urls.py` rejects a `"` or a `\\` in the host at construction.
    # The path and the query are not covered by that gate and still arrive
    # here. This parameter is also a plain `str` on a public function, so a
    # caller can hand it a value that never passed any gate, and `realm`/
    # `scope` are free-form and gated nowhere — which is why the substitution
    # stays.
    header = www_authenticate(
        TokenExpiredError("expired"),
        resource_metadata_url='https://x.example/.well-known/r"\r\nX: 1',
    )
    assert "\r" not in header
    assert "\n" not in header
    assert header.count('resource_metadata="') == 1


def test_a_host_borne_delimiter_can_no_longer_reach_the_substitution() -> None:
    # The construction gate covers the host, and only the host. Named that way
    # on purpose: this backstop's docstring is where the next reader decides
    # whether the substitution is still load-bearing, and a claim scoped wider
    # than the gate would talk them out of a check that is still the only one
    # covering two of the three components.
    from authplane.errors import InvalidResourceError
    from authplane.internal.urls import build_prm_url

    for resource in ('https://api"example.com/mcp', "https://api\\example.com/mcp"):
        with pytest.raises(InvalidResourceError, match="host must not contain a literal"):
            build_prm_url(resource)

    # And the residue, pinned rather than described: a delimiter in the path or
    # the query still constructs, still derives, and still reaches the
    # substitution — which rewrites it, so the advertised URL stops matching
    # the `resource` member served from the same identifier (RFC 9728 §3.3).
    # This is the assertion to delete when that axis is gated too.
    for resource in ('https://api.example.com/m"cp', 'https://api.example.com/mcp?a="b'):
        derived = build_prm_url(resource)
        assert '"' in derived
        challenge = www_authenticate(TokenExpiredError("expired"), resource_metadata_url=derived)
        assert derived not in challenge
        assert f'resource_metadata="{derived.replace(chr(34), " ")}"' in challenge

    # And the derivation an operator DOES configure survives the substitution
    # byte-for-byte, so the advertised URL still matches the served `resource`.
    url = build_prm_url("https://api.example.com/mcp")
    header = www_authenticate(TokenExpiredError("expired"), resource_metadata_url=url)
    assert f'resource_metadata="{url}"' in header


def test_www_authenticate_sanitizes_scope_values() -> None:
    header = www_authenticate(
        InsufficientScopeError("nope"),
        scope=['evil"', "ok"],
    )
    assert '"' not in header.split('scope="', 1)[1].split('"', 1)[0]


# ---------------------------------------------------------------------------
# www_authenticate() — error_description carries no internal detail
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected_description"),
    [
        (
            TokenExpiredError("expired"),
            "The access token is missing or not valid for this resource",
        ),
        (
            InsufficientScopeError("need admin"),
            "The access token does not carry the scope this operation requires",
        ),
        (
            DPoPMultipleProofsError("two proofs"),
            "The DPoP proof is missing or not valid for this request",
        ),
    ],
)
def test_www_authenticate_description_is_fixed_per_error_code(
    error: AuthplaneError, expected_description: str
) -> None:
    # The description is chosen by the RFC 6750 §3.1 / RFC 9449 §7.1 error
    # code, not by the exception, so it is identical for every error that maps
    # to the same code.
    assert f'error_description="{expected_description}"' in www_authenticate(error)


def test_unmapped_error_code_falls_back_to_a_contentless_description() -> None:
    # Every code the mapper can currently produce has a table entry, so this
    # guards the branch that catches a code added later without one: the
    # fallback must still be contentless, never the exception's message.
    error = InvalidClaimsError("Token kid 'signing-key-7' not found in JWKS after refresh")
    description = _description_for(error, "some_future_error_code", verbose=False)
    assert description == "The request could not be authenticated"
    assert "signing-key-7" not in description


@pytest.mark.parametrize(
    ("error", "secret"),
    [
        # The verifier's real messages: each names a detail an unauthenticated
        # caller must not learn. The aud case is the sharpest — it discloses
        # the audience the caller would need to request a token for.
        (
            InvalidClaimsError(
                "Token claims validation failed: invalid_claim: aud "
                "(expected 'https://mysql.internal.example/mcp')"
            ),
            "https://mysql.internal.example/mcp",
        ),
        (InvalidSignatureError("Token kid 'signing-key-7' not found in JWKS after refresh"), "kid"),
        (InvalidClaimsError("Token type must be 'at+jwt', got 'JWT'"), "at+jwt"),
        (InvalidDPoPProofError("DPoP proof nonce mismatch"), "nonce"),
    ],
)
def test_www_authenticate_never_emits_the_internal_message(
    error: AuthplaneError, secret: str
) -> None:
    header = www_authenticate(error)
    assert secret not in header
    assert str(error) not in header


def test_www_authenticate_verbose_description_restores_the_internal_message() -> None:
    error = InvalidClaimsError("Token claims validation failed: invalid_claim: aud")
    header = www_authenticate(error, verbose_description=True)
    assert f'error_description="{error}"' in header


def test_www_authenticate_safe_description_does_not_disturb_other_parameters() -> None:
    header = www_authenticate(
        InsufficientScopeError("missing 'admin'", required_scopes=("admin",)),
        realm="api.example.com",
        resource_metadata_url="https://api.example.com/.well-known/oauth-protected-resource",
    )
    assert header.startswith("Bearer ")
    assert 'realm="api.example.com"' in header
    assert 'error="insufficient_scope"' in header
    assert 'scope="admin"' in header
    assert "resource_metadata=" in header


def test_response_headers_for_forwards_verbose_description() -> None:
    error = InvalidClaimsError("Token kid 'k7' not found in JWKS after refresh")
    _, safe_headers = response_headers_for(error)
    assert "k7" not in safe_headers["WWW-Authenticate"]
    _, verbose_headers = response_headers_for(error, verbose_description=True)
    assert "k7" in verbose_headers["WWW-Authenticate"]


# ---------------------------------------------------------------------------
# www_authenticate_challenges() — one header value per acceptable scheme
# ---------------------------------------------------------------------------


def test_www_authenticate_challenges_defaults_to_the_single_derived_scheme() -> None:
    error = TokenExpiredError("expired")
    challenges = www_authenticate_challenges(error)
    assert challenges == [www_authenticate(error)]


def test_www_authenticate_challenges_derived_scheme_follows_the_error_type() -> None:
    assert www_authenticate_challenges(InvalidDPoPProofError("bad proof"))[0].startswith("DPoP ")
    assert www_authenticate_challenges(DPoPNotSupportedError("no dpop"))[0].startswith("Bearer ")


def test_www_authenticate_challenges_advertises_both_schemes_in_order() -> None:
    # inbound_dpop in optional mode accepts both; RFC 9449 §7.1 wants both
    # advertised, and RFC 7235 §4.1 advises separate header values.
    challenges = www_authenticate_challenges(
        TokenMissingError("no token"),
        schemes=("Bearer", "DPoP"),
        realm="api.example.com",
    )
    assert len(challenges) == 2
    assert challenges[0].startswith("Bearer ")
    assert challenges[1].startswith("DPoP ")
    for challenge in challenges:
        assert 'realm="api.example.com"' in challenge
        assert 'error="invalid_token"' in challenge


def test_www_authenticate_challenges_emits_algs_on_the_dpop_challenge_only() -> None:
    bearer, dpop = www_authenticate_challenges(
        TokenMissingError("no token"),
        schemes=("Bearer", "DPoP"),
        algs=("ES256", "RS256"),
    )
    assert "algs=" not in bearer
    assert 'algs="ES256 RS256"' in dpop


def test_www_authenticate_challenges_omits_algs_when_not_provided() -> None:
    (dpop,) = www_authenticate_challenges(TokenMissingError("no token"), schemes=("DPoP",))
    assert "algs=" not in dpop


def test_www_authenticate_challenges_ignores_algs_without_a_dpop_scheme() -> None:
    (bearer,) = www_authenticate_challenges(
        TokenMissingError("no token"), schemes=("Bearer",), algs=("ES256",)
    )
    assert "algs=" not in bearer


def test_www_authenticate_challenges_rejects_unsupported_algs() -> None:
    # Validated, not escaped: these are bare RFC 7235 tokens, same as
    # `schemes`, and escaping let a comma through — the one character the
    # parameter text works to keep out so a lenient parser cannot split on it.
    with pytest.raises(ValueError, match="Unsupported DPoP proof algorithms"):
        www_authenticate_challenges(
            TokenMissingError("no token"),
            schemes=("DPoP",),
            algs=['ES256", error="injected'],
        )
    with pytest.raises(ValueError, match="Unsupported DPoP proof algorithms"):
        www_authenticate_challenges(
            TokenMissingError("no token"), schemes=("DPoP",), algs=("ES256,RS256",)
        )


def test_www_authenticate_challenges_algs_none_advertises_the_default_set() -> None:
    # The documented call is `algs=options.allowed_proof_algorithms`, and that
    # attribute is None on a default-constructed options object. It used to
    # advertise nothing, then briefly raised TypeError from inside the 401
    # handler — a 500 on every unauthenticated request.
    options = InboundDPoPOptions()
    assert options.allowed_proof_algorithms is None
    (dpop,) = www_authenticate_challenges(
        TokenMissingError("no token"),
        schemes=("DPoP",),
        algs=options.allowed_proof_algorithms,
    )
    assert f'algs="{" ".join(SUPPORTED_DPOP_ALGORITHMS)}"' in dpop


def test_www_authenticate_challenges_algs_default_still_omits_the_parameter() -> None:
    # Passing nothing keeps the parameter off the challenge, which is what
    # every existing caller relies on. Only an explicit None means "default set".
    (dpop,) = www_authenticate_challenges(TokenMissingError("no token"), schemes=("DPoP",))
    assert "algs=" not in dpop


def test_the_withheld_message_is_logged_at_debug() -> None:
    # Three user guides and llm-full.txt justify keeping the exception message
    # off the wire by promising it is logged at DEBUG instead. Without a test,
    # a refactor can drop the log while the docs keep promising it.
    error = InvalidClaimsError("expected aud 'https://api.example.com/mcp', got 'other'")
    with caplog_at_debug() as records:
        challenge = www_authenticate(error)
    assert "expected aud" not in challenge
    assert any("expected aud" in r.getMessage() for r in records)

    with caplog_at_debug() as records:
        (challenge,) = www_authenticate_challenges(error, schemes=("Bearer",))
    assert "expected aud" not in challenge
    assert any("expected aud" in r.getMessage() for r in records)


def test_no_debug_log_when_the_message_already_goes_on_the_wire() -> None:
    # verbose_description puts the message in error_description, so logging it
    # a second time would be pure duplication.
    error = InvalidClaimsError("expected aud 'https://api.example.com/mcp', got 'other'")
    with caplog_at_debug() as records:
        challenge = www_authenticate(error, verbose_description=True)
    assert "expected aud" in challenge
    assert not any("expected aud" in r.getMessage() for r in records)


def test_www_authenticate_challenges_rejects_a_bare_str_for_algs() -> None:
    # `str` satisfies `Sequence[str]`, so this type-checks; joining it would
    # emit algs="E S 2 5 6" and tell the client to sign with algorithms that
    # do not exist. Loud, like the equivalent mistake on `schemes`.
    with pytest.raises(TypeError, match="not a bare str"):
        www_authenticate_challenges(TokenMissingError("no token"), schemes=("DPoP",), algs="ES256")


def test_www_authenticate_challenges_accepts_a_single_algorithm_as_a_sequence() -> None:
    (dpop,) = www_authenticate_challenges(
        TokenMissingError("no token"), schemes=("DPoP",), algs=("ES256",)
    )
    assert 'algs="ES256"' in dpop


def test_www_authenticate_challenges_accepts_schemes_case_insensitively() -> None:
    challenges = www_authenticate_challenges(
        TokenMissingError("no token"), schemes=("bearer", "dpop")
    )
    assert challenges[0].startswith("Bearer ")
    assert challenges[1].startswith("DPoP ")


def test_www_authenticate_challenges_collapses_duplicate_schemes() -> None:
    challenges = www_authenticate_challenges(
        TokenMissingError("no token"), schemes=("DPoP", "dpop", "DPOP")
    )
    assert len(challenges) == 1


def test_www_authenticate_challenges_rejects_an_unsupported_scheme() -> None:
    # The scheme is a bare RFC 7235 token, not a quoted parameter, so it is
    # rejected rather than sanitized into the header.
    with pytest.raises(ValueError, match="Unsupported authentication scheme"):
        www_authenticate_challenges(TokenMissingError("no token"), schemes=("Basic",))


def test_www_authenticate_challenges_rejects_empty_schemes() -> None:
    with pytest.raises(ValueError, match="schemes must be non-empty"):
        www_authenticate_challenges(TokenMissingError("no token"), schemes=())


def test_www_authenticate_challenges_keeps_invalid_dpop_proof_on_the_dpop_challenge() -> None:
    # RFC 9449 §7.1 defines invalid_dpop_proof for the DPoP scheme; a Bearer
    # challenge alongside it must not name a code Bearer does not define.
    bearer, dpop = www_authenticate_challenges(
        DPoPMultipleProofsError("two proofs"), schemes=("Bearer", "DPoP")
    )
    assert 'error="invalid_token"' in bearer
    assert 'error="invalid_dpop_proof"' in dpop


def test_www_authenticate_challenges_maps_insufficient_scope_on_every_scheme() -> None:
    challenges = www_authenticate_challenges(
        InsufficientScopeError("missing 'admin'", required_scopes=("admin",)),
        schemes=("Bearer", "DPoP"),
    )
    for challenge in challenges:
        assert 'error="insufficient_scope"' in challenge
        assert 'scope="admin"' in challenge


def test_www_authenticate_challenges_uses_safe_descriptions_by_default() -> None:
    error = InvalidClaimsError("Token kid 'signing-key-7' not found in JWKS after refresh")
    for challenge in www_authenticate_challenges(error, schemes=("Bearer", "DPoP")):
        assert "signing-key-7" not in challenge
        assert (
            'error_description="The access token is missing or not valid for this resource"'
            in challenge
        )


def test_www_authenticate_challenges_honours_verbose_description() -> None:
    error = InvalidClaimsError("Token kid 'signing-key-7' not found in JWKS after refresh")
    (challenge,) = www_authenticate_challenges(error, schemes=("Bearer",), verbose_description=True)
    assert "signing-key-7" in challenge


def test_www_authenticate_challenges_forwards_resource_metadata_to_every_scheme() -> None:
    url = "https://api.example.com/.well-known/oauth-protected-resource"
    challenges = www_authenticate_challenges(
        TokenMissingError("no token"), schemes=("Bearer", "DPoP"), resource_metadata_url=url
    )
    assert all(f'resource_metadata="{url}"' in challenge for challenge in challenges)


def test_www_authenticate_challenges_are_individually_parseable() -> None:
    # The reason this returns a list rather than a comma-joined string: the
    # comma also separates parameters inside a challenge, so a joined value
    # would be ambiguous. Each element must stand alone as "<scheme> <params>".
    challenges = www_authenticate_challenges(
        TokenMissingError("no token"),
        schemes=("Bearer", "DPoP"),
        realm="api",
        algs=("ES256",),
    )
    for challenge in challenges:
        scheme, _, params = challenge.partition(" ")
        assert scheme in {"Bearer", "DPoP"}
        assert scheme not in params
        # The parameter list is exactly a ", "-joined run of quoted
        # name="value" pairs, with nothing between or around them.
        pairs = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"', params)
        assert ", ".join(f'{name}="{value}"' for name, value in pairs) == params


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
