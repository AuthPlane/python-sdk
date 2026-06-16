"""Tests for VerifiedClaims dataclass."""

from collections.abc import Iterator
from types import MappingProxyType

import pytest

from authplane.errors import InsufficientScopeError
from authplane.verifier.claims import VerifiedClaims, freeze_value


@pytest.fixture
def sample_claims() -> VerifiedClaims:
    """Sample VerifiedClaims for testing."""
    return VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=("read:data", "write:data"),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=freeze_value(
            {
                "sub": "user123",
                "client_id": "client456",
                "scope": "read:data write:data",
                "iss": "https://auth.example.com",
                "aud": "https://api.example.com",
                "exp": 1234567890,
                "iat": 1234567800,
                "jti": "token-id-123",
                "custom_claim": "custom_value",
            }
        ),
    )


def test_has_scope_granted(sample_claims: VerifiedClaims) -> None:
    """has_scope should return True for granted scopes."""
    assert sample_claims.has_scope("read:data") is True
    assert sample_claims.has_scope("write:data") is True


def test_has_scope_missing(sample_claims: VerifiedClaims) -> None:
    """has_scope should return False for missing scopes."""
    assert sample_claims.has_scope("admin") is False
    assert sample_claims.has_scope("delete:data") is False


def test_require_scope_success(sample_claims: VerifiedClaims) -> None:
    """require_scope should not raise for granted scopes."""
    sample_claims.require_scope("read:data")
    sample_claims.require_scope("write:data")
    # No exception raised


def test_require_scope_failure(sample_claims: VerifiedClaims) -> None:
    """require_scope should raise InsufficientScopeError for missing scopes."""
    with pytest.raises(InsufficientScopeError) as exc_info:
        sample_claims.require_scope("admin")

    assert "admin" in str(exc_info.value)
    assert "read:data" in str(exc_info.value)  # Shows granted scopes


def test_require_scopes_empty_is_noop(sample_claims: VerifiedClaims) -> None:
    """Empty input must not raise — callers need not special-case empty iterables."""
    sample_claims.require_scopes([])
    sample_claims.require_scopes(())
    # Generator input also counts as empty.
    empty_gen: list[str] = []
    sample_claims.require_scopes(s for s in empty_gen)


def test_require_scopes_all_present(sample_claims: VerifiedClaims) -> None:
    """All-present input must not raise."""
    sample_claims.require_scopes(["read:data", "write:data"])


def test_require_scopes_consumes_non_empty_generator(
    sample_claims: VerifiedClaims,
) -> None:
    """A non-empty single-use generator must be materialised once and used in
    both the cardinality check and the failure-path ``required_scopes`` field.

    Pins the ``tuple(scopes)`` snapshot in the implementation — without it,
    iterating the generator twice (once to find missing, once to populate the
    error) would silently exhaust the second pass.
    """

    def gen() -> Iterator[str]:
        yield "read:data"
        yield "admin"

    with pytest.raises(InsufficientScopeError) as exc_info:
        sample_claims.require_scopes(gen())

    # The generator's `admin` value must surface in both the message and the
    # structured ``required_scopes`` tuple — proves materialisation happened
    # before the second iteration.
    assert "'admin'" in str(exc_info.value)
    assert exc_info.value.required_scopes == ("read:data", "admin")


def test_require_scopes_single_missing(sample_claims: VerifiedClaims) -> None:
    """A single missing scope renders as ``required scope '<name>'``."""
    with pytest.raises(InsufficientScopeError) as exc_info:
        sample_claims.require_scopes(["read:data", "admin"])

    msg = str(exc_info.value)
    assert "'admin'" in msg
    # Singular "scope" form for one missing entry.
    assert "required scope " in msg
    assert "required scopes " not in msg
    # Surfaces the token's available scopes for the operator.
    assert "read:data" in msg
    # ``required_scopes`` carries the FULL requested tuple, not just missing.
    assert exc_info.value.required_scopes == ("read:data", "admin")


def test_require_scopes_multiple_missing(sample_claims: VerifiedClaims) -> None:
    """Multiple missing scopes render as ``required scopes 'a', 'b'`` (plural)."""
    with pytest.raises(InsufficientScopeError) as exc_info:
        sample_claims.require_scopes(["delete:data", "admin"])

    msg = str(exc_info.value)
    assert "'delete:data'" in msg
    assert "'admin'" in msg
    # Plural form.
    assert "required scopes " in msg
    assert exc_info.value.required_scopes == ("delete:data", "admin")


def test_require_scopes_no_scopes_token() -> None:
    """A token without scopes renders ``Token has scopes: (none)`` so an operator can tell
    the difference between 'wrong scope' and 'no scopes at all'."""
    no_scope_claims = VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=(),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=freeze_value({"sub": "user123"}),
    )
    with pytest.raises(InsufficientScopeError) as exc_info:
        no_scope_claims.require_scopes(["read:data"])

    assert "(none)" in str(exc_info.value)


def test_require_scope_no_scopes_token_matches_plural_rendering() -> None:
    """``require_scope`` (singular) renders an empty scope set the same way the
    plural helper does — ``(none)`` rather than ``[]`` — so the two errors are
    indistinguishable to an operator reading the WWW-Authenticate text."""
    no_scope_claims = VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=(),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=freeze_value({"sub": "user123"}),
    )
    with pytest.raises(InsufficientScopeError) as exc_info:
        no_scope_claims.require_scope("read:data")

    msg = str(exc_info.value)
    assert "(none)" in msg
    # Negative pin: must not regress to the old `[]` rendering.
    assert "Token has scopes: []" not in msg


def test_has_claim_key_only(sample_claims: VerifiedClaims) -> None:
    """has_claim should check key existence when value not provided."""
    assert sample_claims.has_claim("sub") is True
    assert sample_claims.has_claim("custom_claim") is True
    assert sample_claims.has_claim("nonexistent") is False


def test_has_claim_key_and_value(sample_claims: VerifiedClaims) -> None:
    """has_claim should check key and value when value provided."""
    assert sample_claims.has_claim("sub", "user123") is True
    assert sample_claims.has_claim("sub", "other_user") is False
    assert sample_claims.has_claim("custom_claim", "custom_value") is True


def test_has_claim_missing_key(sample_claims: VerifiedClaims) -> None:
    """has_claim should return False for missing keys."""
    assert sample_claims.has_claim("missing_key", "any_value") is False


def test_has_claim_can_match_none_value() -> None:
    """has_claim should distinguish an explicit null from a missing key."""
    claims = VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=(),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=freeze_value({"nullable_claim": None}),
    )

    assert claims.has_claim("nullable_claim") is True
    assert claims.has_claim("nullable_claim", None) is True


def test_scopes_always_tuple() -> None:
    """Scopes should always be a tuple, even for single scope."""
    claims = VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=("single_scope",),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=MappingProxyType({}),
    )

    assert isinstance(claims.scopes, tuple)
    assert claims.scopes == ("single_scope",)


def test_scopes_empty_tuple() -> None:
    """Scopes can be empty."""
    claims = VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=(),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=MappingProxyType({}),
    )

    assert isinstance(claims.scopes, tuple)
    assert claims.scopes == ()
    assert claims.has_scope("any_scope") is False


def test_immutability() -> None:
    """VerifiedClaims should be immutable (frozen dataclass)."""
    claims = VerifiedClaims(
        sub="user123",
        client_id="client456",
        scopes=("read:data",),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=1234567890,
        issued_at=1234567800,
        jti="token-id-123",
        kid="test-key-1",
        raw=MappingProxyType({}),
    )

    # Should not be able to modify attributes
    with pytest.raises(AttributeError):
        claims.sub = "other_user"  # pyright: ignore[reportAttributeAccessIssue]

    with pytest.raises(AttributeError):
        claims.scopes = ("admin",)  # pyright: ignore[reportAttributeAccessIssue]


def test_act_claim_present() -> None:
    """act property returns the 'act' dict when present in raw claims."""
    claims = VerifiedClaims(
        sub="u",
        client_id="c",
        scopes=(),
        issuer="i",
        audience=("a",),
        expires_at=0,
        issued_at=0,
        jti="j",
        kid="k",
        raw=freeze_value({"act": {"sub": "agent-123"}}),
    )
    assert claims.act == {"sub": "agent-123"}


def test_act_claim_absent() -> None:
    """act property returns None when 'act' is not in raw claims."""
    claims = VerifiedClaims(
        sub="u",
        client_id="c",
        scopes=(),
        issuer="i",
        audience=("a",),
        expires_at=0,
        issued_at=0,
        jti="j",
        kid="k",
        raw=MappingProxyType({}),
    )
    assert claims.act is None


def test_act_claim_not_a_dict() -> None:
    """act property returns None when 'act' is not a dict."""
    claims = VerifiedClaims(
        sub="u",
        client_id="c",
        scopes=(),
        issuer="i",
        audience=("a",),
        expires_at=0,
        issued_at=0,
        jti="j",
        kid="k",
        raw=freeze_value({"act": "invalid"}),
    )
    assert claims.act is None


def test_may_act_claim_present() -> None:
    """may_act property returns the 'may_act' dict when present in raw claims."""
    claims = VerifiedClaims(
        sub="u",
        client_id="c",
        scopes=(),
        issuer="i",
        audience=("a",),
        expires_at=0,
        issued_at=0,
        jti="j",
        kid="k",
        raw=freeze_value({"may_act": {"sub": "allowed-agent"}}),
    )
    assert claims.may_act == {"sub": "allowed-agent"}


def test_may_act_claim_absent() -> None:
    """may_act property returns None when 'may_act' is not in raw claims."""
    claims = VerifiedClaims(
        sub="u",
        client_id="c",
        scopes=(),
        issuer="i",
        audience=("a",),
        expires_at=0,
        issued_at=0,
        jti="j",
        kid="k",
        raw=MappingProxyType({}),
    )
    assert claims.may_act is None
