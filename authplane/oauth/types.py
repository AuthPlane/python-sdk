"""OAuth protocol types and constants."""

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Introspection-based revocation marker (sentinel)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntrospectionRevocation:
    """Marker that triggers RFC 7662 introspection-based revocation checking.

    Pass an instance to ``AuthplaneClient.resource(revocation_checker=...)``
    to enable fail-open introspection checking for every ``verify()`` call.
    """


# ---------------------------------------------------------------------------
# RFC 8693 constants
# ---------------------------------------------------------------------------

GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


# ---------------------------------------------------------------------------
# Token Exchange
# ---------------------------------------------------------------------------


@dataclass
class TokenExchangeOptions:
    """Options for an RFC 8693 token exchange request."""

    subject_token: str
    subject_token_type: str = ""
    actor_token: str = ""
    actor_token_type: str = ""
    scope: str = ""
    resources: tuple[str, ...] = ()
    audiences: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.resources = tuple(v for v in self.resources if v)
        self.audiences = tuple(v for v in self.audiences if v)


# ---------------------------------------------------------------------------
# Token Response (shared by client_credentials and token_exchange)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenResponse:
    """Response from token endpoint."""

    access_token: str
    token_type: str
    # ``expires_in`` is tri-state so the wire shape ``expires_in: 0``
    # (RFC 6749 §5.1 — a deliberately-expired one-shot token) is
    # distinguishable from the field being absent. Cache callers honor
    # the AS's intent: ``None`` ⇒ apply the default TTL; ``0`` ⇒ refuse
    # to store.
    expires_in: int | None
    scope: str
    refresh_token: str = ""
    issued_token_type: str = ""
    cnf_jkt: str = ""


# ---------------------------------------------------------------------------
# Introspection Response (RFC 7662)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntrospectionResponse:
    """Response from introspection endpoint (RFC 7662)."""

    active: bool
    scope: str = ""
    client_id: str = ""
    sub: str = ""
    token_type: str = ""
    iss: str = ""
    aud: str | list[str] | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str = ""
    # Authplane extensions
    agent_id: str = ""
    agent_chain: tuple[str, ...] = field(default_factory=tuple)
