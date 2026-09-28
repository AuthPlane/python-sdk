"""OAuth protocol types and constants."""

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

# ---------------------------------------------------------------------------
# Introspection-based revocation marker (sentinel)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntrospectionRevocation:
    """Marker that triggers RFC 7662 introspection-based revocation checking.

    Pass an instance to ``AuthplaneClient.resource(revocation_checker=...)``
    to introspect the token at the AS after local JWT verification, on
    every ``verify()`` call.

    **An introspection error lets the token through.** Pass
    ``fail_closed=True`` alongside this marker to refuse it instead. The
    two directions trade different things away, and neither is safe in the
    abstract:

    * **Fail-open** (the default) keeps the resource server serving when the
      AS is unreachable — which is what local JWT validation exists for — at
      the cost of honouring a token that may already have been revoked, for
      as long as the outage lasts.
    * **Fail-closed** (``fail_closed=True``) never honours a token it could
      not confirm, at the cost of taking the resource server down with the
      introspection endpoint.

    Pick fail-closed when an unconfirmed token would authorise something you
    cannot take back — writes, payments, executing statements on the
    caller's behalf. Pick the default when availability during an AS outage
    matters more than closing the revocation window.
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


# ---------------------------------------------------------------------------
# Startup diagnostics shared by the client factory and the resource gate
# ---------------------------------------------------------------------------

logger = logging.getLogger("authplane.client")


class _AuthCapableClient(Protocol):
    @property
    def can_authenticate(self) -> bool: ...


def warn_unauthenticated_introspection(
    client: "_AuthCapableClient",
    revocation_checker: Any,
    resource: str,
) -> None:
    """Warn when introspection is configured on a client with no AS credentials.

    Unauthenticated introspection is not an error path — the AS answers 200 —
    so nothing downstream will flag it. authserver >= 0.1.2 answers
    ``active: false`` unless the caller is the issuing client or a
    runtime-client of the Resource in ``aud``, and a checker that cannot
    authenticate therefore rejects every token as revoked. Not rejected
    outright because the unauthenticated request is a documented RFC 7662
    shape other servers accept; said once, at startup, where the operator who
    omitted ``auth=`` will see it.
    """
    if isinstance(revocation_checker, IntrospectionRevocation) and not client.can_authenticate:
        logger.warning(
            "IntrospectionRevocation configured without AS credentials: authserver "
            ">= 0.1.2 answers active=false to unauthenticated introspection, so every "
            "token will be rejected as revoked. Pass auth=ASCredentials(...) to "
            "AuthplaneClient.create() for a confidential client that is the issuing "
            "client or a runtime-client of this resource",
            extra={"resource": resource},
        )
