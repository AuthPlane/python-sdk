"""Exception hierarchy for Authplane SDK.

All exceptions inherit from AuthplaneError for easy catching.
InsufficientScope is distinguishable for 403 HTTP status mapping.
"""

import logging
import re
from collections.abc import Sequence

_LOGGER = logging.getLogger(__name__)

_HEADER_VALUE_UNSAFE = re.compile(r'[\r\n"\\]+')


def _sanitize_header_value(value: str) -> str:
    """Replace CR, LF, double-quote, and backslash with a single space so the
    value cannot break out of a quoted ``WWW-Authenticate`` parameter or inject
    additional header fields. Leading/trailing whitespace is stripped.

    This is a backstop and must not be read as the guarantee for
    ``resource_metadata``. Substituting there was in fact the wrong remedy for
    a configured identifier: the header stayed parseable, but it advertised a
    URL that no longer matched the one a client derives from the identifier
    this SDK also serves as the ``resource`` member of the PRM document, which
    is the RFC 9728 §3.3 mismatch reached by another route — the challenge
    looked fine and discovery failed anyway. A `"` or a `\\` in the **host** of
    a configured resource identifier is now rejected at construction
    (``internal/urls.py``), which is where that defect is worst: a backslash
    there leaves the challenge well-formed and redirects a conformant client to
    a different origin entirely.

    The host is the whole of that guarantee, and the scoping is deliberate
    rather than incidental. The construction gate scans ``parsed.hostname``,
    while ``build_prm_url`` splices the identifier's path and query into the
    derived URL verbatim (RFC 9728 §3.1 inserts the well-known segment
    *between* the host and them, so all three land inside this one
    quoted-string). Measured on 3.12: ``https://api.example.com/m"cp``
    constructs, derives
    ``https://api.example.com/.well-known/oauth-protected-resource/m"cp``, and
    arrives here — where the substitution advertises ``.../m cp``, the same
    RFC 9728 §3.3 mismatch one component over. Same-origin and ending in a
    client-side discard rather than a redirect to another host, which is why
    that axis is a separate decision with its own migration cost and is not
    settled here. Until it is, this function is what stands between a path- or
    query-borne delimiter and the challenge.

    It is kept rather than removed for three reasons, none of which the
    construction gate covers. ``realm`` and ``scope`` pass through here and are
    gated nowhere — they are free-form operator strings. So is
    ``resource_metadata_url`` itself: it is a plain ``str`` parameter of the
    public ``www_authenticate``/``response_headers_for``, and nothing obliges a
    caller to have obtained it from ``AuthplaneResource.prm_url()``. And CR/LF
    here defend against header-field injection, a different hazard from the
    quoted-string one, on values whose provenance this module cannot see.
    """
    return _HEADER_VALUE_UNSAFE.sub(" ", value).strip()


class AuthplaneError(Exception):
    """Base exception for all Authplane SDK errors."""

    pass


class InvalidIssuerError(AuthplaneError, ValueError):
    """Raised when an issuer identifier is not the shape RFC 8414 §2 requires.

    Inherits ``ValueError`` as well as ``AuthplaneError`` so existing
    ``except ValueError`` handlers keep working — the identifier guards raised a
    bare ``ValueError`` before this class existed, and that is a public contract.
    What it adds is the ability to tell *which* ``ValueError``: a configuration
    error on the issuer was previously indistinguishable from, say,
    ``jwks_refresh_seconds must be positive``.

    """

    pass


class InvalidResourceError(AuthplaneError, ValueError):
    """Raised when a resource indicator is not the shape RFC 8707 §2 requires.

    Same additive shape as :class:`InvalidIssuerError`, and for the same reason:
    rejecting a fragment-bearing resource at ``AuthplaneClient.resource(...)`` is
    a behaviour change for a deployment that used to start, and the only way to
    catch it specifically was ``except ValueError`` — which is exactly the
    undiscriminating handler the issuer half of this work set out to improve on.
    Typing one identifier and not the other would have left that half-done.
    """

    pass


class TokenMissingError(AuthplaneError):
    """Raised when no token is provided for validation."""

    pass


class TokenExpiredError(AuthplaneError):
    """Raised when the token has expired (exp claim in the past)."""

    pass


class InvalidSignatureError(AuthplaneError):
    """Raised when the token signature verification fails."""

    pass


class InvalidClaimsError(AuthplaneError):
    """Raised when token claims fail validation (iss, aud, typ, etc.)."""

    pass


class InsufficientScopeError(AuthplaneError):
    """Raised when the token lacks required scopes.

    Maps to HTTP 403 Forbidden, while other AuthplaneError exceptions
    typically map to HTTP 401 Unauthorized. The optional ``required_scopes``
    attribute carries the scopes the caller required so
    :func:`www_authenticate` can emit the RFC 6750 ``scope=`` challenge
    parameter automatically.
    """

    def __init__(self, message: str, *, required_scopes: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.required_scopes = required_scopes


class JWKSFetchError(AuthplaneError):
    """Raised when fetching the JWKS fails and no cache is available."""

    pass


class MetadataFetchError(AuthplaneError):
    """Raised when fetching AS metadata fails and no cache is available."""

    pass


class TokenRevokedError(AuthplaneError):
    """Raised when the token's jti has been identified as revoked.

    Returned by the built-in introspection check (active=false from AS) or
    by a caller-supplied revocation_checker that returns True.

    Maps to HTTP 401 Unauthorized, like other AuthplaneError subclasses.
    """

    pass


class VerifierRuntimeError(AuthplaneError):
    """Raised when verification fails for a non-cryptographic runtime reason."""

    pass


class ProtocolError(AuthplaneError):
    """Raised when an OAuth/OIDC/DPoP protocol message is malformed."""

    pass


class MissingMetadataEndpointError(MetadataFetchError):
    """Raised when required AS metadata endpoint fields are missing."""

    pass


class DPoPError(AuthplaneError):
    """Base exception for DPoP-specific failures."""

    pass


class DPoPProofMissingError(DPoPError):
    """Raised when DPoP verification is requested without a proof."""

    pass


class InvalidDPoPProofError(DPoPError):
    """Raised when a DPoP proof is malformed or fails validation."""

    pass


class DPoPMultipleProofsError(InvalidDPoPProofError):
    """Raised when the inbound request carries more than one ``DPoP`` header
    value (RFC 9449 §4.3 #1).

    Surfaces with WWW-Authenticate ``error="invalid_dpop_proof"`` per
    RFC 9449 §7.1. The other ``DPoPError`` subclasses keep the SDK's
    historical ``invalid_token`` mapping; only this §4.3 cardinality
    violation gets the proof-specific error code.
    """

    pass


class DPoPReplayDetectedError(DPoPError):
    """Raised when a DPoP proof `jti` has already been seen."""

    pass


class DPoPBindingMismatchError(DPoPError):
    """Raised when a DPoP proof key does not match the access token binding."""

    pass


class DPoPNotSupportedError(DPoPError):
    """Raised when a request carries DPoP signals (a bound access token or
    a proof header) but the resource has not been configured to support
    DPoP via ``InboundDPoPOptions``.

    Per RFC 9449 §6, only resource servers that support DPoP are obliged
    to validate the binding; a resource that has not opted in must reject
    DPoP-bearing requests rather than fall back to bearer-only validation
    or apply ad-hoc defaults that were never advertised in PRM.
    """

    pass


# ---------------------------------------------------------------------------
# Auth client errors (token acquisition / AS interactions)
# ---------------------------------------------------------------------------


class AuthError(AuthplaneError):
    """Base for all auth client (token acquisition) errors."""

    def __init__(self, message: str, code: str = "", status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class ConsentRequiredError(AuthError):
    """User interaction/consent is required before token issuance can continue."""

    def __init__(
        self,
        message: str,
        *,
        service_id: str = "unknown_service",
        cause_detail: str = "",
        consent_url: str | None = None,
        code: str = "consent_required",
        status_code: int | None = None,
    ) -> None:
        super().__init__(message, code=code, status_code=status_code)
        self.service_id = service_id
        self.cause_detail = cause_detail or message
        self.consent_url = consent_url

    def describe(self) -> str:
        """Single-line description: ``"<message> (<service_id>: <cause_detail>)"``.

        The defaults match what adapters surfacing this error need: an empty
        ``service_id`` becomes ``"unknown_service"``, and an empty ``cause_detail``
        falls back to ``message`` (already the constructor default). Adapters
        call this instead of formatting locally so every adapter — and any other
        consumer — emits the same human-readable form.
        """
        sid = self.service_id or "unknown_service"
        cause = self.cause_detail or str(self)
        return f"{self} ({sid}: {cause})"


class AccessDeniedError(AuthError):
    """AS refused the request outright (``access_denied``, HTTP 403).

    No RFC section is cited because there is none for this endpoint: RFC 6749
    defines ``access_denied`` at the *authorization* endpoint (§4.1.2.1), and
    neither the token-endpoint list (§5.2) nor RFC 8693 §2.2.2 includes it.
    The code as used here is authserver's token-endpoint extension.

    On a token exchange this is a policy decision, not a consent gap: the
    exchanging client is not in the target Resource's exchange allowlist
    (``policy.exchange.allowed_client_ids`` / ``policy.runtime.client_ids``).
    Re-prompting the user cannot fix it — the operator has to allowlist the
    client on the Resource — which is why it is kept apart from
    :class:`ConsentRequiredError`. Not an outage signal: it never trips the
    circuit breaker.
    """

    pass


class InvalidTargetError(AuthError):
    """The ``resource`` parameter names no granted resource (RFC 8707 §2.2 'invalid_target').

    The AS compares the indicator byte for byte against the resources it
    knows, so a trailing slash or a differing scheme is enough. Not an
    outage signal: it never trips the circuit breaker.
    """

    pass


class InvalidClientError(AuthError):
    """AS rejected the client credentials (RFC 6749 'invalid_client')."""

    pass


class UnauthorizedClientError(AuthError):
    """Client is not authorized for the requested grant type (RFC 6749 'unauthorized_client')."""

    pass


class InvalidScopeError(AuthError):
    """Requested scope is invalid or exceeds what the client may request (RFC 6749 'invalid_scope')."""

    pass


class InvalidGrantError(AuthError):
    """Grant is invalid, expired, or revoked (RFC 6749 'invalid_grant')."""

    pass


class UnsupportedGrantTypeError(AuthError):
    """AS does not support the requested grant type (RFC 6749 'unsupported_grant_type')."""

    pass


class InvalidRequestError(AuthError):
    """Request is malformed or missing required parameters (RFC 6749 'invalid_request')."""

    pass


class ServerError(AuthError):
    """AS returned an internal server error (HTTP 5xx)."""

    pass


class CircuitOpenError(AuthError):
    """Circuit breaker is open; the AS is considered unavailable."""

    pass


# The challenge reaches a caller who by definition has not authenticated, so
# `error_description` is built from the RFC 6750 §3.1 / RFC 9449 §7.1 error
# code, never from the exception message. The SDK's own messages name the
# failing detail — the unknown `kid`, the claim that did not validate, the
# `typ` that was rejected — and an `aud` mismatch in particular would hand the
# caller the exact audience string the resource expects, which is the value
# they would need in order to request a token for it. RFC 6750 §3 does not
# require `error_description` to be diagnostic: the `error` code already
# carries everything a conforming client needs to decide what to do next.
# `_sanitize_header_value` is not a defence here — it prevents header
# injection, not disclosure; a sanitized `kid` is still a `kid`.
#
# The descriptions carry no comma. A comma inside a quoted-string is legal
# RFC 7235, but it is also the separator between challenge parameters and
# between header values, so keeping it out of the one parameter whose text we
# choose leaves nothing for a lenient client-side parser to split on.
_SAFE_ERROR_DESCRIPTIONS: dict[str, str] = {
    "invalid_token": "The access token is missing or not valid for this resource",
    "insufficient_scope": "The access token does not carry the scope this operation requires",
    "invalid_dpop_proof": "The DPoP proof is missing or not valid for this request",
}

# Fallback for an error code added without a matching entry above. Kept
# deliberately contentless for the same reason the table exists.
_FALLBACK_ERROR_DESCRIPTION = "The request could not be authenticated"

# Authentication schemes this SDK can advertise. Unlike the quoted challenge
# parameters, the scheme is a bare RFC 7235 token, so an unrecognized value is
# rejected outright rather than sanitized into the header.
_SUPPORTED_SCHEMES: dict[str, str] = {"bearer": "Bearer", "dpop": "DPoP"}


def _error_code_for(error: AuthplaneError, scheme: str) -> str:
    """Return the RFC 6750 §3.1 error code to advertise for ``error`` under ``scheme``."""
    if isinstance(error, InsufficientScopeError):
        return "insufficient_scope"
    if isinstance(error, DPoPMultipleProofsError) and scheme == "DPoP":
        # RFC 9449 §7.1 prescribes `invalid_dpop_proof` for §4.3
        # cardinality rejections, not the SDK's historical `invalid_token`
        # used by the other `DPoPError` shapes. Scoped to this error;
        # a broader sweep is a separate change. The code is defined for the
        # DPoP scheme, so a Bearer challenge emitted alongside it keeps
        # `invalid_token` rather than naming a code Bearer does not define.
        return "invalid_dpop_proof"
    return "invalid_token"


def _scheme_for(error: AuthplaneError) -> str:
    """Return the single scheme that matches ``error``'s type."""
    return (
        "DPoP"
        if isinstance(error, DPoPError) and not isinstance(error, DPoPNotSupportedError)
        else "Bearer"
    )


def _description_for(error: AuthplaneError, error_code: str, verbose: bool) -> str:
    """Return the `error_description` value to emit for ``error``."""
    if verbose:
        return _sanitize_header_value(str(error))
    return _SAFE_ERROR_DESCRIPTIONS.get(error_code, _FALLBACK_ERROR_DESCRIPTION)


def _normalize_schemes(schemes: Sequence[str]) -> list[str]:
    """Canonicalize and de-duplicate ``schemes``, preserving caller order."""
    normalized: list[str] = []
    for scheme in schemes:
        canonical = _SUPPORTED_SCHEMES.get(scheme.strip().lower())
        if canonical is None:
            raise ValueError(
                f"Unsupported authentication scheme {scheme!r}; "
                f"only {sorted(_SUPPORTED_SCHEMES.values())} can be advertised"
            )
        if canonical not in normalized:
            normalized.append(canonical)
    if not normalized:
        raise ValueError("schemes must be non-empty; omit it to derive the scheme from the error")
    return normalized


def _normalize_algs(algs: Sequence[str] | None) -> tuple[str, ...]:
    """Resolve ``algs`` to the exact set to advertise, rejecting what cannot be.

    Three inputs, three defined meanings:

    * a bare ``str`` — rejected. ``str`` satisfies ``Sequence[str]``, so
      ``algs="ES256"`` type-checks under pyright strict and then ``" ".join``
      iterates it into ``algs="E S 2 5 6"``: a challenge advertising
      algorithms that do not exist, from which a conforming client concludes
      it cannot sign a proof at all. ``schemes`` is protected against the same
      slip by accident (``_normalize_schemes`` rejects ``'B'``).
    * ``None`` — the default set, the same meaning
      :class:`~authplane.dpop.InboundDPoPOptions` gives it. This is what makes
      the documented ``algs=options.allowed_proof_algorithms`` call correct on
      an options object built from defaults, where that attribute *is* ``None``:
      it used to advertise nothing at all, and briefly raised ``TypeError``
      from inside the 401 handler, which turns an unauthenticated request into
      a 500.
    * a sequence — validated, not sanitized. These are bare RFC 7235 tokens,
      the same shape as ``schemes``, so they get the same treatment: an
      unusable value is refused rather than quietly rewritten. Escaping alone
      let a comma through, and a comma is the one character the surrounding
      code works to keep out of parameter text so that a lenient client-side
      parser has nothing to split on.

    An empty sequence stays "omit the parameter", which is the parameter's own
    default and what every caller that does not pass it relies on.
    """
    # Imported here, not at module scope: `dpop` imports this module, so a
    # top-level import would be circular.
    from .dpop import SUPPORTED_DPOP_ALGORITHMS

    if isinstance(algs, str):
        raise TypeError(
            f"algs must be a sequence of algorithm names, not a bare str ({algs!r}); "
            f"pass ({algs!r},) to advertise a single algorithm"
        )
    if algs is None:
        return tuple(SUPPORTED_DPOP_ALGORITHMS)
    normalized = tuple(algs)
    unsupported = [alg for alg in normalized if alg not in SUPPORTED_DPOP_ALGORITHMS]
    if unsupported:
        raise ValueError(
            f"Unsupported DPoP proof algorithms {unsupported!r}; only "
            f"{list(SUPPORTED_DPOP_ALGORITHMS)} can be advertised"
        )
    return normalized


def _build_challenge(
    error: AuthplaneError,
    scheme: str,
    *,
    realm: str,
    resource_metadata_url: str | None,
    scope: Sequence[str] | None,
    algs: Sequence[str],
    verbose_description: bool,
) -> str:
    """Assemble one ``WWW-Authenticate`` header value for a single scheme."""
    error_code = _error_code_for(error, scheme)

    parts: list[str] = []
    if realm:
        parts.append(f'realm="{_sanitize_header_value(realm)}"')
    parts.append(f'error="{error_code}"')
    parts.append(f'error_description="{_description_for(error, error_code, verbose_description)}"')
    if scope:
        parts.append(f'scope="{_sanitize_header_value(" ".join(scope))}"')
    if resource_metadata_url:
        parts.append(f'resource_metadata="{_sanitize_header_value(resource_metadata_url)}"')
    # RFC 9449 §7.1 defines `algs` for the DPoP challenge only, so a Bearer
    # challenge in the same set never carries it.
    if scheme == "DPoP" and algs:
        # No escaping: `_normalize_algs` has already refused anything that is
        # not one of the supported bare tokens, so there is nothing to escape.
        parts.append(f'algs="{" ".join(algs)}"')
    return f"{scheme} " + ", ".join(parts)


def _resolved_scope(error: AuthplaneError, scope: Sequence[str] | None) -> Sequence[str] | None:
    """Fall back to ``InsufficientScopeError.required_scopes`` when no scope was passed."""
    if scope is None and isinstance(error, InsufficientScopeError) and error.required_scopes:
        return list(error.required_scopes)
    return scope


def www_authenticate(
    error: AuthplaneError,
    *,
    realm: str = "",
    resource_metadata_url: str | None = None,
    scope: Sequence[str] | None = None,
    verbose_description: bool = False,
) -> str:
    """Build an RFC 6750 §3 ``WWW-Authenticate`` header value.

    Maps SDK errors to the correct error code and authentication scheme:
    - ``InsufficientScopeError`` → ``insufficient_scope``
    - ``DPoPMultipleProofsError`` → ``DPoP`` scheme with
      ``invalid_dpop_proof`` (RFC 9449 §7.1 prescribes this code for §4.3
      cardinality rejections).
    - Other ``DPoPError`` subclasses (except ``DPoPNotSupportedError``) →
      ``DPoP`` scheme with ``invalid_token``
    - All other ``AuthplaneError`` → ``Bearer`` scheme with ``invalid_token``

    ``error_description`` is a fixed, caller-safe sentence chosen by the error
    code — the exception's own message is never placed on the wire, because the
    challenge is served to a caller who has not authenticated. The message stays
    on the exception for the resource server to log, and is also emitted here at
    ``DEBUG`` on the ``authplane.errors`` logger.

    ``verbose_description=True`` restores the previous behaviour of copying the
    exception message into the challenge. It is a development aid: it discloses
    SDK-internal detail (the unknown ``kid``, the claim that failed, the
    expected audience) to unauthenticated callers, so do not enable it in
    production.

    If ``scope`` is provided (or the error is an :class:`InsufficientScopeError`
    carrying ``required_scopes``), an RFC 6750 §3 ``scope="…"`` challenge
    parameter is included. An explicit ``scope`` argument takes precedence.

    If ``resource_metadata_url`` is provided, the RFC 9728 §5.1
    ``resource_metadata`` challenge parameter is included so clients can
    discover the Protected Resource Metadata document.

    Every interpolated value is sanitized to prevent header injection.

    A resource that accepts more than one scheme — ``inbound_dpop`` in optional
    mode accepts both ``Bearer`` and ``DPoP`` — cannot be described by a single
    header value; use :func:`www_authenticate_challenges` for that.

    Returns:
        A header value like ``Bearer error="invalid_token", error_description="..."``
    """
    scheme = _scheme_for(error)
    if not verbose_description:
        _LOGGER.debug(
            "www_authenticate: %s: %s",
            type(error).__name__,
            error,
            extra={"scheme": scheme, "error_code": _error_code_for(error, scheme)},
        )
    return _build_challenge(
        error,
        scheme,
        realm=realm,
        resource_metadata_url=resource_metadata_url,
        scope=_resolved_scope(error, scope),
        algs=(),
        verbose_description=verbose_description,
    )


def www_authenticate_challenges(
    error: AuthplaneError,
    *,
    schemes: Sequence[str] | None = None,
    algs: Sequence[str] | None = (),
    realm: str = "",
    resource_metadata_url: str | None = None,
    scope: Sequence[str] | None = None,
    verbose_description: bool = False,
) -> list[str]:
    """Build one RFC 6750 §3 challenge per authentication scheme the resource accepts.

    :func:`www_authenticate` picks the scheme from the error's type, so it can
    only ever name one. A resource running ``inbound_dpop`` in optional mode
    accepts both ``Bearer`` and ``DPoP`` and should advertise both, so that a
    DPoP-capable client can discover that sender-constrained tokens are taken
    here (RFC 9449 §7.1; §7.2 covers running the two schemes side by side).

    Two challenges cannot be joined with a comma: the comma is also the
    separator *between parameters inside* a challenge, so the result cannot be
    parsed unambiguously. RFC 7235 §4.1 permits the comma-joined form but
    warns about parsing it, so separate ``WWW-Authenticate`` header values are
    the interoperable choice: this returns a list and the caller emits one header value
    per element::

        for challenge in www_authenticate_challenges(error, schemes=("Bearer", "DPoP")):
            response.headers.add("WWW-Authenticate", challenge)

    Args:
        error: The error the challenge responds to. It selects the error code
            the same way :func:`www_authenticate` does, per scheme:
            ``invalid_dpop_proof`` is DPoP-specific, so a ``Bearer`` challenge
            emitted alongside a DPoP one keeps ``invalid_token``.
        schemes: The schemes to advertise, in the order they should appear.
            ``Bearer`` and ``DPoP`` are recognized, case-insensitively;
            duplicates collapse. Omit it to derive the single scheme from the
            error's type, which returns exactly what
            :func:`www_authenticate` would, in a one-element list.
        algs: JOSE ``alg`` values accepted for DPoP proofs, emitted as the
            RFC 9449 §7.1 ``algs`` parameter on the ``DPoP`` challenge only,
            and ignored when ``DPoP`` is not among ``schemes``. Pass
            ``options.allowed_proof_algorithms`` straight through: ``None``
            there means "the default set", and means the same here, so an
            options object built from defaults advertises the
            algorithms it actually accepts rather than nothing. The default ``()``
            omits the parameter. Values are validated against the supported
            set, so an unusable one raises rather than reaching the wire.
        realm: RFC 7235 ``realm``, emitted on every challenge when non-empty.
        resource_metadata_url: RFC 9728 §5.1 ``resource_metadata``, emitted on
            every challenge when provided.
        scope: RFC 6750 §3 ``scope``, emitted on every challenge. Falls back to
            :attr:`InsufficientScopeError.required_scopes` when not passed.
        verbose_description: Development-only. See :func:`www_authenticate`.

    Returns:
        One header value per scheme, in the order given.

    Raises:
        ValueError: If ``schemes`` is empty or names a scheme this SDK cannot
            advertise.
        TypeError: If ``algs`` is a bare ``str`` rather than a sequence of
            algorithm names.
    """
    resolved_schemes = [_scheme_for(error)] if schemes is None else _normalize_schemes(schemes)
    resolved_algs = _normalize_algs(algs)
    if not verbose_description:
        _LOGGER.debug(
            "www_authenticate_challenges: %s: %s",
            type(error).__name__,
            error,
            extra={"schemes": resolved_schemes},
        )
    resolved_scope = _resolved_scope(error, scope)
    return [
        _build_challenge(
            error,
            scheme,
            realm=realm,
            resource_metadata_url=resource_metadata_url,
            scope=resolved_scope,
            algs=resolved_algs,
            verbose_description=verbose_description,
        )
        for scheme in resolved_schemes
    ]


def http_status(error: AuthplaneError) -> int:
    """Map an AuthplaneError to an HTTP status code.

    Returns:
        403 for InsufficientScopeError.
        503 for JWKSFetchError, MetadataFetchError, and CircuitOpenError
            (the AS is temporarily unable to participate in validation).
        401 for all authentication failures (missing/expired/invalid tokens,
            DPoP errors, revoked tokens).
        500 for internal errors (SSRF, protocol, runtime).
    """
    if isinstance(error, InsufficientScopeError):
        return 403
    if isinstance(error, (JWKSFetchError, MetadataFetchError, CircuitOpenError)):
        return 503
    if isinstance(
        error,
        (
            TokenMissingError,
            TokenExpiredError,
            InvalidSignatureError,
            InvalidClaimsError,
            TokenRevokedError,
            DPoPError,
        ),
    ):
        return 401
    if isinstance(error, (ProtocolError, VerifierRuntimeError)):
        return 500
    return 500


def response_headers_for(
    error: AuthplaneError,
    *,
    realm: str = "",
    resource_metadata_url: str | None = None,
    scope: Sequence[str] | None = None,
    verbose_description: bool = False,
) -> tuple[int, dict[str, str]]:
    """Return ``(status, {"WWW-Authenticate": challenge})`` for an Authplane error.

    One call replaces the parallel use of :func:`http_status` and
    :func:`www_authenticate`. Forwards keyword arguments to
    :func:`www_authenticate` so callers can include ``realm``,
    ``resource_metadata_url``, ``scope``, and ``verbose_description`` without
    re-deriving the mapping.

    A dict holds one value per header name, so this helper is single-scheme by
    construction. A resource advertising both ``Bearer`` and ``DPoP`` pairs
    :func:`http_status` with :func:`www_authenticate_challenges` instead.
    """
    return (
        http_status(error),
        {
            "WWW-Authenticate": www_authenticate(
                error,
                realm=realm,
                resource_metadata_url=resource_metadata_url,
                scope=scope,
                verbose_description=verbose_description,
            )
        },
    )


def map_oauth_error(
    operation: str,
    status_code: int,
    data: dict[str, object],
    endpoint: str,
    duration_ms: int,
) -> AuthError:
    """Map an OAuth error response to an AuthError subclass."""
    import logging

    logger = logging.getLogger(__name__)

    oauth_error = str(data.get("error", ""))
    description = str(data.get("error_description", ""))

    logger.warning(
        "%s: error response",
        operation,
        extra={
            "endpoint": endpoint,
            "http_status": status_code,
            "oauth_error": oauth_error,
            "description": description,
            "duration_ms": duration_ms,
        },
    )

    msg = (
        f"authplane: {operation}: {description}"
        if description
        else f"authplane: {operation}: {oauth_error or f'HTTP {status_code}'}"
    )

    error_map: dict[str, type[AuthError]] = {
        "invalid_client": InvalidClientError,
        "unauthorized_client": UnauthorizedClientError,
        "invalid_scope": InvalidScopeError,
        "invalid_grant": InvalidGrantError,
        "unsupported_grant_type": UnsupportedGrantTypeError,
        "invalid_request": InvalidRequestError,
        "access_denied": AccessDeniedError,
        "invalid_target": InvalidTargetError,
    }

    if status_code >= 500:
        return ServerError(msg, code="server_error", status_code=status_code)

    cls = error_map.get(oauth_error)
    if cls:
        return cls(msg, code=oauth_error, status_code=status_code)

    if oauth_error in {"consent_required", "interaction_required"}:
        consent_url_raw = data.get("consent_url")
        consent_url = consent_url_raw if isinstance(consent_url_raw, str) else None

        service_id = "unknown_service"
        for key in ("service_id", "service", "resource"):
            value = data.get(key)
            if isinstance(value, str) and value:
                service_id = value
                break

        cause_raw = data.get("cause")
        cause_detail = (
            cause_raw if isinstance(cause_raw, str) and cause_raw else description or oauth_error
        )

        return ConsentRequiredError(
            msg,
            service_id=service_id,
            cause_detail=cause_detail,
            consent_url=consent_url,
            code=oauth_error,
            status_code=status_code,
        )

    if status_code == 401:
        return InvalidClientError(msg, code="invalid_client", status_code=401)

    return AuthError(msg, code=oauth_error or "unknown", status_code=status_code)
