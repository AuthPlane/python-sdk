"""Exception hierarchy for Authplane SDK.

All exceptions inherit from AuthplaneError for easy catching.
InsufficientScope is distinguishable for 403 HTTP status mapping.
"""

import re

_HEADER_VALUE_UNSAFE = re.compile(r'[\r\n"\\]+')


def _sanitize_header_value(value: str) -> str:
    """Replace CR, LF, double-quote, and backslash with a single space so the
    value cannot break out of a quoted ``WWW-Authenticate`` parameter or inject
    additional header fields. Leading/trailing whitespace is stripped.
    """
    return _HEADER_VALUE_UNSAFE.sub(" ", value).strip()


class AuthplaneError(Exception):
    """Base exception for all Authplane SDK errors."""

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


def www_authenticate(
    error: AuthplaneError,
    *,
    realm: str = "",
    resource_metadata_url: str | None = None,
    scope: list[str] | None = None,
) -> str:
    """Build an RFC 6750 §3 ``WWW-Authenticate`` header value.

    Maps SDK errors to the correct error code and authentication scheme:
    - ``InsufficientScopeError`` → ``insufficient_scope``
    - ``DPoPError`` subclasses (except ``DPoPNotSupportedError``) → ``DPoP``
      scheme with ``invalid_token``
    - All other ``AuthplaneError`` → ``Bearer`` scheme with ``invalid_token``

    If ``scope`` is provided (or the error is an :class:`InsufficientScopeError`
    carrying ``required_scopes``), an RFC 6750 §3 ``scope="…"`` challenge
    parameter is included. An explicit ``scope`` argument takes precedence.

    If ``resource_metadata_url`` is provided, the RFC 9728 §5.1
    ``resource_metadata`` challenge parameter is included so clients can
    discover the Protected Resource Metadata document.

    Every interpolated value is sanitized to prevent header injection.

    Returns:
        A header value like ``Bearer error="invalid_token", error_description="..."``
    """
    if isinstance(error, InsufficientScopeError):
        error_code = "insufficient_scope"
    else:
        error_code = "invalid_token"

    scheme = (
        "DPoP"
        if isinstance(error, DPoPError) and not isinstance(error, DPoPNotSupportedError)
        else "Bearer"
    )

    if scope is None and isinstance(error, InsufficientScopeError) and error.required_scopes:
        scope = list(error.required_scopes)

    parts: list[str] = []
    if realm:
        parts.append(f'realm="{_sanitize_header_value(realm)}"')
    parts.append(f'error="{error_code}"')
    parts.append(f'error_description="{_sanitize_header_value(str(error))}"')
    if scope:
        parts.append(f'scope="{_sanitize_header_value(" ".join(scope))}"')
    if resource_metadata_url:
        parts.append(f'resource_metadata="{_sanitize_header_value(resource_metadata_url)}"')
    return f"{scheme} " + ", ".join(parts)


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
    scope: list[str] | None = None,
) -> tuple[int, dict[str, str]]:
    """Return ``(status, {"WWW-Authenticate": challenge})`` for an Authplane error.

    One call replaces the parallel use of :func:`http_status` and
    :func:`www_authenticate`. Forwards keyword arguments to
    :func:`www_authenticate` so callers can include ``realm``,
    ``resource_metadata_url``, and ``scope`` without re-deriving the mapping.
    """
    return (
        http_status(error),
        {
            "WWW-Authenticate": www_authenticate(
                error,
                realm=realm,
                resource_metadata_url=resource_metadata_url,
                scope=scope,
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
