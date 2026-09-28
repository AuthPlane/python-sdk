"""Authplane Python SDK — OAuth 2.1 JWT validation and token operations for protected resources."""

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("authplane-sdk")
except _PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.0.0+unknown"

# Client
# Authentication
# Raw-ASGI glue. Supported API, unlike the rest of `_dpop_adapter`: these three
# exist for third-party middleware that cannot run under Starlette's
# `BaseHTTPMiddleware` (its response queue stalls a long-lived
# `text/event-stream` body), so the consumer is outside this repository. Leaving
# them reachable only as `authplane._dpop_adapter` would make the sole way to
# use them a private-module import on a `0.x` package, where a rename in a patch
# release breaks an installed resource server at import time — the same hazard
# that promoted `validate_prm_resource_identifier` to this module.
from ._dpop_adapter import (
    get_or_create_verify_cache_from_scope,
    raw_request_path_from_scope,
    read_dpop_header_from_scope,
)
from .auth_provider import AuthProvider, ClientCredentialsProvider
from .cache import TokenCache
from .client import AuthplaneClient
from .credentials import ASCredentials
from .dpop import (
    SUPPORTED_DPOP_ALGORITHMS,
    DPoPKeyMaterial,
    DPoPNonceStore,
    DPoPProvider,
    DPoPReplayStore,
    DPoPRequestContext,
    InboundDPoPOptions,
    InMemoryDPoPNonceStore,
    InMemoryDPoPReplayStore,
)
from .dpop_verification import VerifiedDPoPProof

# Errors (base + the one that changes HTTP status)
from .errors import (
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
    InvalidIssuerError,
    InvalidRequestError,
    InvalidResourceError,
    InvalidScopeError,
    InvalidSignatureError,
    InvalidTargetError,
    JWKSFetchError,
    MetadataFetchError,
    MissingMetadataEndpointError,
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
    www_authenticate_challenges,
)

# Identifier validation. The construction-time gate itself — re-exported
# because the MCP adapters call it before AuthplaneClient.create(), which makes
# it part of their contract with the core SDK: a public name cannot be moved or
# renamed without a deprecation cycle, where an `authplane.internal` path could
# break an installed adapter/core pair at import time with no resolver signal.
#
# "prm_resource_identifier", not "resource_indicator": the gate requires a host,
# which RFC 8707 §2 does not — that section requires an absolute URI (RFC 3986
# §4.3), which `urn:example:api` is. The host requirement is RFC 9728 §3's and
# binds a resource that publishes PRM. Since the same deprecation cycle would
# apply to a wrong name, it is worth spending the accuracy before the first
# release that carries it.
#
# ``validate_issuer_identifier`` is exported for the same reason and alongside
# it, rather than left reachable only as ``authplane.internal``. ``build_prm``
# is public and now raises ``InvalidIssuerError``, and that class is exported
# from here — so without the predicate a consumer who wants to check its
# configuration before constructing anything has the error but no way to
# provoke it except by calling a builder, or by importing a private module on a
# ``0.x`` package. The pair is also the thing to keep symmetric: one identifier
# with a public gate and one without is how the two drifted apart in the first
# place.
#
# ``validate_resource_metadata_url`` joins them for the third operator-supplied
# URL the SDK gates at construction: the ``resource_metadata_url`` override on
# ``AuthplaneClient.resource(...)``. The MCP adapters check it ahead of
# ``AuthplaneClient.create()``, through this public name, for the same reason
# they check the resource identifier there.
from .internal.urls import (
    validate_issuer_identifier,
    validate_prm_resource_identifier,
    validate_resource_metadata_url,
)

# Configuration
from .net import FetchSettings
from .oauth.types import IntrospectionRevocation

# Resource (verifier)
from .verifier import AuthplaneResource, VerifiedClaims
from .verifier.verifier import RevocationChecker

__all__ = [
    "SUPPORTED_DPOP_ALGORITHMS",
    "ASCredentials",
    "AccessDeniedError",
    "AuthError",
    "AuthProvider",
    "AuthplaneClient",
    "AuthplaneError",
    "AuthplaneResource",
    "CircuitOpenError",
    "ClientCredentialsProvider",
    "ConsentRequiredError",
    "DPoPBindingMismatchError",
    "DPoPError",
    "DPoPKeyMaterial",
    "DPoPMultipleProofsError",
    "DPoPNonceStore",
    "DPoPNotSupportedError",
    "DPoPProofMissingError",
    "DPoPProvider",
    "DPoPReplayDetectedError",
    "DPoPReplayStore",
    "DPoPRequestContext",
    "FetchSettings",
    "InMemoryDPoPNonceStore",
    "InMemoryDPoPReplayStore",
    "InboundDPoPOptions",
    "InsufficientScopeError",
    "IntrospectionRevocation",
    "InvalidClaimsError",
    "InvalidClientError",
    "InvalidDPoPProofError",
    "InvalidGrantError",
    "InvalidIssuerError",
    "InvalidRequestError",
    "InvalidResourceError",
    "InvalidScopeError",
    "InvalidSignatureError",
    "InvalidTargetError",
    "JWKSFetchError",
    "MetadataFetchError",
    "MissingMetadataEndpointError",
    "ProtocolError",
    "RevocationChecker",
    "ServerError",
    "TokenCache",
    "TokenExpiredError",
    "TokenMissingError",
    "TokenRevokedError",
    "UnauthorizedClientError",
    "UnsupportedGrantTypeError",
    "VerifiedClaims",
    "VerifiedDPoPProof",
    "VerifierRuntimeError",
    "__version__",
    "get_or_create_verify_cache_from_scope",
    "http_status",
    "raw_request_path_from_scope",
    "read_dpop_header_from_scope",
    "response_headers_for",
    "validate_issuer_identifier",
    "validate_prm_resource_identifier",
    "validate_resource_metadata_url",
    "www_authenticate",
    "www_authenticate_challenges",
]
