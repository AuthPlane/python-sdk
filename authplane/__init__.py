"""Authplane Python SDK — OAuth 2.1 JWT validation and token operations for protected resources."""

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("authplane-sdk")
except _PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.0.0+unknown"

# Client
# Authentication
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
    AuthError,
    AuthplaneError,
    CircuitOpenError,
    ConsentRequiredError,
    DPoPBindingMismatchError,
    DPoPError,
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
    "InvalidRequestError",
    "InvalidScopeError",
    "InvalidSignatureError",
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
    "http_status",
    "response_headers_for",
    "www_authenticate",
]
