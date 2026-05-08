"""Authplane Python SDK - FastMCP adapter.

This package provides a thin adapter between the Authplane Python SDK and FastMCP,
enabling FastMCP servers to validate Authplane-issued JWT access tokens.

Core SDK types (``ASCredentials``, ``FetchSettings``, ``IntrospectionRevocation``,
DPoP types, errors, etc.) are imported from ``authplane`` directly. This package
exports only the adapter-owned glue.
"""

__version__ = "0.1.0"

from .auth import AuthplaneAuthResult, authplane_auth
from .url_elicitation import to_url_elicitation_required_error
from .verifier import AuthplaneTokenVerifier

__all__ = [
    "AuthplaneAuthResult",
    "AuthplaneTokenVerifier",
    "__version__",
    "authplane_auth",
    "to_url_elicitation_required_error",
]
