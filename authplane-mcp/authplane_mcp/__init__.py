"""Authplane Python SDK - MCP adapter.

This package provides a thin adapter between the Authplane Python SDK and the
official Model Context Protocol (MCP) Python SDK, enabling MCP servers to
validate Authplane-issued JWT access tokens.

Core SDK types (``ASCredentials``, ``FetchSettings``, ``IntrospectionRevocation``,
DPoP types, errors, etc.) are imported from ``authplane`` directly. This package
exports only the adapter-owned glue.
"""

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("authplane-mcp")
except _PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.0.0+unknown"

from .auth import AuthplaneAuthResult, authplane_mcp_auth, require_scope
from .url_elicitation import to_url_elicitation_required_error
from .verifier import AuthplaneTokenVerifier

__all__ = [
    "AuthplaneAuthResult",
    "AuthplaneTokenVerifier",
    "__version__",
    "authplane_mcp_auth",
    "require_scope",
    "to_url_elicitation_required_error",
]
