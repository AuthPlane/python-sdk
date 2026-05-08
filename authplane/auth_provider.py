"""AuthProvider protocol — pluggable authentication for OAuth operations."""

from typing import Protocol, runtime_checkable

from .net.http import build_basic_auth_header


@runtime_checkable
class AuthProvider(Protocol):
    """Protocol for providing authentication headers to OAuth endpoints.

    Implementations return the headers dict (e.g. ``{"Authorization": "Basic ..."}``).
    """

    def auth_headers(self) -> dict[str, str]:
        """Return HTTP headers for authenticating to the AS."""
        ...


class ClientCredentialsProvider:
    """HTTP Basic Auth from client_id + client_secret (RFC 6749 §2.3.1)."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        self._headers = build_basic_auth_header(client_id, client_secret)

    def auth_headers(self) -> dict[str, str]:
        """Return Basic auth headers built from client_id and client_secret."""
        return self._headers
