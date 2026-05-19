"""AuthplaneTokenVerifier - FastMCP TokenVerifier backed by AuthplaneResource.

Bridges the Authplane core SDK with FastMCP's ``TokenVerifier`` interface,
delegating all JWT validation to ``AuthplaneResource`` and mapping results
to FastMCP's ``AccessToken`` with the full JWT payload in ``claims``.
"""

import logging
from typing import Any, cast

from authplane import AuthplaneError, AuthplaneResource
from fastmcp.server.auth import AccessToken, TokenVerifier

logger = logging.getLogger(__name__)


class AuthplaneTokenVerifier(TokenVerifier):
    """FastMCP TokenVerifier backed by AuthplaneResource.

    Validates JWTs once per request via the core Authplane SDK and returns
    a FastMCP ``AccessToken`` with ``claims`` populated from the full JWT
    payload (``VerifiedClaims.raw``). Token claims are then available in
    tool handlers via FastMCP's native ``CurrentAccessToken()`` dependency
    or ``get_access_token()`` function.

    All security-critical logic (signature verification, claim validation,
    JWKS caching, SSRF protection) is handled by the core SDK. This class
    is a thin adapter that maps between the two interfaces.

    Scope enforcement is FastMCP's responsibility via
    ``@mcp.tool(auth=require_scopes(...))``.
    """

    def __init__(
        self,
        verifier: AuthplaneResource,
        base_url: str | None = None,
        required_scopes: list[str] | None = None,
    ) -> None:
        """Initialize the token verifier.

        Args:
            verifier: A fully initialized ``AuthplaneResource`` instance,
                typically created via ``AuthplaneClient.create()`` and
                ``client.resource()``.
            base_url: The base URL of this server. Passed to the parent
                ``TokenVerifier`` for PRM generation.
            required_scopes: Scopes required for all requests. Passed to
                the parent ``TokenVerifier``.
        """
        super().__init__(base_url=base_url, required_scopes=required_scopes)
        self._verifier = verifier

    @property
    def verifier(self) -> AuthplaneResource:
        """The underlying ``AuthplaneResource`` instance."""
        return self._verifier

    @property
    def scopes_supported(self) -> list[str]:
        """Return scopes supported by this verifier.

        Returns the scopes configured in the ``AuthplaneResource``, which
        are used by FastMCP for PRM metadata generation at
        ``/.well-known/oauth-protected-resource``.
        """
        return list(self._verifier.scopes)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a JWT and return a FastMCP AccessToken.

        Called by FastMCP once per authenticated request. Delegates to
        ``AuthplaneResource.verify()`` for all validation, then maps the
        resulting ``VerifiedClaims`` to a FastMCP ``AccessToken`` with the
        full JWT payload in ``claims``.

        Args:
            token: The raw JWT string (FastMCP strips ``'Bearer '``
                before calling this method).

        Returns:
            ``AccessToken`` on successful validation with ``token``,
            ``client_id``, ``scopes``, ``expires_at``, and ``claims``
            (full JWT payload dict) fields populated. Returns ``None``
            on any validation failure (FastMCP responds with 401).
        """
        try:
            claims = await self._verifier.verify(token)
        except AuthplaneError as error:
            logger.debug(
                "authplane.token_verification_failed",
                extra={"error_class": type(error).__name__, "error": str(error)},
            )
            return None

        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=list(claims.scopes),
            expires_at=claims.expires_at,
            claims=cast("dict[str, Any]", claims.raw),  # full JWT payload
        )
