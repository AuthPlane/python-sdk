"""AuthplaneTokenVerifier - MCP SDK TokenVerifier backed by AuthplaneResource.

Bridges the Authplane core SDK with the official MCP Python SDK's
``TokenVerifier`` interface, delegating all JWT validation to
``AuthplaneResource`` and mapping results to MCP's ``AccessToken``.
"""

import logging

from authplane import AuthplaneError, AuthplaneResource
from mcp.server.auth.provider import AccessToken, TokenVerifier

logger = logging.getLogger(__name__)


class AuthplaneTokenVerifier(TokenVerifier):
    """MCP SDK TokenVerifier backed by AuthplaneResource.

    Validates JWTs once per request via the core Authplane SDK and returns
    an MCP ``AccessToken`` populated with standard OAuth 2.1 claims
    (``client_id``, ``scopes``, ``expires_at``, ``resource``).

    All security-critical logic (signature verification, claim validation,
    JWKS caching, SSRF protection) is handled by the core SDK. This class
    is a thin adapter that maps between the two interfaces.
    """

    def __init__(self, verifier: AuthplaneResource) -> None:
        """Initialize the token verifier.

        Args:
            verifier: A fully initialized ``AuthplaneResource`` instance,
                typically created via ``AuthplaneClient.create()`` and
                ``client.resource()``.
        """
        self._verifier = verifier

    @property
    def verifier(self) -> AuthplaneResource:
        """The underlying ``AuthplaneResource`` instance."""
        return self._verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a JWT and return an MCP AccessToken.

        Called by the MCP server once per authenticated request. Delegates
        to ``AuthplaneResource.verify()`` for all validation, then maps the
        resulting ``VerifiedClaims`` to an MCP ``AccessToken``.

        Args:
            token: The raw JWT string (the server strips ``'Bearer '``
                before calling this method).

        Returns:
            ``AccessToken`` on successful validation with ``token``,
            ``client_id``, ``scopes``, ``expires_at``, and ``resource``
            fields populated. Returns ``None`` on any validation failure
            (the MCP server responds with 401).
        """
        try:
            claims = await self._verifier.verify(token)
        except AuthplaneError as error:
            logger.debug(
                "authplane.token_verification_failed",
                extra={"error_class": type(error).__name__, "error": str(error)},
            )
            return None

        # AccessToken.resource must be a string. Since audience is a list,
        # take the first one (standard JWT behavior when multiple audiences are present).
        resource = claims.audience[0]

        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=list(claims.scopes),
            expires_at=claims.expires_at,
            resource=str(resource),
        )
