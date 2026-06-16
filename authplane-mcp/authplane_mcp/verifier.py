"""AuthplaneTokenVerifier - MCP SDK TokenVerifier backed by AuthplaneResource.

Bridges the Authplane core SDK with the official MCP Python SDK's
``TokenVerifier`` interface, delegating all JWT validation to
``AuthplaneResource`` and mapping results to MCP's ``AccessToken``.
"""

import asyncio
import logging
from collections.abc import Callable
from urllib.parse import urlsplit

from authplane import AuthplaneError, AuthplaneResource, DPoPRequestContext
from authplane._dpop_adapter import (
    BuiltDPoPRequestContext,
    get_or_create_verify_cache,
    raw_request_path,
    read_dpop_header,
)
from mcp.server.auth.provider import AccessToken, TokenVerifier
from starlette.requests import Request

from ._request_context import get_current_request as _default_get_http_request

logger = logging.getLogger(__name__)


__all__ = ["AuthplaneTokenVerifier"]


class AuthplaneTokenVerifier(TokenVerifier):
    """MCP SDK TokenVerifier backed by AuthplaneResource.

    Validates JWTs once per request via the core Authplane SDK and returns
    an MCP ``AccessToken`` populated with standard OAuth 2.1 claims
    (``client_id``, ``scopes``, ``expires_at``, ``resource``). All
    security-critical logic (signature verification, claim validation,
    JWKS caching, SSRF protection) is handled by the core SDK; this class
    is a thin adapter that maps between the two interfaces.

    DPoP (RFC 9449)
    ---------------

    When the underlying :class:`AuthplaneResource` was created with
    ``inbound_dpop=InboundDPoPOptions(...)``, this verifier pulls the
    active HTTP request via :func:`get_current_request` (populated by
    :class:`AuthplaneRequestContextMiddleware`), builds a
    :class:`~authplane.DPoPRequestContext` (method + reconstructed
    ``htu`` + proof header), and forwards it to
    :meth:`AuthplaneResource.verify`. The ``htu`` origin
    (scheme + host + port) is taken from the operator-configured
    resource URI, never from the inbound ``Host`` /
    ``X-Forwarded-Proto`` headers — letting an upstream decide which
    ``htu`` the proof is checked against would neuter DPoP's
    cross-endpoint anti-replay. Only the path varies per call.

    The MCP SDK ships no per-request dependency analogous to
    FastMCP's ``get_http_request()``, so the adapter installs a small
    ASGI middleware (:class:`AuthplaneRequestContextMiddleware`) that
    publishes the active :class:`starlette.requests.Request` on a
    ContextVar before MCP's ``AuthenticationMiddleware`` runs. Call
    :func:`authplane_mcp.install_request_context` on your ``FastMCP``
    instance to wire that middleware in — otherwise
    :func:`get_current_request` raises, the verifier passes
    ``dpop_request=None``, and DPoP-bound requests fail closed
    (``DPoPBindingMismatchError``). Bearer-only tokens are likewise
    rejected when the resource is configured with
    ``inbound_dpop=InboundDPoPOptions(required=True)``. The
    misconfiguration surfaces as a 401, not as a silent bypass.

    Per-request verify cache
    ------------------------

    MCP's standard HTTP stack invokes ``verify_token`` exactly once per
    request (Starlette ``AuthenticationMiddleware`` →
    ``BearerAuthBackend`` → ``TokenVerifier.verify_token``). The first
    call's in-flight verify task is stashed on ``request.state`` keyed by
    the access token; any subsequent invocation within the same request
    awaits the same task instead of re-entering the inbound DPoP replay
    store. The cache is defensive: it mirrors the TS adapter's
    ``AsyncLocalStorage`` pattern and pre-empts a class of regressions
    where a future framework change (transport rewrite, custom auth
    provider, ASGI wrapper) would silently double-call ``verify_token``
    and the second call's proof would be rejected as
    ``DPoPReplayDetected``. Different requests get distinct
    ``request.state`` objects so cross-request replay protection is
    preserved.
    """

    def __init__(
        self,
        verifier: AuthplaneResource,
        *,
        get_http_request: Callable[[], Request] | None = None,
    ) -> None:
        """Initialize the token verifier.

        Args:
            verifier: A fully initialized ``AuthplaneResource`` instance,
                typically created via ``AuthplaneClient.create()`` and
                ``client.resource()``.
            get_http_request: Override for the active-request lookup
                (defaults to :func:`get_current_request`, which reads the
                ContextVar set by
                :class:`AuthplaneRequestContextMiddleware`). Tests inject
                a fake to drive the DPoP / per-request-cache paths
                without spinning up an ASGI app.
        """
        self._verifier = verifier
        self._get_http_request = get_http_request or _default_get_http_request

        # ``AuthplaneResource.resource`` is operator-configured and must be a
        # string URI — guard against mis-wired mocks (a bare ``MagicMock`` with
        # no ``resource`` set silently produces ``MagicMock://MagicMock`` here
        # and would corrupt ``htu`` reconstruction in production).
        if not isinstance(verifier.resource, str):
            raise TypeError(
                f"verifier.resource must be a str URI, got {type(verifier.resource).__name__}"
            )
        split = urlsplit(verifier.resource)
        self._resource_origin = f"{split.scheme}://{split.netloc}"

    @property
    def verifier(self) -> AuthplaneResource:
        """The underlying ``AuthplaneResource`` instance."""
        return self._verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a JWT and return an MCP ``AccessToken``.

        Pulls the active HTTP request to build a per-request
        :class:`DPoPRequestContext` (RFC 9449 §7.1) and to scope the
        verify-task cache. The cache hit path re-awaits the original
        :class:`asyncio.Task`, so a cached :class:`AuthplaneError`
        re-raises with the same type on every call within the request —
        the ``AuthplaneError → None`` translation happens once here, not
        inside the cached coroutine, which keeps the cached failure
        diagnosable.

        Args:
            token: The raw JWT string (MCP strips the ``Bearer ``
                prefix before calling this method).

        Returns:
            ``AccessToken`` on successful validation with ``token``,
            ``client_id``, ``scopes``, ``expires_at``, and ``resource``
            fields populated. Returns ``None`` on any
            ``AuthplaneError`` (MCP responds with 401).
        """
        try:
            request: Request | None = self._get_http_request()
        except RuntimeError as exc:
            # ``get_current_request`` (and FastMCP's ``get_http_request``)
            # raise a bare ``RuntimeError("No active HTTP request found.")``
            # when called outside an HTTP request context (unit tests,
            # background tasks, or — for the MCP SDK path — any request
            # served without ``AuthplaneRequestContextMiddleware`` installed).
            # Match the message to avoid silently degrading to
            # ``dpop_request=None`` if a future framework change surfaces an
            # unrelated ``RuntimeError`` from the dependency — that would
            # re-introduce the silent-pass this PR fixed (PRM advertising
            # DPoP-required while the verifier never sees a proof). Drop
            # this narrow when both upstream surfaces adopt a typed
            # exception.
            if "No active HTTP request" not in str(exc):
                raise
            request = None

        try:
            if request is None:
                claims = await self._verifier.verify(token, dpop_request=None)
            else:
                cache = get_or_create_verify_cache(request)
                task = cache.get(token)
                if task is None:
                    # No await between cache miss and cache write — concurrent
                    # verify_token(token) calls on the same loop cannot race.
                    dpop_request = self._build_dpop_request_context(request)
                    task = asyncio.create_task(
                        self._verifier.verify(token, dpop_request=dpop_request)
                    )
                    cache[token] = task
                claims = await task
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

    def _build_dpop_request_context(self, request: Request) -> DPoPRequestContext:
        """Build the per-request DPoP context.

        Always returns a context — the resource verifier inspects the
        access token's ``cnf`` claim plus the context's ``proof`` to
        decide whether DPoP enforcement applies. When the resource is
        not configured for inbound DPoP, the verifier's Mode-3 path
        rejects any DPoP signal regardless of what is passed here.

        Cross-SDK note: the TS sibling ``buildDpopRequestContext``
        returns ``undefined`` when no ``DPoP`` header is present;
        Python intentionally always builds the context with
        ``proof=None``. Both shapes are behaviorally equivalent in
        the core verifier (Mode 3 path treats absent and ``None``
        proofs the same), but a DPoP-bound token with no proof
        yields a more specific ``DPoPProofMissingError`` here
        instead of ``DPoPBindingMismatchError``. The error-type
        contract is pinned per language by design.
        """
        # ``raw_request_path`` reads ``scope["raw_path"]`` to preserve
        # percent-encoding for DPoP ``htu`` parity with the TS sibling.
        # ``request.url.query`` is sourced from ``scope["query_string"]``
        # without percent-decoding, so it is already on-wire-safe.
        url = f"{self._resource_origin}{raw_request_path(request)}"
        query = request.url.query
        if query:
            url = f"{url}?{query}"
        return BuiltDPoPRequestContext(
            method=request.method.upper(),
            url=url,
            proof=read_dpop_header(request),
        )
