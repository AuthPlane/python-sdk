"""AuthplaneTokenVerifier - FastMCP TokenVerifier backed by AuthplaneResource.

Bridges the Authplane core SDK with FastMCP's ``TokenVerifier`` interface,
delegating all JWT validation to ``AuthplaneResource`` and mapping results
to FastMCP's ``AccessToken`` with the full JWT payload in ``claims``.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urlsplit

from authplane import AuthplaneError, AuthplaneResource, DPoPRequestContext
from authplane._dpop_adapter import (
    BuiltDPoPRequestContext,
    get_or_create_verify_cache,
    raw_request_path,
    read_dpop_header,
)
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_http_request as _default_get_http_request
from starlette.requests import Request

logger = logging.getLogger(__name__)


__all__ = ["AuthplaneTokenVerifier"]


class AuthplaneTokenVerifier(TokenVerifier):
    """FastMCP TokenVerifier backed by AuthplaneResource.

    Validates JWTs once per request via the core Authplane SDK and returns
    a FastMCP ``AccessToken`` with ``claims`` populated from the full JWT
    payload (``VerifiedClaims.raw``). Token claims are then available in
    tool handlers via FastMCP's native ``CurrentAccessToken()`` dependency
    or ``get_access_token()`` function.

    DPoP (RFC 9449)
    ---------------

    When the underlying :class:`AuthplaneResource` was created with
    ``inbound_dpop=InboundDPoPOptions(...)``, this verifier pulls the
    active HTTP request via
    :func:`fastmcp.server.dependencies.get_http_request`, builds a
    :class:`~authplane.DPoPRequestContext` (method + reconstructed
    ``htu`` + proof header), and forwards it to
    :meth:`AuthplaneResource.verify`. The ``htu`` origin
    (scheme + host + port) is taken from the operator-configured
    resource URI, never from the inbound ``Host`` /
    ``X-Forwarded-Proto`` headers — letting an upstream decide which
    ``htu`` the proof is checked against would neuter DPoP's
    cross-endpoint anti-replay. Only the path varies per call.

    Per-request verify cache
    ------------------------

    FastMCP's standard HTTP stack invokes ``verify_token`` exactly once
    per request (Starlette ``AuthenticationMiddleware`` →
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

    Scope enforcement is FastMCP's responsibility via
    ``@mcp.tool(auth=require_scopes(...))``.
    """

    def __init__(
        self,
        verifier: AuthplaneResource,
        base_url: str | None = None,
        required_scopes: list[str] | None = None,
        *,
        get_http_request: Callable[[], Request] | None = None,
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
            get_http_request: Override for the active-request lookup
                (defaults to
                ``fastmcp.server.dependencies.get_http_request``). Tests
                inject a fake to drive the DPoP / per-request-cache
                paths without spinning up an ASGI app.
        """
        super().__init__(base_url=base_url, required_scopes=required_scopes)
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

    @property
    def scopes_supported(self) -> list[str]:
        """Return scopes supported by this verifier.

        Returns the scopes configured in the ``AuthplaneResource``, which
        are used by FastMCP for PRM metadata generation at
        ``/.well-known/oauth-protected-resource``.
        """
        return list(self._verifier.scopes)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a JWT and return a FastMCP ``AccessToken``.

        Pulls the active HTTP request to build a per-request
        :class:`DPoPRequestContext` (RFC 9449 §7.1) and to scope the
        verify-task cache. The cache hit path re-awaits the original
        :class:`asyncio.Task`, so a cached :class:`AuthplaneError`
        re-raises with the same type on every call within the request —
        the ``AuthplaneError → None`` translation happens once here, not
        inside the cached coroutine, which keeps the cached failure
        diagnosable.

        Args:
            token: The raw JWT string (FastMCP strips the ``Bearer ``
                prefix before calling this method).

        Returns:
            ``AccessToken`` on successful validation. ``None`` on any
            ``AuthplaneError`` (FastMCP responds with 401).
        """
        try:
            request: Request | None = self._get_http_request()
        except RuntimeError as exc:
            # ``fastmcp.server.dependencies.get_http_request`` raises a bare
            # ``RuntimeError("No active HTTP request found.")`` when called
            # outside an HTTP request context (unit tests, background tasks
            # with no snapshotted request). Match the message to avoid
            # silently degrading to ``dpop_request=None`` if a future
            # FastMCP release surfaces an unrelated ``RuntimeError`` from
            # this dependency — that would re-introduce the silent-pass
            # this PR fixed (PRM advertising DPoP-required while the
            # verifier never sees a proof). Drop this narrow when the
            # upstream public surface adopts a typed exception.
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

        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=list(claims.scopes),
            expires_at=claims.expires_at,
            claims=cast("dict[str, Any]", claims.raw),  # full JWT payload
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
