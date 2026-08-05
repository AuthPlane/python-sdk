"""Convenience factory for enabling Authplane auth on MCP servers.

Provides ``authplane_mcp_auth()``, an async factory function that creates
and configures all the components needed to add Authplane JWT validation
to an official MCP Python SDK server in a single call.
"""

import warnings
from collections.abc import Iterator
from typing import Any

from authplane import (
    ASCredentials,
    AuthplaneClient,
    DPoPProvider,
    FetchSettings,
    InboundDPoPOptions,
    IntrospectionRevocation,
    RevocationChecker,
)
from authplane.oauth import TokenExchangeOptions, TokenResponse
from mcp.server.auth.middleware.auth_context import get_access_token as _get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from ._prm import rewrite_prm_routes_verbatim
from ._request_context import AuthplaneRequestContextMiddleware
from .url_elicitation import to_url_elicitation_required_error
from .verifier import AuthplaneTokenVerifier

_INSTALLED_FLAG = "_authplane_request_context_installed"


def _wrap_client_for_elicitation(client: AuthplaneClient) -> AuthplaneClient:
    """Translate ``client.exchange`` consent errors into MCP ``-32042``.

    Wrapping ``exchange()`` (the only method that realistically surfaces
    ``ConsentRequiredError`` from the AS) means user tool code can call
    ``result.client.exchange(...)`` without any try/except: a consent error
    becomes a ``UrlElicitationRequiredError`` transparently, and FastMCP /
    the MCP server forwards it as a ``-32042`` JSON-RPC error.
    """
    original_exchange = client.exchange

    async def exchange(options: TokenExchangeOptions) -> TokenResponse:
        try:
            return await original_exchange(options)
        except Exception as error:
            mapped = to_url_elicitation_required_error(error)
            if mapped is not None:
                raise mapped from error
            raise

    client.exchange = exchange
    return client


def require_scope(scope: str) -> None:
    """Raise PermissionError if the current request token is missing a required scope.

    Call this at the top of a tool handler to enforce per-tool scope requirements::

        @mcp.tool()
        async def add(a: float, b: float) -> float:
            require_scope("tools/add")
            return a + b

    Args:
        scope: The scope string that must be present in the token.

    Raises:
        PermissionError: If the token is absent or does not contain ``scope``.
    """
    token = _get_access_token()
    if token is None or scope not in token.scopes:
        raise PermissionError(f"Missing required scope: {scope}")


def install_request_context(mcp: FastMCP) -> None:
    """Wire Authplane's per-app hooks onto a ``FastMCP`` server.

    Wraps ``mcp.streamable_http_app`` so the Starlette app it returns is
    post-processed with two Authplane concerns before it starts serving.
    ``mcp.sse_app`` is wrapped with the second concern only — the SSE branch
    applies just the verbatim-PRM rewrite, not the request-context middleware:

    1. **Request context (DPoP).** :class:`AuthplaneRequestContextMiddleware`
       is installed before MCP's ``AuthenticationMiddleware`` (streamable-HTTP
       app only). That middleware publishes the active
       :class:`starlette.requests.Request` on a ContextVar, which
       :meth:`AuthplaneTokenVerifier.verify_token` reads to forward a
       :class:`~authplane.DPoPRequestContext` to
       :meth:`AuthplaneResource.verify`.

    2. **Verbatim PRM identifiers.** The Protected Resource Metadata route the
       MCP SDK auto-registers serves ``authorization_servers`` / ``resource``
       through ``pydantic.AnyHttpUrl``, which normalizes an empty-path
       authority with a trailing slash. The core SDK compares the issuer /
       resource identifier byte-for-byte (RFC 8414 §3.3, RFC 9728 §3.3), so the
       served document is rewritten to advertise the operator-configured
       identifiers verbatim — otherwise a client that follows the PRM literally
       is rejected by the strict comparison ("issuer mismatch") and tokens
       minted for the advertised ``resource`` fail the ``aud`` check.

    The MCP SDK's ``FastMCP`` builds its middleware list and its auth routes
    internally with no public hook, so wrapping the app factory is the
    least-invasive way to slot both concerns in without subclassing or
    monkeypatching the SDK.

    Without this call the verifier still works for non-DPoP flows, but DPoP-bound
    requests fail closed (``DPoPBindingMismatchError``) and the served PRM keeps
    the slash-normalized identifiers. Call it right after constructing the
    ``FastMCP`` instance.

    Args:
        mcp: A ``FastMCP`` instance (typically
            ``FastMCP("...", **authplane_mcp_auth_result)``). Safe to
            call before tools are registered.

    Example::

        async def main() -> None:
            result = await authplane_mcp_auth(issuer=..., resource=..., ...)
            mcp = FastMCP("My Server", **result)
            install_request_context(mcp)
            async with result:
                await mcp.run_streamable_http_async()

        asyncio.run(main())

    Idempotent: a second call on the same ``FastMCP`` instance is a no-op.
    Without this guard, repeated installs would chain wrappers and the
    inner middleware's ``ContextVar.reset`` would fire against a token
    created by the outer wrapper, raising
    ``RuntimeError: <Token> was created in a different Context`` at
    request time.
    """
    if getattr(mcp, _INSTALLED_FLAG, False):
        return

    # The verbatim identifiers ride on the AuthplaneTokenVerifier that
    # ``authplane_mcp_auth`` stashed on the server. If a server was wired
    # without the factory (no verbatim identifiers available), the PRM rewrite
    # is skipped and the request-context middleware is still installed.
    token_verifier = getattr(mcp, "_token_verifier", None)
    if token_verifier is None:
        # ``_token_verifier`` is an MCP SDK private attribute. If a future SDK
        # release renames it, this lookup returns None and the verbatim PRM
        # rewrite would quietly no-op, reverting the served document to the
        # slash-normalized identifiers that break the strict comparison. Surface
        # that loudly rather than silently regressing.
        warnings.warn(
            "FastMCP._token_verifier is absent; skipping the verbatim PRM "
            "rewrite. The served Protected Resource Metadata will advertise "
            "slash-normalized issuer/resource identifiers, which the core SDK's "
            "byte-for-byte comparison rejects. This usually means the MCP SDK "
            "renamed the private attribute the adapter reads.",
            RuntimeWarning,
            stacklevel=2,
        )
    verbatim_issuer = getattr(token_verifier, "_verbatim_issuer", None)
    verbatim_resource = getattr(token_verifier, "_verbatim_resource", None)

    def rewrite_prm(app: Starlette) -> None:
        if verbatim_issuer is not None and verbatim_resource is not None:
            rewrite_prm_routes_verbatim(
                app.router.routes,
                issuer=verbatim_issuer,
                resource=verbatim_resource,
            )

    original_streamable_http_app = mcp.streamable_http_app

    def streamable_http_app() -> Starlette:
        app = original_streamable_http_app()
        # ``Starlette.add_middleware`` rejects calls after the app has built
        # its middleware stack (first request). ``streamable_http_app`` is
        # invoked once at startup before serving begins, so wrapping is safe
        # here and runs before MCP's AuthenticationMiddleware on every call.
        app.add_middleware(AuthplaneRequestContextMiddleware)
        rewrite_prm(app)
        return app

    original_sse_app = mcp.sse_app

    def sse_app(*args: Any, **kwargs: Any) -> Starlette:
        # Forward whatever positional/keyword args the SDK passes so a future
        # signature change in ``sse_app`` cannot TypeError at app-build time;
        # only the verbatim PRM rewrite below is ours.
        app = original_sse_app(*args, **kwargs)
        rewrite_prm(app)
        return app

    # Fragility: instance-attribute assignment works only because FastMCP
    # exposes ``streamable_http_app`` / ``sse_app`` as plain methods, not
    # ``@property`` or ``@cached_property``. If a future MCP SDK release changes
    # that, the assignment will silently no-op (or raise AttributeError) and
    # both concerns above fall back to the SDK defaults.
    # Track https://github.com/modelcontextprotocol/python-sdk for a public
    # subclassing hook or per-app middleware API and migrate to it when available.
    mcp.streamable_http_app = streamable_http_app
    mcp.sse_app = sse_app
    setattr(mcp, _INSTALLED_FLAG, True)


class AuthplaneAuthResult:
    """Return value of ``authplane_mcp_auth()``.

    Supports ``**`` unpacking into ``FastMCP()`` — only ``token_verifier``
    and ``auth`` keys are included in the mapping view so FastMCP receives
    exactly what it expects. ``client`` is exposed as a plain attribute for
    advanced use cases such as RFC 8693 token exchange::

        result = await authplane_mcp_auth(issuer=..., resource=..., ...)
        mcp = FastMCP("My Server", **result)

        # Inside a tool handler — exchange a user token for a downstream token:
        downstream = await result.client.exchange(TokenExchangeOptions(
            subject_token=user_token,
        ))

    Call ``await result.aclose()`` on server shutdown to release background
    tasks and HTTP connections held by the underlying ``AuthplaneClient``.
    """

    def __init__(
        self,
        token_verifier: AuthplaneTokenVerifier,
        auth: AuthSettings,
        client: AuthplaneClient,
    ) -> None:
        self.token_verifier = token_verifier
        self.auth = auth
        self.client = client

    async def aclose(self) -> None:
        """Release resources held by the underlying ``AuthplaneClient``.

        Cancels the background JWKS refresh task and closes the HTTP
        connection pool.  Safe to call multiple times.
        """
        await self.client.aclose()

    # Mapping protocol — yields only what FastMCP expects.
    def keys(self) -> list[str]:
        return ["token_verifier", "auth"]

    def __getitem__(self, key: str) -> Any:
        if key == "token_verifier":
            return self.token_verifier
        if key == "auth":
            return self.auth
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())


async def authplane_mcp_auth(
    issuer: str,
    resource: str,
    scopes: list[str] | None = None,
    *,
    enforce_scopes_on_all_requests: bool = False,
    as_credentials: ASCredentials | None = None,
    dpop: DPoPProvider | None = None,
    allowed_algorithms: list[str] | None = None,
    jwks_refresh_seconds: int | None = None,
    metadata_refresh_seconds: int | None = None,
    cache_ttl_buffer_seconds: float | None = None,
    default_ttl_seconds: float | None = None,
    cache_max_entries: int | None = None,
    circuit_breaker_threshold: int | None = None,
    circuit_breaker_cooldown_seconds: float | None = None,
    clock_skew_seconds: int | None = None,
    dev_mode: bool | None = None,
    fetch_settings: FetchSettings | None = None,
    inbound_dpop: InboundDPoPOptions | None = None,
    revocation_checker: IntrospectionRevocation | RevocationChecker | None = None,
    fail_closed: bool = False,
) -> AuthplaneAuthResult:
    """Build the kwargs to enable Authplane auth on a FastMCP server.

    This async factory performs RFC 8414 metadata discovery, fetches the
    JWKS, and wires up all components (client, resource, token verifier,
    auth settings) in a single awaitable call.

    Usage::

        mcp = FastMCP(
            "My Server",
            **await authplane_mcp_auth(
                issuer="https://auth.company.com",
                resource="https://mcp.company.com",
                scopes=["tools/query", "tools/write"],
            )
        )

    Args:
        issuer: Authplane authorization server URL
            (e.g., ``"https://auth.company.com"``).
        resource: URL of this MCP server / resource identifier
            (e.g., ``"https://mcp.company.com"``). This is used as the
            JWT audience (``aud`` claim) and ``resource_server_url`` in
            AuthSettings.
        scopes: All scopes this server supports. Defaults to an empty
            list.
        enforce_scopes_on_all_requests: When ``True``, ``scopes`` are passed
            to the MCP SDK as ``AuthSettings.required_scopes``. This causes
            two things:

            1. The Protected Resource Metadata (PRM) endpoint advertises
               them as ``scopes_supported`` — required for OAuth-discovery
               clients (e.g. Claude Code) to know which scopes to request
               on a fresh token mint, otherwise they fall back to the AS
               metadata's global ``scopes_supported`` (every scope across
               every resource) and the AS rejects with ``invalid_scope``.
            2. ``RequireAuthMiddleware`` rejects any request whose token
               does not carry **all** listed scopes — coarse-grained
               enforcement at the request layer.

            This is a workaround for an MCP reference SDK limitation:
            ``AuthSettings`` has no separate "supported" field, so the SDK
            uses ``required_scopes`` for both purposes (see
            ``mcp/server/fastmcp/server.py`` ``create_protected_resource_routes``
            calls).  Per-tool ``require_scope()`` is the intended granular
            pattern; keep those calls in place even when this flag is
            ``True`` — they remain correct, are simply redundant under
            request-level enforcement, and continue to work unchanged
            once the upstream SDK gains a separate "supported" field and
            this flag becomes unnecessary.

            Defaults to ``False``: PRM advertises no scopes, per-tool
            ``require_scope()`` is the only enforcement.
        dpop: Optional DPoP provider used for outbound calls from the
            underlying SDK client to the authorization server.
        allowed_algorithms: Algorithms allowed for signature verification.
            Defaults to SDK defaults (``["RS256", "ES256"]``).
        jwks_refresh_seconds: JWKS cache TTL in seconds (default ``300``).
        cache_ttl_buffer_seconds: Buffer subtracted from token TTLs
            before cache expiry (default ``30.0``).
        default_ttl_seconds: Fallback token cache TTL used when token
            responses do not include expiry metadata (default ``3600.0``).
        cache_max_entries: Maximum number of tokens kept in the LRU cache
            before the least-recently-used entry is evicted (default
            :attr:`TokenCache.DEFAULT_MAX_ENTRIES` = 10 000). Token-exchange
            keys are high-cardinality; raise this cap for long-lived servers
            with many distinct subjects.
        circuit_breaker_threshold: Number of transient failures before
            opening the AS circuit breaker (default ``5``).
        circuit_breaker_cooldown_seconds: Cooldown before allowing a
            half-open probe request after the circuit opens
            (default ``30.0``).
        clock_skew_seconds: Leeway in seconds for exp/nbf/iat validation
            (default ``30``).
        dev_mode: Enable development mode. Relaxes SSRF checks to allow
            HTTP, localhost, and private networks. Can also be set via
            ``AUTHPLANE_DEV_MODE=true`` environment variable.
        metadata_refresh_seconds: AS metadata cache TTL in seconds
            (default ``3600``).
        fetch_settings: Full ``FetchSettings`` object applied to both
            metadata and JWKS fetches. When provided, overrides
            ``dev_mode`` for those fetches.
        inbound_dpop: Per-resource inbound DPoP policy
            (:class:`InboundDPoPOptions`).  Bundles ``required``,
            ``signing_algs``, ``max_proof_age_seconds``,
            ``clock_skew_seconds`` and ``replay_store``; see RFC 9728 §2 +
            RFC 9449 §7.1 for the field semantics.
        as_credentials: Client credentials for authenticating to the AS.
            Shared by introspection (RFC 7662) and token exchange (RFC 8693).
            Required when using ``IntrospectionRevocation`` for authenticated
            introspection, or when calling ``client.exchange()``.
        revocation_checker: Controls token revocation checking after
            signature validation passes.

            - ``None`` (default): disables revocation checking (offline
              validation only).
            - ``IntrospectionRevocation()``: calls the AS
              ``introspection_endpoint`` (RFC 7662) discovered from AS
              metadata. Raises ``TokenRevokedError`` if ``active=false``.
              Pass ``as_credentials`` for authenticated introspection.
              Fails open if the endpoint is unavailable, unless
              ``fail_closed=True``.
            - async callable: custom checker called with
              ``(VerifiedClaims, raw_token)``; return ``True`` to reject
              the token (raises ``TokenRevokedError``).
        fail_closed: Policy applied when the configured
            ``revocation_checker`` itself fails (e.g. the introspection
            endpoint is unreachable). ``False`` (default) accepts the
            token — offline signature/claims validation still applies.
            ``True`` rejects it with ``TokenRevokedError``, trading
            availability during an AS outage for a hard revocation
            guarantee. Only consulted when a ``revocation_checker`` is
            configured; note that once the client's circuit breaker
            opens, every request is rejected until the cooldown elapses.

    Returns:
        ``AuthplaneAuthResult`` with ``token_verifier`` (``AuthplaneTokenVerifier``),
        ``auth`` (``AuthSettings``), and ``client`` (``AuthplaneClient``) attributes.
        Supports ``**`` unpacking into ``FastMCP()`` — only ``token_verifier``
        and ``auth`` are included in the mapping view. Access ``client`` directly
        for RFC 8693 token exchange via ``result.client.exchange()``.

    Raises:
        ValueError: If configuration is invalid (bad algorithms, etc.).
        JWKSFetchError: If metadata discovery or JWKS fetching fails.
    """
    resolved_scopes = scopes or []

    # Prepare client-level kwargs, filtering out None to use SDK defaults
    client_kwargs_raw: dict[str, Any] = {
        "dpop": dpop,
        "dev_mode": dev_mode,
        "fetch_settings": fetch_settings,
        "jwks_refresh_seconds": jwks_refresh_seconds,
        "metadata_refresh_seconds": metadata_refresh_seconds,
        "cache_ttl_buffer_seconds": cache_ttl_buffer_seconds,
        "default_ttl_seconds": default_ttl_seconds,
        "cache_max_entries": cache_max_entries,
        "circuit_breaker_threshold": circuit_breaker_threshold,
        "circuit_breaker_cooldown_seconds": circuit_breaker_cooldown_seconds,
    }
    client_kwargs: dict[str, Any] = {k: v for k, v in client_kwargs_raw.items() if v is not None}

    # Prepare resource-level kwargs, filtering out None to use SDK defaults
    verifier_kwargs_raw: dict[str, Any] = {
        "allowed_algorithms": allowed_algorithms,
        "clock_skew_seconds": clock_skew_seconds,
        "inbound_dpop": inbound_dpop,
    }
    verifier_kwargs: dict[str, Any] = {
        k: v for k, v in verifier_kwargs_raw.items() if v is not None
    }

    # Create the AuthplaneClient (handles metadata discovery, JWKS fetching, caching)
    client = await AuthplaneClient.create(
        issuer=issuer,
        auth=as_credentials,
        **client_kwargs,
    )

    # Translate ConsentRequiredError → MCP UrlElicitationRequiredError at the
    # client boundary, before user tool code sees it.  Tool authors don't need
    # to wrap handlers or import elicitation primitives — the MCP wire-format
    # mapping is owned by the adapter that constructs the client.
    client = _wrap_client_for_elicitation(client)

    # Create the resource from the client
    verifier = client.resource(
        resource=resource,
        scopes=resolved_scopes,
        revocation_checker=revocation_checker,
        fail_closed=fail_closed,
        **verifier_kwargs,
    )

    # Wrap in AuthplaneTokenVerifier.  The verbatim issuer / resource ride
    # along on the verifier so ``install_request_context`` can advertise them
    # unchanged in the served PRM — the MCP SDK builds that document from
    # ``AuthSettings`` ``AnyHttpUrl`` fields, which normalize an empty-path
    # authority with a trailing slash (RFC 8414 §3.3, RFC 9728 §3.3).
    token_verifier = AuthplaneTokenVerifier(
        verifier,
        verbatim_issuer=issuer,
        verbatim_resource=resource,
    )

    # Create AuthSettings for FastMCP.
    #
    # The MCP SDK's AuthSettings has no separate "supported" field — it uses
    # ``required_scopes`` for both PRM ``scopes_supported`` advertisement
    # AND RequireAuthMiddleware enforcement.  See the docstring on
    # ``enforce_scopes_on_all_requests`` above for the trade-off and why
    # this flag exists.  Per-tool ``require_scope()`` is the intended
    # granular pattern in either mode.
    auth_settings = AuthSettings(
        issuer_url=AnyHttpUrl(issuer),
        resource_server_url=AnyHttpUrl(resource),
        required_scopes=resolved_scopes if enforce_scopes_on_all_requests else None,
    )

    return AuthplaneAuthResult(
        token_verifier=token_verifier,
        auth=auth_settings,
        client=client,
    )
