"""Convenience factory for enabling Authplane auth on MCP servers.

Provides ``authplane_mcp_auth()``, an async factory function that creates
and configures all the components needed to add Authplane JWT validation
to an official MCP Python SDK server in a single call.
"""

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
from pydantic import AnyHttpUrl

from .url_elicitation import to_url_elicitation_required_error
from .verifier import AuthplaneTokenVerifier


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
    circuit_breaker_threshold: int | None = None,
    circuit_breaker_cooldown_seconds: float | None = None,
    clock_skew_seconds: int | None = None,
    dev_mode: bool | None = None,
    fetch_settings: FetchSettings | None = None,
    inbound_dpop: InboundDPoPOptions | None = None,
    revocation_checker: IntrospectionRevocation | RevocationChecker | None = None,
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
              Fails open if the endpoint is unavailable.
            - async callable: custom checker called with
              ``(VerifiedClaims, raw_token)``; return ``True`` to reject
              the token (raises ``TokenRevokedError``).

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
        **verifier_kwargs,
    )

    # Wrap in AuthplaneTokenVerifier
    token_verifier = AuthplaneTokenVerifier(verifier)

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
