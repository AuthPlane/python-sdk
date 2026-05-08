"""Convenience factory for enabling Authplane auth on FastMCP servers.

Provides ``authplane_auth()``, an async factory function that creates and
configures all the components needed to add Authplane JWT validation to a
FastMCP server in a single call.
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
from fastmcp.server.auth import RemoteAuthProvider
from pydantic import AnyHttpUrl

from .url_elicitation import to_url_elicitation_required_error
from .verifier import AuthplaneTokenVerifier


def _wrap_client_for_elicitation(client: AuthplaneClient) -> AuthplaneClient:
    """Translate ``client.exchange`` consent errors into MCP ``-32042``.

    Wrapping ``exchange()`` (the only method that realistically surfaces
    ``ConsentRequiredError`` from the AS) means user tool code can call
    ``result.client.exchange(...)`` without any try/except: a consent error
    becomes a ``UrlElicitationRequiredError`` transparently, and FastMCP
    forwards it as a ``-32042`` JSON-RPC error.
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


class AuthplaneAuthResult:
    """Return value of ``authplane_auth()``.

    Supports ``**`` unpacking into ``FastMCP()`` — only the ``auth`` key
    is included in the mapping view so FastMCP receives exactly what it
    expects. ``token_verifier`` and ``client`` are exposed as plain
    attributes for advanced use cases such as RFC 8693 token exchange::

        result = await authplane_auth(issuer=..., base_url=..., ...)
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
        auth: RemoteAuthProvider,
        token_verifier: AuthplaneTokenVerifier,
        client: AuthplaneClient,
    ) -> None:
        self.auth = auth
        self.token_verifier = token_verifier
        self.client = client

    async def aclose(self) -> None:
        """Release resources held by the underlying ``AuthplaneClient``.

        Cancels the background JWKS refresh task and closes the HTTP
        connection pool.  Safe to call multiple times.
        """
        await self.client.aclose()

    # Mapping protocol — yields only "auth" so FastMCP(**result) works cleanly.
    def keys(self) -> list[str]:
        return ["auth"]

    def __getitem__(self, key: str) -> Any:
        if key == "auth":
            return self.auth
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())


async def authplane_auth(
    issuer: str,
    base_url: str,
    scopes: list[str] | None = None,
    *,
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
    mcp_path: str = "/mcp",
    revocation_checker: IntrospectionRevocation | RevocationChecker | None = None,
) -> AuthplaneAuthResult:
    """Build the kwargs to enable Authplane auth on a FastMCP server.

    This async factory performs RFC 8414 metadata discovery, fetches the
    JWKS, and wires up all components (client, resource, token verifier,
    auth provider) in a single awaitable call.

    Usage::

        mcp = FastMCP("My Server", **await authplane_auth(
            issuer="https://auth.company.com",
            base_url="https://mcp.company.com",
            scopes=["tools/query", "tools/write"],
        ))

    After setup:

    - Use ``@mcp.tool(auth=require_scopes(...))`` for scope enforcement.
    - Use ``CurrentAccessToken()`` or ``get_access_token()`` to access
      token claims inside tool handlers (both are FastMCP built-ins).

    Args:
        issuer: Authplane authorization server URL
            (e.g., ``"https://auth.company.com"``).
        base_url: Root URL of the FastMCP server
            (e.g., ``"https://mcp.company.com"``). Same value you would
            pass to FastMCP for deployment.
        scopes: All scopes this server supports. Used in AuthSettings
            and the PRM document. Defaults to an empty list.
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
        mcp_path: Mount path of the MCP endpoint (default ``"/mcp"``).
            The JWT audience (resource) is derived as
            ``base_url + mcp_path``. Only set this if you changed
            FastMCP's default HTTP mount path.
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
        ``AuthplaneAuthResult`` with ``auth`` (``RemoteAuthProvider``),
        ``token_verifier`` (``AuthplaneTokenVerifier``), and ``client``
        (``AuthplaneClient``) attributes. Supports ``**`` unpacking into
        ``FastMCP()`` — only ``auth`` is included in the mapping view.
        Access ``client`` directly for RFC 8693 token exchange via
        ``result.client.exchange()``.

    Raises:
        ValueError: If configuration is invalid (bad algorithms, etc.).
        JWKSFetchError: If metadata discovery or JWKS fetching fails.
    """
    resolved_scopes = scopes or []

    # Derive the canonical resource URL (= JWT audience) from base_url + mcp_path.
    # This must match exactly what RemoteAuthProvider advertises in the PRM, which
    # FastMCP computes as base_url + mcp_path via _get_resource_url().
    resource = base_url.rstrip("/") + "/" + mcp_path.lstrip("/")

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
    # Note: FastMCP 3.0.0 uses token_verifier.base_url for PRM generation if provided
    token_verifier = AuthplaneTokenVerifier(verifier, base_url=base_url)

    # Wrap in RemoteAuthProvider to get PRM routes
    auth_provider = RemoteAuthProvider(
        token_verifier=token_verifier,
        authorization_servers=[AnyHttpUrl(issuer)],
        base_url=AnyHttpUrl(base_url),
        scopes_supported=resolved_scopes,
    )

    return AuthplaneAuthResult(
        auth=auth_provider,
        token_verifier=token_verifier,
        client=client,
    )
