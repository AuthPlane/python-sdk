"""AuthplaneClient — unified OAuth client with caching and resilience."""

import logging
import os
from typing import TYPE_CHECKING, Self

import httpx

from .auth_provider import AuthProvider, ClientCredentialsProvider
from .cache import TokenCache
from .circuit_breaker import CircuitBreaker
from .credentials import ASCredentials
from .dpop import DPoPProvider, InboundDPoPOptions
from .errors import CircuitOpenError, DPoPError, MetadataFetchError, ServerError
from .internal import (
    DocumentFetcher,
    JWKSCache,
    MetadataCache,
    build_metadata_url,
)
from .net import FetchSettings
from .net.ssrf import SSRFError
from .oauth import (
    IntrospectionResponse,
    TokenExchangeOptions,
    TokenResponse,
    client_credentials_grant,
    exchange_token,
    introspect_token,
    revoke_token,
)

if TYPE_CHECKING:
    from .oauth.types import IntrospectionRevocation
    from .verifier import AuthplaneResource
    from .verifier.verifier import RevocationChecker

logger = logging.getLogger(__name__)


class AuthplaneClient:
    """Unified OAuth 2.1 client for Authplane authorization servers.

    Owns AS connection state (metadata, JWKS), caches, and resilience
    (circuit breaker, token cache). Creates resources via `resource()`.

    Usage:
        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            auth=ASCredentials(client_id="...", client_secret="..."),
        )

        # Token operations
        token = await client.client_credentials(scopes=["read"])
        result = await client.introspect(some_token)
        await client.revoke(some_token)

        # Create a resource scoped to a URI
        res = client.resource(
            resource="https://api.example.com",
            scopes=["read", "write"],
        )
        claims = await res.verify(incoming_token)
    """

    def __init__(self) -> None:
        """Private constructor. Use create() instead."""
        # These are set by create()
        self._issuer: str = ""
        self._auth: AuthProvider | None = None
        self._fetch_settings: FetchSettings = FetchSettings()
        self._metadata_cache: MetadataCache | None = None
        self._jwks_cache: JWKSCache | None = None
        self._token_cache: TokenCache = TokenCache()
        self._circuit_breaker: CircuitBreaker = CircuitBreaker()
        self._dev_mode: bool = False
        self._dpop: DPoPProvider | None = None
        self._jwks_uri: str | None = None
        self._jwks_refresh_seconds: int = 300
        self._metadata_refresh_seconds: int = 3600

    @classmethod
    async def create(
        cls,
        issuer: str,
        *,
        auth: AuthProvider | ASCredentials | None = None,
        dpop: DPoPProvider | None = None,
        dev_mode: bool | None = None,
        fetch_settings: FetchSettings | None = None,
        jwks_refresh_seconds: int = 300,
        metadata_refresh_seconds: int = 3600,
        cache_ttl_buffer_seconds: float = 30.0,
        default_ttl_seconds: float = 3600.0,
        cache_max_entries: int = TokenCache.DEFAULT_MAX_ENTRIES,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_cooldown_seconds: float = 30.0,
    ) -> Self:
        """Create and initialize the client.

        Discovers AS metadata and starts JWKS background refresh.

        Args:
            issuer: Authorization-server issuer URL (the prefix RFC 8414 metadata
                is fetched from). Trailing slash is stripped.
            auth: Client authentication for OAuth endpoints. Accepts either a raw
                :class:`AuthProvider` or an :class:`ASCredentials` shorthand (which
                is materialised as :class:`ClientCredentialsProvider`).
            dpop: Optional :class:`DPoPProvider` for sender-constrained outbound
                requests against the AS (token / introspection / revocation).
            dev_mode: When True, relaxes SSRF and HTTPS-only fetch policies for
                local development. Falls back to the ``AUTHPLANE_DEV_MODE``
                environment variable when omitted.
            fetch_settings: Explicit :class:`FetchSettings` override. When None,
                derived from ``dev_mode``.
            jwks_refresh_seconds: Background JWKS refresh interval (must be > 0).
            metadata_refresh_seconds: Background metadata refresh interval
                (must be > 0).
            cache_ttl_buffer_seconds: Safety margin subtracted from each token's
                lifetime before the entry is considered expired. Same shape as
                java-sdk ``TokenCacheConfig.ttlBufferSeconds`` and ts-sdk
                ``TokenCache`` ctor. Default 30s.
            default_ttl_seconds: Fallback lifetime applied when the AS response
                omits ``expires_in``. Cross-SDK parity with java-sdk
                ``TokenCacheConfig.defaultTtlSeconds``. Default 3600s.
            cache_max_entries: Maximum number of cached tokens before
                least-recently-used eviction kicks in. Default
                :attr:`TokenCache.DEFAULT_MAX_ENTRIES` (10_000). Must be a
                positive integer (``bool``/``float`` rejected — see
                :class:`TokenCache`).
            circuit_breaker_threshold: Consecutive AS failures before the
                circuit opens. Default 5.
            circuit_breaker_cooldown_seconds: Half-open probe interval after the
                circuit trips. Default 30s.
        """
        client = cls()
        client._issuer = issuer.rstrip("/")

        # Dev mode
        resolved_dev_mode = (
            dev_mode
            if dev_mode is not None
            else (os.getenv("AUTHPLANE_DEV_MODE", "").lower() in ("true", "1", "yes"))
        )
        client._dev_mode = resolved_dev_mode
        client._dpop = dpop

        # Auth provider
        if isinstance(auth, ASCredentials):
            client._auth = ClientCredentialsProvider(
                auth.client_id,
                auth.client_secret,
            )
        elif auth is not None:
            client._auth = auth

        # Fetch settings — a single instance applies to both metadata and JWKS
        # fetches; both endpoints share the same SSRF policy in practice.
        client._fetch_settings = fetch_settings or FetchSettings.from_dev_mode(resolved_dev_mode)
        client._jwks_refresh_seconds = jwks_refresh_seconds
        client._metadata_refresh_seconds = metadata_refresh_seconds

        # Validate refresh intervals
        if jwks_refresh_seconds <= 0:
            raise ValueError(f"jwks_refresh_seconds must be positive, got {jwks_refresh_seconds}.")
        if metadata_refresh_seconds <= 0:
            raise ValueError(
                f"metadata_refresh_seconds must be positive, got {metadata_refresh_seconds}."
            )

        # Resilience
        client._token_cache = TokenCache(
            cache_ttl_buffer_seconds,
            default_ttl_seconds,
            cache_max_entries,
        )
        client._circuit_breaker = CircuitBreaker(
            circuit_breaker_threshold,
            circuit_breaker_cooldown_seconds,
        )

        # Initialize metadata + JWKS caches
        await client._initialize_caches()

        logger.info(
            "AuthplaneClient initialized",
            extra={"issuer": client._issuer, "dev_mode": client._dev_mode},
        )

        return client

    async def _initialize_caches(self) -> None:
        """Initialize metadata and JWKS caches."""
        metadata_url = build_metadata_url(self._issuer)

        # Set up metadata cache (needed for endpoint discovery)
        metadata_fetcher = DocumentFetcher(
            metadata_url,
            document_type="metadata",
            settings=self._fetch_settings,
            max_size=131072,  # 128KB for metadata
        )
        self._metadata_cache = MetadataCache(
            fetcher=metadata_fetcher.fetch,
            # RFC 8414 requires the advertised metadata issuer to match the
            # issuer we were configured with before any discovered endpoint is trusted.
            expected_issuer=self._issuer,
            allow_http=self._fetch_settings.allow_http,
            refresh_seconds=self._metadata_refresh_seconds,
            document_type="metadata",
            on_change=self._on_metadata_changed,
        )

        # Security-first: JWKS location is always discovery-derived; we do not
        # fall back to a synthesized default path anymore.
        self._jwks_uri = await self._metadata_cache.get_jwks_uri()
        logger.info(
            "JWKS URI discovered from AS metadata",
            extra={"jwks_uri": self._jwks_uri},
        )

        # Start JWKS cache
        jwks_fetcher = DocumentFetcher(
            self._jwks_uri,
            document_type="jwks",
            settings=self._fetch_settings,
            max_size=65536,  # 64KB for JWKS
        )
        self._jwks_cache = JWKSCache(
            fetcher=jwks_fetcher.fetch,
            refresh_seconds=self._jwks_refresh_seconds,
            document_type="jwks",
        )
        # Prime the cache
        await self._jwks_cache.get()

    async def _on_metadata_changed(
        self,
        old_metadata: dict[str, object],
        new_metadata: dict[str, object],
    ) -> None:
        """Handle metadata changes (e.g., JWKS URI rotation)."""
        # Log introspection_endpoint changes
        old_introspection = old_metadata.get("introspection_endpoint")
        new_introspection = new_metadata.get("introspection_endpoint")
        if old_introspection != new_introspection:
            logger.info(
                "introspection_endpoint changed in AS metadata",
                extra={
                    "old_introspection_endpoint": old_introspection,
                    "new_introspection_endpoint": new_introspection,
                },
            )

        new_jwks_uri = new_metadata.get("jwks_uri")
        if self._jwks_uri == new_jwks_uri:
            return

        logger.warning(
            "JWKS URI changed in AS metadata, restarting JWKS cache",
            extra={"old_jwks_uri": self._jwks_uri, "new_jwks_uri": new_jwks_uri},
        )

        # Rotation is applied eagerly so subsequent verifications fetch from the
        # newly advertised key set rather than silently continuing on stale metadata.
        if self._jwks_cache is not None:
            await self._jwks_cache.aclose()

        # Update URI and restart JWKS cache
        self._jwks_uri = str(new_jwks_uri) if new_jwks_uri else None
        if self._jwks_uri is not None:
            jwks_fetcher = DocumentFetcher(
                self._jwks_uri,
                document_type="jwks",
                settings=self._fetch_settings,
                max_size=65536,
            )
            self._jwks_cache = JWKSCache(
                fetcher=jwks_fetcher.fetch,
                refresh_seconds=self._jwks_refresh_seconds,
                document_type="jwks",
            )
            await self._jwks_cache.get()
            logger.info(
                "JWKS cache restarted with new URI",
                extra={"jwks_uri": self._jwks_uri},
            )

    # ----- Public API: Token operations -----

    async def client_credentials(
        self,
        scopes: list[str] | None = None,
        resources: list[str] | None = None,
    ) -> TokenResponse:
        """Obtain a machine token using client_credentials grant."""
        self._require_circuit_open()

        # Client-credentials results are safe to cache by requested scope/resource
        # because the SDK only uses this cache for its own outbound AS calls.
        scope_key = " ".join(scopes) if scopes else ""
        resource_key = ",".join(resources) if resources else ""
        cache_key = "cc:" + TokenCache.cache_key(scope_key, resource_key)
        cached = self._token_cache.get(cache_key)
        if cached:
            return TokenResponse(
                access_token=cached.access_token,
                token_type=cached.token_type,
                expires_in=cached.expires_in,
                scope=cached.scope,
                cnf_jkt=cached.cnf_jkt,
            )

        token_endpoint = await self._get_token_endpoint()
        try:
            result = await client_credentials_grant(
                token_endpoint,
                self._auth_headers,
                self._fetch_settings,
                scopes,
                resources,
                dpop_provider=self._dpop,
            )
            self._circuit_breaker.record_success()
            self._token_cache.set(
                cache_key,
                result.access_token,
                result.token_type,
                result.expires_in,
                result.scope,
                cnf_jkt=result.cnf_jkt,
            )
            return result
        except Exception as exc:
            self._handle_failure(exc)
            raise

    async def exchange(
        self,
        options: TokenExchangeOptions,
    ) -> TokenResponse:
        """Perform RFC 8693 token exchange."""
        self._require_circuit_open()
        token_endpoint = await self._get_token_endpoint()
        try:
            result = await exchange_token(
                token_endpoint,
                options,
                self._auth_headers,
                self._fetch_settings,
                dpop_provider=self._dpop,
            )
            self._circuit_breaker.record_success()
            return result
        except Exception as exc:
            self._handle_failure(exc)
            raise

    async def introspect(self, token: str) -> IntrospectionResponse:
        """Introspect a token (RFC 7662)."""
        self._require_circuit_open()
        endpoint = await self._get_introspection_endpoint()
        try:
            result = await introspect_token(
                endpoint,
                token,
                self._auth_headers,
                self._fetch_settings,
                dpop_provider=self._dpop,
            )
            self._circuit_breaker.record_success()
            return result
        except Exception as exc:
            self._handle_failure(exc)
            raise

    async def revoke(self, token: str) -> None:
        """Revoke a token (RFC 7009)."""
        self._require_circuit_open()
        endpoint = await self._get_revocation_endpoint()
        try:
            await revoke_token(
                endpoint,
                token,
                self._auth_headers,
                self._fetch_settings,
                dpop_provider=self._dpop,
            )
            self._circuit_breaker.record_success()
        except Exception as exc:
            self._handle_failure(exc)
            raise

    # ----- Resource factory -----

    def resource(
        self,
        resource: str,
        scopes: list[str] | None = None,
        *,
        allowed_algorithms: list[str] | None = None,
        clock_skew_seconds: int = 30,
        revocation_checker: "RevocationChecker | IntrospectionRevocation | None" = None,
        fail_closed: bool = False,
        inbound_dpop: InboundDPoPOptions | None = None,
    ) -> "AuthplaneResource":
        """Create a resource scoped to a URI.

        The resource uses this client's JWKS cache and metadata.

        When *fail_closed* is True, the verifier rejects tokens when the
        revocation checker raises an exception instead of the default
        fail-open behaviour.

        Inbound DPoP enforcement (RFC 9449 § 7) is configured per-resource
        via :class:`InboundDPoPOptions` per RFC 9728 § 2. Passing any
        ``InboundDPoPOptions`` instance (even default-constructed) is the
        explicit opt-in that turns on PRM advertising of
        ``dpop_signing_alg_values_supported`` and
        ``dpop_bound_access_tokens_required``; omitting the argument keeps
        DPoP fields out of PRM entirely.
        """
        from .verifier import AuthplaneResource

        return AuthplaneResource(
            client=self,
            resource=resource,
            scopes=scopes or [],
            allowed_algorithms=allowed_algorithms or ["RS256", "ES256"],
            clock_skew_seconds=clock_skew_seconds,
            revocation_checker=revocation_checker,
            fail_closed=fail_closed,
            inbound_dpop=inbound_dpop,
        )

    # ----- Internal: endpoint resolution -----

    async def _get_token_endpoint(self) -> str:
        if not self._metadata_cache:
            raise MetadataFetchError("authplane: AS metadata cache is not initialized")
        return await self._metadata_cache.get_token_endpoint()

    async def _get_introspection_endpoint(self) -> str:
        if not self._metadata_cache:
            raise MetadataFetchError("authplane: AS metadata cache is not initialized")
        return await self._metadata_cache.get_introspection_endpoint()

    async def _get_revocation_endpoint(self) -> str:
        if not self._metadata_cache:
            raise MetadataFetchError("authplane: AS metadata cache is not initialized")
        return await self._metadata_cache.get_revocation_endpoint()

    # ----- Internal: resilience -----

    def _require_circuit_open(self) -> None:
        if not self._circuit_breaker.allow():
            raise CircuitOpenError(
                "authplane: circuit breaker is open — AS may be unavailable",
                code="circuit_open",
            )

    def _handle_failure(self, exc: Exception) -> None:
        # SSRF failures are configuration/security rejections, not signs that the
        # AS is down, so they intentionally do not move the circuit state.
        if isinstance(exc, SSRFError):
            return
        # Transport failures and server-side failures are the outage signals the
        # breaker should react to.
        if isinstance(exc, (ServerError, httpx.RequestError)):
            self._circuit_breaker.record_failure()

    @property
    def _auth_headers(self) -> dict[str, str]:
        return self._auth.auth_headers() if self._auth else {}

    # ----- Internal: accessors for verifier -----

    @property
    def jwks_cache(self) -> JWKSCache | None:
        return self._jwks_cache

    @property
    def metadata_cache(self) -> MetadataCache | None:
        return self._metadata_cache

    @property
    def fetch_settings(self) -> FetchSettings:
        return self._fetch_settings

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def dev_mode(self) -> bool:
        return self._dev_mode

    @property
    def dpop(self) -> DPoPProvider | None:
        return self._dpop

    def dpop_headers(
        self,
        method: str,
        url: str,
        *,
        access_token: str = "",
    ) -> dict[str, str]:
        """Build DPoP proof headers for an outbound request to a downstream API."""
        if self._dpop is None:
            raise DPoPError("authplane: no DPoP provider configured")
        # This helper exposes the same proof generator used for AS calls so the
        # caller can reuse the configured DPoP key/nonce state for downstream APIs.
        return self._dpop.build_headers(method, url, access_token=access_token)

    # ----- Cleanup -----

    async def aclose(self) -> None:
        """Clean up resources (background tasks, caches)."""
        if self._jwks_cache:
            await self._jwks_cache.aclose()
        if self._metadata_cache:
            await self._metadata_cache.aclose()
