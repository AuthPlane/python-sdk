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
    FetchResult,
    JWKSCache,
    MetadataCache,
    build_metadata_url,
    validate_prm_resource_identifier,
    validate_resource_metadata_url,
)
from .net import FetchSettings
from .net.ssrf import SSRFError
from .oauth import (
    IntrospectionResponse,
    IntrospectionRevocation,
    TokenExchangeOptions,
    TokenResponse,
    client_credentials_grant,
    exchange_token,
    introspect_token,
    revoke_token,
)

if TYPE_CHECKING:
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

        Discovers AS metadata and primes the JWKS cache. Refreshes are driven by
        traffic, not by a task started here: the first background refresh is
        spawned by a read that finds the document past 80% of its TTL.

        Args:
            issuer: Authorization-server issuer URL (the prefix RFC 8414 metadata
                is fetched from). Stored verbatim and compared byte-for-byte; a
                trailing slash is significant and is preserved.
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
            metadata_refresh_seconds: AS metadata re-read interval (must be > 0).
                Governs verification traffic as well as outbound AS calls: once
                the interval has elapsed, the next ``verify()`` re-reads
                metadata and follows a rotated ``jwks_uri``.
            cache_ttl_buffer_seconds: Safety margin subtracted from each token's
                lifetime before the entry is considered expired. Default 30s.
            default_ttl_seconds: Fallback lifetime applied when the AS omits
                ``expires_in``. Default 3600s.
            cache_max_entries: Maximum number of cached tokens before
                least-recently-used eviction kicks in. Default
                :attr:`TokenCache.DEFAULT_MAX_ENTRIES` (10_000). Must be a
                positive integer (``bool``/``float`` rejected — see
                :class:`TokenCache`).
            circuit_breaker_threshold: Consecutive AS failures before the
                circuit opens. Default 5.
            circuit_breaker_cooldown_seconds: Half-open probe interval after the
                circuit trips. Default 30s.

        Raises:
            InvalidIssuerError: If ``issuer`` carries a query or a fragment
                component (RFC 8414 §2 forbids both), contains whitespace or
                a control character (RFC 3986 §2 — ``urlsplit`` removes tab,
                CR and LF from anywhere in the input, so the derived fetch
                target would differ from the identifier the AS-metadata
                comparison is seeded with), is not an absolute URL
                with a scheme and a host (RFC 8414 §2 requires a URL; §3.1
                inserts the well-known suffix after the host, so without one
                there is no derivable metadata URL), or carries a userinfo
                subcomponent (RFC 9110 §4.2.4 — the issuer is published to
                unauthenticated callers in the PRM document's
                ``authorization_servers`` member). This fails fast at
                construction, before any network fetch. Subclasses ``ValueError``,
                so an existing ``except ValueError`` still catches it.
        """
        client = cls()
        # Identity: the issuer is an identifier (RFC 9068 `iss`), stored verbatim
        # and compared byte-for-byte. Do NOT strip a trailing slash here — an AS
        # whose issuer ends in `/` mints tokens whose `iss` keeps the slash, and
        # normalizing it away rejects every token. Slash stripping belongs only
        # to .well-known URL derivation (see build_metadata_url), not to identity.
        client._issuer = issuer

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
        )

        # Security-first: JWKS location is always discovery-derived; we do not
        # fall back to a synthesized default path anymore. Read once here so a
        # metadata document that is unreachable, rejected, or silent about
        # ``jwks_uri`` fails ``create()`` as a metadata problem, rather than
        # reaching the operator wrapped in whatever the first key-set fetch
        # happened to raise. The value is not retained: every fetch resolves it
        # again from the document current at that moment.
        jwks_uri = await self._metadata_cache.get_jwks_uri()
        logger.info(
            "JWKS URI discovered from AS metadata",
            extra={"jwks_uri": jwks_uri},
        )

        self._jwks_cache = JWKSCache(
            fetcher=self._fetch_jwks,
            refresh_seconds=self._jwks_refresh_seconds,
            document_type="jwks",
            # The key set's TTL says when its *contents* may have changed. It
            # says nothing about the AS having published them somewhere else,
            # which is what a `jwks_uri` rotation is — so the cache is given the
            # means to compare where its keys came from against where metadata
            # currently says they live.
            source_resolver=self._metadata_cache.get_jwks_uri,
        )
        # Prime the cache
        await self._jwks_cache.get()

    async def _fetch_jwks(self) -> FetchResult:
        """Fetch the key set from wherever the current AS metadata says it lives.

        The location is resolved per fetch instead of being captured at
        construction and rebound when the document changes. There is then no
        second cache object to swap: a rotation takes effect on the next key-set
        fetch, whichever path reaches it first.

        Resolving the URI and committing the key set are separate awaits, so a
        metadata refresh that commits a rotated document in between still
        leaves a key set fetched from the withdrawn URI in the cache. What no
        longer follows is that it keeps being served: :class:`JWKSCache` is
        given the means to compare where its key set came from against where
        metadata currently says the keys live, and refetches when the two
        disagree rather than waiting out its own TTL. Recovery is therefore not
        contingent on the rotation also introducing a new `kid` — a re-key
        under a stable `kid` produces no miss to recover on.

        The URI comes from the validated document, so a metadata response that
        fails validation cannot redirect key retrieval; and if the newly
        advertised URI is unreachable, the fetch fails and :class:`JWKSCache`
        keeps serving the keys it already had rather than being left empty.
        """
        if self._metadata_cache is None:  # pragma: no cover - set before this is reachable
            raise MetadataFetchError("authplane: AS metadata cache is not initialized")
        jwks_uri = await self._metadata_cache.get_jwks_uri()
        jwks_fetcher = DocumentFetcher(
            jwks_uri,
            document_type="jwks",
            settings=self._fetch_settings,
            max_size=65536,  # 64KB for JWKS
        )
        return await jwks_fetcher.fetch()

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
        resource_metadata_url: str | None = None,
    ) -> "AuthplaneResource":
        """Create a resource scoped to a URI.

        The resource uses this client's JWKS cache and metadata.

        When a *revocation_checker* is configured and the check itself fails
        — introspection unreachable, an error response, a custom checker
        raising — **the token is let through** and a warning is logged. Pass
        ``fail_closed=True`` to refuse it instead. The default keeps the
        resource server answering while the AS is unreachable, which is what
        local JWT validation is for; ``fail_closed=True`` trades that
        availability for never honouring a token it could not confirm. See
        :class:`~authplane.IntrospectionRevocation` for the trade-off in
        full.

        ``fail_closed`` is only consulted when a revocation check actually
        runs. Both halves of that pairing are logged at construction when
        they point the surprising way: setting the flag without a checker
        (nothing to fail), and configuring a checker while leaving the
        fail-open default in place.

        Inbound DPoP enforcement (RFC 9449 § 7) is configured per-resource
        via :class:`InboundDPoPOptions` per RFC 9728 § 2. Passing any
        ``InboundDPoPOptions`` instance (even default-constructed) is the
        explicit opt-in that turns on PRM advertising of
        ``dpop_signing_alg_values_supported`` and
        ``dpop_bound_access_tokens_required``; omitting the argument keeps
        DPoP fields out of PRM entirely.

        ``resource_metadata_url`` overrides the URL advertised as RFC 9728
        §5.1 ``resource_metadata``, for a deployment where the Protected
        Resource Metadata document is served by the authorization server
        rather than by this resource — authserver >= 0.2.0 serves one per
        registered Resource. It changes what
        :meth:`~authplane.verifier.AuthplaneResource.resource_metadata_url`
        returns, and nothing else: the resource identifier, the token
        ``aud`` check, and the document :meth:`prm_response
        <authplane.verifier.AuthplaneResource.prm_response>` builds are
        untouched. Leave it unset — the default — and the advertised URL is
        the RFC 9728 §3.1 derivation of the resource identifier, byte for
        byte what it was before this option existed.

        Raises:
            InvalidResourceError: If *resource* carries a fragment component
                (RFC 8707 §2 forbids one in a resource indicator), contains
                whitespace or a control character (RFC 3986 §2; parsing would
                strip it, diverging from the identifier stored verbatim,
                RFC 9728 §3.3), is not an absolute URL with a scheme and a
                host (RFC 8707 §2 requires an absolute URI; RFC 9728 §3
                derives the metadata URL by inserting the well-known suffix
                after the host), carries a userinfo subcomponent
                (RFC 9110 §4.2.4 — the identifier reaches a 401 challenge, an
                ``htu`` origin, and log records, so embedded credentials are
                rejected outright), or carries a port that does not parse
                (RFC 3986 §3.2.3). Rejected here, at construction, for the
                same reason ``create()`` rejects a malformed issuer — the
                alternative is surfacing it from ``prm_url()`` while composing
                an RFC 9728 challenge, i.e. from inside a 401 response path.
                Subclasses ``ValueError``, so an existing ``except
                ValueError`` still catches it. Also raised when
                *resource_metadata_url* is not an absolute ``http`` /
                ``https`` URL, or carries a fragment, whitespace or a control
                character, a userinfo subcomponent, a ``"`` or a ``\\``, or a
                port that does not parse — see
                :func:`~authplane.validate_resource_metadata_url`. Same
                reasoning: the value is advertised in a challenge served to an
                unauthenticated caller, so a bad one is a startup failure, not
                a 401-path one.
            ValueError: If *allowed_algorithms* contains an algorithm outside
                ``("RS256", "ES256")``. Raised by
                :class:`~authplane.verifier.AuthplaneResource`'s constructor,
                which this method forwards to, and propagated unchanged.
        """
        from .verifier import AuthplaneResource

        # Deliberately duplicated: AuthplaneResource.__init__ runs this same
        # gate, and it — not this call — is the authoritative one, since it also
        # covers constructing the package-root export directly. What this call
        # is load-bearing for is the traceback: it raises at the line the
        # operator wrote, symmetrically with the issuer guard in create(),
        # rather than one frame deeper in the constructor. Pinned by
        # test_client_resource_rejects_fragment_at_construction, which asserts
        # the invoking frame — deleting this line turns that test red rather
        # than changing behaviour.
        validate_prm_resource_identifier(resource)

        # Same pairing, same reason, for the override: redundant for the
        # guarantee (the constructor gates it too) and load-bearing for the
        # traceback. Kept on the same line of defence as the identifier so the
        # two configured URLs of this factory are diagnosed together.
        if resource_metadata_url is not None:
            validate_resource_metadata_url(resource_metadata_url)

        # fail_closed is only consulted when a revocation check runs; setting
        # it without a checker means no revocation check happens at all, which
        # is the opposite of what the operator asked for — make it observable.
        if fail_closed and revocation_checker is None:
            logger.warning(
                "fail_closed=True has no effect without a revocation_checker: "
                "no revocation check will run",
                extra={"resource": resource},
            )

        # The mirror image, and the more surprising of the two: an operator who
        # configured a revocation checker asked for a stricter posture, and the
        # default answers an unanswerable "is this token still valid?" with yes.
        # Say so at startup rather than only per failed check, where it arrives
        # after the token was already accepted.
        #
        # INFO, not WARNING, and the difference is deliberate: the mirror case
        # above is a mistake — the flag does nothing — while this one is a
        # documented, defensible choice. `fail_closed=False` is the default and
        # the user guide recommends keeping it when availability matters, so an
        # operator who read that section and chose it would have no way to
        # acknowledge a WARNING short of filtering this logger — the same logger
        # carrying the mistake above and the per-check fail-open warning. The
        # realistic outcome is that they filter it and lose all three.
        if revocation_checker is not None and not fail_closed:
            logger.info(
                "Revocation checking is fail-open: a failed revocation check accepts "
                "the token. Pass fail_closed=True to reject instead",
                extra={"resource": resource},
            )

        # The introspection-credentials warning is not duplicated here the way
        # validate_prm_resource_identifier is: that one raises, so the extra
        # frame buys a traceback at the operator's own line, while this one
        # logs and a second copy would just be a duplicate record at startup.
        # It lives on AuthplaneResource.__init__, which every path reaches.

        return AuthplaneResource(
            client=self,
            resource=resource,
            scopes=scopes or [],
            allowed_algorithms=allowed_algorithms or ["RS256", "ES256"],
            clock_skew_seconds=clock_skew_seconds,
            revocation_checker=revocation_checker,
            fail_closed=fail_closed,
            inbound_dpop=inbound_dpop,
            resource_metadata_url=resource_metadata_url,
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
        # breaker should react to. Every other AuthError — including the 403
        # `access_denied` a non-allowlisted cross-client exchange gets and the
        # 400 `invalid_target` for a resource indicator that matches nothing —
        # is the AS answering, not the AS failing, and stays out of the count.
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
    def can_authenticate(self) -> bool:
        """True when the client holds AS credentials it can introspect with."""
        return self._auth is not None

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
