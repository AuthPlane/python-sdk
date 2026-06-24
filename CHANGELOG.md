# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `TokenCache` is now bounded by a configurable `max_entries` cap (default `10_000`, exposed as `TokenCache.DEFAULT_MAX_ENTRIES` and a read-only `cache.max_entries` property) and evicts the least-recently-used entry on overflow; both `get` and `set` bump the touched key to MRU. Plumbed through `AuthplaneClient.create(cache_max_entries=...)`. Token-exchange cache keys are high-cardinality (the subject token is part of the key), so the cap keeps long-lived clients bounded.
- `VerifiedClaims.require_scopes(scopes: Iterable[str])` — plural AND-style helper that requires all listed scopes. Empty input is a no-op; on failure the raised `InsufficientScopeError` carries the full requested tuple on `required_scopes` and names every missing scope plus the token's available scopes in the message.
- `authplane-mcp`: new public surface — `AuthplaneRequestContextMiddleware`, `get_current_request()`, `install_request_context(mcp)` — an ASGI middleware that publishes the active request on a `ContextVar` so the verifier can build a `DPoPRequestContext`.
- `authplane-fastmcp`, `authplane-mcp`: `AuthplaneTokenVerifier` caches the in-flight verify task per request (keyed by access token on `request.state`), so a repeat `verify_token` within the same HTTP request awaits the same task rather than re-entering the inbound DPoP replay store. Cross-request replay protection is unaffected (distinct requests get distinct caches).

### Fixed
- `TokenCache.set` now distinguishes a missing `expires_in` from `expires_in: 0`. Both previously collapsed into `default_ttl`. The store now applies `default_ttl` only when `expires_in` is absent (`None`), treats `expires_in: 0` (RFC 6749 §5.1) as already expired and refuses to store it, and honors `n` seconds when positive. `parse_token_response` carries the missing-vs-zero distinction through the parser.
- `authplane-fastmcp`, `authplane-mcp`: inbound DPoP cardinality (RFC 9449 §4.3 #1) is now enforced. `read_dpop_header` reads the full multi-value `DPoP` header list (and splits on `,` defensively to catch proxies that pre-join duplicate headers) and raises `DPoPMultipleProofsError` when more than one non-empty proof is present. `www_authenticate` maps this error to `error="invalid_dpop_proof"` per RFC 9449 §7.1.
- `authplane-fastmcp`, `authplane-mcp`: inbound DPoP proof-of-possession is now enforced end-to-end. `AuthplaneTokenVerifier.verify_token` forwards a `DPoPRequestContext` (method + reconstructed `htu` + proof header) to `AuthplaneResource.verify`, so `inbound_dpop=InboundDPoPOptions(required=True)` checks the proof on every request. The `htu` origin is always the operator-configured resource URI, never the inbound `Host` / `X-Forwarded-Proto` headers. Operators using `required=True` with `authplane-mcp` should call `install_request_context(mcp)` after constructing `FastMCP` so the verifier can read the per-request context; if it is not installed the request fails closed (401) rather than skipping the check.
- `authplane-fastmcp`, `authplane-mcp`: DPoP `htu` reconstruction reads `scope["raw_path"]` to preserve percent-encoding (e.g. `%2F`) on the wire under ASGI, falling back to `request.url.path` when the server omits `raw_path`.
- `authplane-mcp`: `install_request_context(mcp)` is idempotent — repeated calls on the same `FastMCP` instance are no-ops.
- `require_scope` (singular) now renders an empty token scope set as `(none)` instead of `[]`, matching the plural helper's output. Logging pipelines keyed on the old `Token has scopes: []` string should be updated.
- Docs and demos now run adapter setup, the async server entry point (`run_streamable_http_async` / `run_async`), and `aclose()` in a single `asyncio.run(main())`, keeping the client's locks, HTTP pool, and background JWKS/metadata refresh tasks on one event loop.

### Changed
- **BREAKING (pre-1.0)** `TokenResponse.expires_in` and `CacheEntry.expires_in` are now typed `int | None` (was `int`), so a token response that omits `expires_in` is `None` rather than `0`. **Migration:** typed downstream callers reading `resp.expires_in` directly (arithmetic, comparison, formatting) must guard for `None`; treat `None` as "apply your default" and `0` as "already expired".

## [0.2.0] - 2026-05-20

### Security
- `www_authenticate()` now sanitizes CR, LF, double-quote, and backslash from every value it interpolates (`realm`, `error_description`, `scope`, `resource_metadata`), closing a header-injection path through attacker-influenced error messages.

### Fixed
- `DPoPNotSupportedError` now emits `WWW-Authenticate: Bearer` instead of `DPoP`. The resource is bearer-only by configuration, so advertising the DPoP scheme misled clients into retries that would fail the same way.
- `http_status(CircuitOpenError)` now returns `503` (was `500`). The circuit breaker is structurally identical to other temporary-AS-unavailability errors and should be retryable, not surfaced as an internal error.
- Outbound `Host` header now preserves non-default ports and brackets IPv6 hostnames, fixing DPoP `htu` validation against authservers on non-standard ports.
- Packaging issues discovered after the first release.
- Documentation links and demo references.
- `authplane-fastmcp` dependency range now correctly requires `fastmcp>=3.2,<4` (was `>=2.0`, which could resolve to a version the adapter can't import).

### Added
- `www_authenticate()` accepts `resource_metadata_url=` (RFC 9728 §5.1) and `scope=` (RFC 6750 §3) keyword arguments. When the caller does not pass `scope=`, the helper auto-populates it from `InsufficientScopeError.required_scopes`.
- `InsufficientScopeError` now carries a structured `required_scopes` attribute, populated automatically by `VerifiedClaims.require_scope()` so the wire challenge can advertise the missing scope.
- `response_headers_for(error, *, realm, resource_metadata_url, scope)` — bundled helper returning `(status, {"WWW-Authenticate": challenge})` in one call.
- Both adapter verifiers (`authplane-mcp`, `authplane-fastmcp`) now emit a `logging.DEBUG` event `authplane.token_verification_failed` with structured `error_class` and `error` fields before returning `None`. Wire behaviour is unchanged; operators can now distinguish expired tokens from JWKS outages and DPoP replays in logs.

### Changed
- CI and release workflow improvements from first-release learnings.

## [0.1.0] - 2026-05-11

- Initial release.
