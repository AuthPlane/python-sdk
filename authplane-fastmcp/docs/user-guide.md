# authplane-fastmcp User Guide

OAuth 2.1 JWT authentication for [FastMCP](https://github.com/PrefectHQ/fastmcp) servers, powered by the [Authplane Python SDK](https://github.com/AuthPlane/python-sdk).

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Scope Enforcement](#scope-enforcement)
- [Accessing Token Claims](#accessing-token-claims)
- [Protected Resource Metadata (PRM)](#protected-resource-metadata-prm)
- [Token Revocation Checking](#token-revocation-checking)
- [Token Exchange (RFC 8693)](#token-exchange-rfc-8693)
- [URL Elicitation for Consent](#url-elicitation-for-consent)
- [Development Mode](#development-mode)
- [SSRF Protection](#ssrf-protection)
- [Resource Cleanup](#resource-cleanup)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)

---

## Installation

```bash
pip install authplane-fastmcp
```

Requires Python 3.11+.

## Quick Start

```python
from fastmcp import FastMCP
from authplane_fastmcp import authplane_auth

mcp = FastMCP(
    "My Server",
    **await authplane_auth(
        issuer="https://auth.company.com",
        base_url="https://mcp.company.com",
        scopes=["tools/query", "tools/write"],
    ),
)

@mcp.tool()
def query(sql: str) -> str:
    """Execute a query."""
    return run_query(sql)

mcp.run(transport="http", port=8080)
```

`authplane_auth()` performs RFC 8414 metadata discovery, fetches the JWKS, and wires up all authentication components. The result unpacks directly into `FastMCP()`.

## Configuration Reference

All parameters of `authplane_auth()`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `issuer` | `str` | *required* | Authorization server URL |
| `base_url` | `str` | *required* | Root URL of this FastMCP server |
| `scopes` | `list[str]` | `[]` | Scopes this server supports |
| `mcp_path` | `str` | `"/mcp"` | Mount path of the MCP endpoint. The JWT audience is derived as `base_url + mcp_path` |
| `as_credentials` | `ASCredentials` | `None` | Client credentials for introspection and token exchange |
| `dpop` | `DPoPProvider` | `None` | DPoP provider for outbound calls to the AS (introspection, token exchange) |
| `allowed_algorithms` | `list[str]` | `["RS256", "ES256"]` | Allowed JWT signature algorithms (asymmetric only) |
| `jwks_refresh_seconds` | `int` | `300` | JWKS cache TTL |
| `metadata_refresh_seconds` | `int` | `3600` | AS metadata cache TTL |
| `cache_ttl_buffer_seconds` | `float` | `30.0` | Buffer subtracted from token TTLs before cache expiry |
| `default_ttl_seconds` | `float` | `3600.0` | Fallback token cache TTL when responses omit expiry metadata |
| `circuit_breaker_threshold` | `int` | `5` | Transient failures before opening the AS circuit breaker |
| `circuit_breaker_cooldown_seconds` | `float` | `30.0` | Cooldown before allowing a half-open probe |
| `clock_skew_seconds` | `int` | `30` | Leeway for `exp`/`nbf`/`iat` validation |
| `dev_mode` | `bool` | `False` | Relaxes SSRF checks for local development |
| `revocation_checker` | see [below](#token-revocation-checking) | `None` | Token revocation strategy |
| `fetch_settings` | `FetchSettings` | `None` | Full SSRF / fetch settings applied to both metadata and JWKS fetches (overrides `dev_mode`) |
| `inbound_dpop` | `InboundDPoPOptions` | `None` | Per-resource inbound DPoP policy (replay store, max proof age, clock skew, accepted proof algorithms, `required`). When set, the resource advertises DPoP support in PRM (RFC 9728 §2). See **Inbound DPoP through the FastMCP adapter** below for current limitations. |

### Inbound DPoP through the FastMCP adapter

FastMCP's `TokenVerifier` builds on the upstream MCP `BearerAuthBackend`, which matches only `Authorization: Bearer ...` headers and exposes a bearer-only `verify_token(token: str)` protocol. RFC 9449 §7.1 DPoP-bound requests use the `Authorization: DPoP <token>` scheme and would be rejected at the framework layer before reaching this adapter.

Setting `inbound_dpop=InboundDPoPOptions(...)` therefore affects only Protected Resource Metadata advertising in the standard adapter integration; verify-time DPoP enforcement requires custom request-aware middleware that extracts the proof header and threads a `DPoPRequestContext` into `AuthplaneResource.verify(...)`.

## Scope Enforcement

Use FastMCP's built-in `require_scopes` decorator to enforce per-tool scope requirements:

```python
from fastmcp.server.auth import require_scopes

@mcp.tool(auth=require_scopes("tools/query"))
def query(sql: str) -> str:
    """Requires the tools/query scope."""
    return run_query(sql)

@mcp.tool(auth=require_scopes("tools/admin", "tools/delete"))
def delete_all() -> str:
    """Requires BOTH tools/admin AND tools/delete scopes."""
    return clear_database()
```

FastMCP enforces scopes **before** the handler runs. If the token is missing a required scope, FastMCP returns a 403 response and the handler is never called.

## Accessing Token Claims

### Dependency Injection (Recommended)

```python
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken

@mcp.tool()
async def my_tool(data: str, token: AccessToken = CurrentAccessToken()) -> str:
    # Standard JWT claims
    sub = token.claims.get("sub")         # Subject (user ID)
    jti = token.claims.get("jti")         # JWT ID
    iss = token.claims.get("iss")         # Issuer
    aud = token.claims.get("aud")         # Audience
    exp = token.claims.get("exp")         # Expiration (Unix timestamp)
    nbf = token.claims.get("nbf")         # Not before
    iat = token.claims.get("iat")         # Issued at

    # OAuth claims
    client_id = token.client_id           # Client ID
    scopes = token.scopes                 # List of granted scopes
    expires_at = token.expires_at         # Expiration (Unix timestamp)

    # Custom claims
    tenant = token.claims.get("tenant_id")
    org = token.claims.get("organization")

    return f"Hello {sub} from tenant {tenant}"
```

The `claims` dict contains the **full JWT payload** including all standard and custom claims.

### Imperative Access

```python
from fastmcp.server.dependencies import get_access_token

@mcp.tool()
async def my_tool(data: str) -> str:
    token = get_access_token()  # Returns None if unauthenticated
    if token:
        user = token.claims.get("sub")
    return f"Processing {data}"
```

## Protected Resource Metadata (PRM)

The adapter automatically serves [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/rfc9728/) at the well-known URI. This enables MCP clients to discover the authorization server and supported scopes.

The PRM endpoint location depends on the resource URL:

| Resource URL | PRM Endpoint |
|---|---|
| `https://mcp.company.com` | `GET /.well-known/oauth-protected-resource` |
| `https://mcp.company.com/api/v1` | `GET /.well-known/oauth-protected-resource/api/v1` |

The response includes:
- Authorization server URL (issuer)
- Supported scopes
- Bearer token methods
- Resource identifier

No additional configuration is needed; PRM is served automatically.

## Token Revocation Checking

By default, tokens are validated offline (signature + claims only). You can enable revocation checking to catch tokens that have been revoked before they expire.

### No Revocation (Default)

```python
await authplane_auth(
    issuer="https://auth.company.com",
    base_url="https://mcp.company.com",
    # revocation_checker is None by default
)
```

### RFC 7662 Introspection

Calls the authorization server's introspection endpoint to check if a token is still active:

```python
from authplane import ASCredentials, IntrospectionRevocation

await authplane_auth(
    issuer="https://auth.company.com",
    base_url="https://mcp.company.com",
    revocation_checker=IntrospectionRevocation(),
    as_credentials=ASCredentials(
        client_id="my_resource_server",
        client_secret="secret",
    ),
)
```

- The introspection endpoint is automatically discovered from AS metadata.
- If the endpoint returns `active=false`, the token is rejected with `TokenRevokedError`.
- **Fails open**: if the introspection endpoint is unavailable, the token is accepted (offline validation still applies).
- `as_credentials` enables authenticated introspection (recommended for production).

### Custom Revocation Checker

Implement your own revocation logic with an async callable:

```python
from authplane import VerifiedClaims

async def check_blocklist(claims: VerifiedClaims, raw_token: str) -> bool:
    """Return True to reject the token (it is revoked)."""
    return await redis_client.sismember("revoked_tokens", claims.jti)

await authplane_auth(
    issuer="https://auth.company.com",
    base_url="https://mcp.company.com",
    revocation_checker=check_blocklist,
)
```

## Token Exchange (RFC 8693)

Exchange an inbound token for a narrowly-scoped downstream token to call other services on behalf of the caller. The call goes to the authorization server's `token_endpoint` (discovered via RFC 8414 metadata), reuses the client's SSRF settings, and attaches DPoP proofs when a `DPoPProvider` was configured.

```python
from authplane import ASCredentials
from authplane.oauth import TokenExchangeOptions
from authplane_fastmcp import authplane_auth

result = await authplane_auth(
    issuer="https://auth.company.com",
    base_url="https://mcp.company.com",
    scopes=["tools/add"],
    as_credentials=ASCredentials(
        client_id="https://mcp.company.com/mcp",
        client_secret="s3cret",
    ),
)

downstream = await result.client.exchange(
    TokenExchangeOptions(
        subject_token=inbound_token,
        scope="tools/add",                           # narrow to the minimum
        resources=("https://downstream.example",),   # RFC 8707 audience binding
    )
)

# downstream.access_token — present to the downstream service
# downstream.expires_in    — lifetime in seconds
# downstream.token_type    — "Bearer" or "DPoP"
```

`TokenExchangeOptions` fields:

| Field | Type | Purpose |
|---|---|---|
| `subject_token` | `str` (required) | Token being exchanged (typically the inbound caller's token). |
| `subject_token_type` | `str` | RFC 8693 token-type URI; defaults to `urn:ietf:params:oauth:token-type:access_token`. |
| `actor_token` / `actor_token_type` | `str` | Optional actor (delegation) token. |
| `scope` | `str` | Space-separated scopes to request on the downstream token. |
| `resources` | `tuple[str, ...]` | Target resource identifiers (RFC 8707). Binds the downstream token's audience. |
| `audiences` | `tuple[str, ...]` | Explicit audiences when not using `resources`. |

`client.exchange()` raises `InvalidGrantError` on a rejected grant, `ConsentRequiredError` when the AS requires interactive user consent before issuance, `CircuitOpenError` when the AS circuit is open, and other `AuthplaneError` subclasses for transport/protocol failures. See [Error Handling](#error-handling) and [URL Elicitation for Consent](#url-elicitation-for-consent) below.

## URL Elicitation for Consent

When a token exchange needs interactive user consent at the AS (for example, first-time authorization against a third-party service), the AS returns `consent_required` with a `consent_url`. MCP surfaces this through the URL elicitation flow (JSON-RPC error `-32042`). The [`authplane-mcp`](../../authplane-mcp/docs/user-guide.md#url-elicitation-for-consent) adapter wires it up end-to-end.

**fastmcp 3.2.4 does not propagate `McpError` from tool handlers** (its tool dispatch wraps everything except `FastMCPError` as `{"isError": true}`), so `-32042` never reaches the wire. Handle `ConsentRequiredError` in the tool body for now:

```python
from authplane import ConsentRequiredError
from authplane.oauth import TokenExchangeOptions

@mcp.tool(auth=require_scopes("tools/call_downstream"))
async def call_downstream(payload: str) -> str:
    try:
        downstream = await auth_result.client.exchange(
            TokenExchangeOptions(subject_token=..., scope="downstream/write")
        )
    except ConsentRequiredError as error:
        return f"Consent required: {error.consent_url}"
    return await downstream_api_call(downstream.access_token, payload)
```

The client returned by `authplane_auth(...)` already wraps `exchange()` to raise `UrlElicitationRequiredError` for qualifying consent errors. Once fastmcp's tool path propagates `McpError`, this `try/except` simply stops triggering — no SDK changes needed. `to_url_elicitation_required_error` is exported for the same reason.

## Development Mode

For local development, enable `dev_mode` to relax SSRF restrictions and allow HTTP/localhost:

```python
await authplane_auth(
    issuer="http://localhost:9000",
    base_url="http://localhost:8080",
    scopes=["tools/query"],
    dev_mode=True,
)
```

Development mode allows:
- HTTP (non-TLS) connections
- Localhost addresses (`127.0.0.0/8`)
- Private network addresses (`10.x`, `172.16-31.x`, `192.168.x`)

Cloud metadata addresses (`169.254.x`) are **always blocked**, even in dev mode.

You can also enable dev mode via environment variable:

```bash
export AUTHPLANE_DEV_MODE=true
python myserver.py
```

## SSRF Protection

The adapter provides SSRF controls for JWKS and metadata fetching via `FetchSettings`.

For most use cases, `dev_mode=True` is sufficient for local development. Use `FetchSettings` when you need fine-grained control:

```python
from authplane import FetchSettings

settings = FetchSettings(
    ssrf_protection=True,
    allow_http=False,
    allow_localhost=True,
    allow_private_networks=True,
    timeout=10.0,
)

await authplane_auth(
    issuer="https://auth.internal.corp",
    base_url="https://api.prod.com",
    fetch_settings=settings,
)
```

When `fetch_settings` is provided, `dev_mode` is ignored for both metadata and JWKS fetches.

### Protection Details

| Check | Default | Description |
|-------|---------|-------------|
| HTTPS required | Yes | Blocks HTTP unless explicitly allowed |
| Localhost blocked | Yes | Blocks `127.0.0.0/8` |
| Private networks blocked | Yes | Blocks `10.x`, `172.16-31.x`, `192.168.x` |
| Cloud metadata blocked | **Always** | Blocks `169.254.x` (cannot be disabled) |
| DNS pinning | Yes | Resolves DNS once, validates the IP |
| Redirect blocking | Yes | Prevents open redirect attacks |
| Size limit | 64KB | Maximum JWKS response size |
| Timeout | 10s | HTTP request timeout |

## Resource Cleanup

`authplane_auth()` returns an `AuthplaneAuthResult` that holds background JWKS / metadata refresh tasks and an HTTP connection pool. Call `aclose()` on shutdown:

```python
result = await authplane_auth(...)
try:
    mcp = FastMCP("My Server", **result)
    await mcp.run_async(transport="http", port=8080)
finally:
    await result.aclose()
```

`result.aclose()` closes the underlying `AuthplaneClient`, cancels its background tasks, and releases connections. Skipping it surfaces as leaked tasks, open sockets, and `ResourceWarning` in tests.

## Error Handling

### Verification path

`AuthplaneTokenVerifier.verify_token` catches every `AuthplaneError` raised by `AuthplaneResource.verify()` (missing/expired/invalid/revoked token, DPoP failure, etc.) and returns `None`. FastMCP turns that into a uniform **401 Unauthorized** for the request — the adapter does not differentiate by error type.

### Scope enforcement

Scope checks happen *after* token validation succeeds and are a separate enforcement layer — see [Scope Enforcement](#scope-enforcement) above for `@mcp.tool(auth=require_scopes(...))`. Inside a handler, `claims.require_scope("…")` raises `InsufficientScopeError` (which `http_status()` maps to 403 if you call it).

### Catching SDK errors directly

If you call `AuthplaneResource.verify()` yourself (for example, in custom middleware or non-MCP code), the relevant exceptions to catch are the ones `verify()` actually raises:

```python
from authplane import (
    AuthplaneError,
    DPoPError,
    InvalidClaimsError,
    InvalidSignatureError,
    TokenExpiredError,
    TokenRevokedError,
)

try:
    claims = await verifier.verify(token)
except TokenRevokedError:
    log.warning("Revoked token used")
    raise
except (TokenExpiredError, InvalidSignatureError, InvalidClaimsError):
    raise  # 401-class verification failures
except DPoPError:
    raise  # RFC 9449 binding/proof failures
except AuthplaneError:
    raise  # everything else from the verifier
```

`InsufficientScopeError` is not raised by `verify()`; it comes from `claims.require_scope("…")` after a successful verification.

## API Reference

### `authplane_auth()`

```python
async def authplane_auth(
    issuer: str,
    base_url: str,
    scopes: list[str] | None = None,
    *,
    mcp_path: str = "/mcp",
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
) -> AuthplaneAuthResult
```

Async factory that performs metadata discovery, fetches JWKS, and returns an `AuthplaneAuthResult` ready to unpack into `FastMCP()`.

**Raises:**
- `ValueError` — invalid configuration (e.g., HMAC algorithm)
- `JWKSFetchError` — metadata discovery or JWKS fetch failed

### `AuthplaneAuthResult`

Returned by `authplane_auth()`. Supports `**` unpacking into `FastMCP()` — the mapping view yields only `auth`. `token_verifier` and `client` are exposed as plain attributes for advanced use cases. Call `await result.aclose()` on shutdown to release background tasks and HTTP connections.

| Attribute | Type | Description |
|-----------|------|-------------|
| `auth` | `RemoteAuthProvider` | Auth provider for FastMCP |
| `token_verifier` | `AuthplaneTokenVerifier` | Token verifier (for advanced / manual setup) |
| `client` | `AuthplaneClient` | Underlying SDK client (use `client.exchange()` for RFC 8693) |

### `AuthplaneTokenVerifier`

FastMCP `TokenVerifier` implementation.

| Method/Property | Description |
|-----------------|-------------|
| `verify_token(token: str) -> AccessToken \| None` | Validate JWT, return `AccessToken` or `None` |
| `verifier` (property) | Access underlying `AuthplaneResource` |
| `scopes_supported` (property) | Scopes configured in the verifier |

### Core SDK types

The adapter does not re-export core SDK types. Import them from `authplane`
(or `authplane.oauth` for token-operation types):

| Type | Import from |
|------|-------------|
| `ASCredentials`, `FetchSettings`, `IntrospectionRevocation`, `RevocationChecker`, DPoP types | `authplane` |
| Verification errors (`AuthplaneError`, `InsufficientScopeError`, `TokenExpiredError`, `TokenRevokedError`, `ConsentRequiredError`, …) | `authplane` |
| `TokenExchangeOptions`, `TokenResponse` | `authplane.oauth` |

### Security Properties

The adapter enforces (via the core SDK):

- **RFC 9068 compliance** — validates all 9 required JWT claims (`iss`, `aud`, `sub`, `client_id`, `exp`, `nbf`, `iat`, `jti`, `typ`)
- **Type header enforcement** — only accepts `typ: "at+jwt"`
- **Asymmetric algorithms only** — HMAC and `none` are rejected
- **SSRF protection** — DNS pinning, IP blocklists, protocol allowlists, redirect blocking
- **Background JWKS refresh** — refreshes at 80% of TTL to avoid request-time latency
- **Stale cache fallback** — uses cached JWKS if a refresh fails, maintaining availability
