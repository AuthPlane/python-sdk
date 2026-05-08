# authplane-mcp User Guide

OAuth 2.1 JWT authentication for the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), powered by the [Authplane Python SDK](https://github.com/AuthPlane/python-sdk).

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
pip install authplane-mcp
```

Requires Python 3.11+.

## Quick Start

```python
from mcp.server.fastmcp import FastMCP
from authplane_mcp import authplane_mcp_auth, require_scope

mcp = FastMCP(
    "My Server",
    port=8080,
    json_response=True,
    **await authplane_mcp_auth(
        issuer="https://auth.company.com",
        resource="https://mcp.company.com",
        scopes=["tools/query", "tools/write"],
    ),
)

@mcp.tool()
async def query(sql: str) -> str:
    """Execute a query."""
    require_scope("tools/query")
    return run_query(sql)

mcp.run(transport="streamable-http")
```

`authplane_mcp_auth()` performs RFC 8414 metadata discovery, fetches the JWKS, and returns a dict with `token_verifier` and `auth` keys that unpack directly into `FastMCP()`.

## Configuration Reference

All parameters of `authplane_mcp_auth()`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `issuer` | `str` | *required* | Authorization server URL |
| `resource` | `str` | *required* | URL of this MCP server (used as JWT audience) |
| `scopes` | `list[str]` | `[]` | Scopes this server supports |
| `enforce_scopes_on_all_requests` | `bool` | `False` | When `True`, the MCP SDK both advertises `scopes` in PRM `scopes_supported` and rejects any request whose token lacks all of them. Workaround for an MCP SDK limitation: `AuthSettings` has no separate "supported" field. Per-tool `require_scope()` is the recommended granular pattern; this flag enables coarse request-layer enforcement and PRM advertising. |
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
| `inbound_dpop` | `InboundDPoPOptions` | `None` | Per-resource inbound DPoP policy (replay store, max proof age, clock skew, accepted proof algorithms, `required`). When set, the resource advertises DPoP support in PRM (RFC 9728 §2). See **Inbound DPoP through the MCP adapter** below for current limitations. |

### Inbound DPoP through the MCP adapter

The upstream `mcp.server.auth` framework integrates with token verifiers through a bearer-only `TokenVerifier.verify_token(token: str)` protocol. Its `BearerAuthBackend` matches only `Authorization: Bearer ...` headers and never reads the `DPoP` request header — RFC 9449 §7.1 DPoP-bound requests use the `Authorization: DPoP <token>` scheme and would be rejected at the framework layer before reaching this adapter.

Setting `inbound_dpop=InboundDPoPOptions(...)` therefore affects only Protected Resource Metadata advertising in the standard adapter integration; verify-time DPoP enforcement requires custom request-aware middleware that extracts the proof header and threads a `DPoPRequestContext` into `AuthplaneResource.verify(...)`.

## Scope Enforcement

Use the `require_scope()` helper at the top of tool handlers to enforce per-tool scope requirements:

```python
from authplane_mcp import require_scope

@mcp.tool()
async def query(sql: str) -> str:
    """Requires the tools/query scope."""
    require_scope("tools/query")
    return run_query(sql)

@mcp.tool()
async def delete_all() -> str:
    """Requires the tools/admin scope."""
    require_scope("tools/admin")
    return clear_database()
```

If the token is missing the required scope, `require_scope()` raises a `PermissionError`. The MCP server catches this and returns an error result (`isError: true`) to the client. The rest of the handler is never executed.

### How It Works

`require_scope()` reads the current request's access token from the MCP request context. It checks if the token's scopes include the required scope string. If the token is absent or the scope is missing, it raises `PermissionError`.

## Accessing Token Claims

Use the MCP SDK's `get_access_token()` to access the validated token in tool handlers:

```python
from mcp.server.auth.middleware.auth_context import get_access_token

@mcp.tool()
async def my_tool(data: str) -> str:
    token = get_access_token()
    if token:
        client_id = token.client_id       # Client ID
        scopes = token.scopes             # List of granted scopes
        expires_at = token.expires_at     # Expiration (Unix timestamp)
        resource = token.resource         # Resource (audience) URL
    return f"Processing {data}"
```

The `AccessToken` fields populated by the adapter:

| Field | Type | Description |
|-------|------|-------------|
| `token` | `str` | Raw JWT string |
| `client_id` | `str` | OAuth client ID |
| `scopes` | `list[str]` | Granted scopes |
| `expires_at` | `int` | Expiration Unix timestamp |
| `resource` | `str` | Resource identifier (audience) |

## Protected Resource Metadata (PRM)

The MCP SDK automatically serves [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/rfc9728/) at a well-known URI. This enables MCP clients to discover the authorization server and supported scopes.

The PRM endpoint location depends on the resource URL:

| Resource URL | PRM Endpoint |
|---|---|
| `https://mcp.company.com` | `GET /.well-known/oauth-protected-resource` |
| `https://mcp.company.com/mcp` | `GET /.well-known/oauth-protected-resource/mcp` |

The response includes:
- Authorization server URL (issuer)
- Supported scopes
- Bearer token methods
- Resource identifier

No additional configuration is needed; PRM is served automatically by the MCP SDK.

## Token Revocation Checking

By default, tokens are validated offline (signature + claims only). You can enable revocation checking to catch tokens that have been revoked before they expire.

### No Revocation (Default)

```python
await authplane_mcp_auth(
    issuer="https://auth.company.com",
    resource="https://mcp.company.com",
    # revocation_checker is None by default
)
```

### RFC 7662 Introspection

Calls the authorization server's introspection endpoint to check if a token is still active:

```python
from authplane import ASCredentials, IntrospectionRevocation

await authplane_mcp_auth(
    issuer="https://auth.company.com",
    resource="https://mcp.company.com",
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

await authplane_mcp_auth(
    issuer="https://auth.company.com",
    resource="https://mcp.company.com",
    revocation_checker=check_blocklist,
)
```

## Token Exchange (RFC 8693)

Exchange an inbound token for a narrowly-scoped downstream token to call other services on behalf of the caller. The call goes to the authorization server's `token_endpoint` (discovered via RFC 8414 metadata), reuses the client's SSRF settings, and attaches DPoP proofs when a `DPoPProvider` was configured.

```python
from authplane import ASCredentials
from authplane.oauth import TokenExchangeOptions
from authplane_mcp import authplane_mcp_auth

result = await authplane_mcp_auth(
    issuer="https://auth.company.com",
    resource="https://mcp.company.com",
    scopes=["tools/add"],
    as_credentials=ASCredentials(
        client_id="https://mcp.company.com",
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

`client.exchange()` raises `InvalidGrantError` on a rejected grant, `ConsentRequiredError` when the AS requires interactive user consent before issuance, `CircuitOpenError` when the AS circuit is open, and other `AuthplaneError` subclasses for transport/protocol failures. See [Error Handling](#error-handling).

## URL Elicitation for Consent

Some token exchanges require the user to complete interactive consent at the authorization server before a downstream token can be issued (for example, first-time authorization against a third-party service). The AS signals this with an OAuth error of `consent_required` or `interaction_required` and — when capable — a `consent_url` the user must visit.

MCP clients surface this through the **URL elicitation** flow (JSON-RPC error code `-32042`): the server raises an `UrlElicitationRequiredError` carrying the consent URL, and the MCP client prompts the user to open it. After the user completes consent, the client retries the call.

The adapter handles this for you. The `client` returned by `authplane_mcp_auth(...)` is wrapped so that `client.exchange(...)` automatically translates a qualifying `ConsentRequiredError` (one that carries a `consent_url`) into `UrlElicitationRequiredError`. **No tool-side error handling is needed:**

```python
from authplane.oauth import TokenExchangeOptions

@mcp.tool()
async def call_downstream(user_token: str, payload: str) -> str:
    downstream = await result.client.exchange(
        TokenExchangeOptions(subject_token=user_token, scope="downstream/write")
    )  # raises UrlElicitationRequiredError transparently when consent is needed
    return await downstream_api_call(downstream.access_token, payload)
```

The elicitation message is generated by `ConsentRequiredError.describe()` and uses the format `"<message> (<service_id>: <cause_detail>)"`.

**Errors that pass through unchanged:**

- Non-consent errors (`InvalidGrantError`, `CircuitOpenError`, transport failures, etc.).
- `ConsentRequiredError` without a `consent_url` — the AS signaled consent is needed but provided no URL the user can complete it at; the original SDK error propagates so the application can decide how to surface it.

**Manual translation (escape hatch).** If you need to map a consent error to MCP `-32042` outside `client.exchange()` (for example, you produce a `ConsentRequiredError` from your own logic), call the underlying primitive:

```python
from authplane_mcp import to_url_elicitation_required_error

mapped = to_url_elicitation_required_error(error)
if mapped is not None:
    raise mapped
raise error
```

`to_url_elicitation_required_error` returns the MCP-shaped exception when the input is a `ConsentRequiredError` with a `consent_url`, otherwise `None`.

## Development Mode

For local development, enable `dev_mode` to relax SSRF restrictions and allow HTTP/localhost:

```python
await authplane_mcp_auth(
    issuer="http://localhost:9000",
    resource="http://localhost:8080/mcp",
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

await authplane_mcp_auth(
    issuer="https://auth.internal.corp",
    resource="https://api.prod.com",
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

`authplane_mcp_auth()` returns an `AuthplaneAuthResult` that holds background JWKS / metadata refresh tasks and an HTTP connection pool. For a long-running server that exits with the process, the README quickstart shape is sufficient — the OS reaps everything on exit:

```python
auth_result = asyncio.run(authplane_mcp_auth(...))
mcp = FastMCP("My Server", **auth_result)
mcp.run(transport="streamable-http")  # starts its own event loop and blocks
```

`mcp.run()` starts its own event loop internally, so it cannot share a loop with `await auth_result.aclose()`. If you need explicit teardown (tests, or an embedded server that should release resources without exiting the process), drive the MCP SDK's async server entry point so the auth setup, server, and `aclose()` share one loop:

```python
import asyncio

async def main() -> None:
    auth_result = await authplane_mcp_auth(...)
    try:
        mcp = FastMCP("My Server", **auth_result)
        await mcp.run_streamable_http_async()
    finally:
        await auth_result.aclose()

asyncio.run(main())
```

`auth_result.aclose()` closes the underlying `AuthplaneClient`, cancels its background tasks, and releases connections. In test code, skipping it surfaces as leaked tasks, open sockets, and `ResourceWarning`. Each transport has an async equivalent: `run_streamable_http_async`, `run_sse_async`, `run_stdio_async`.

## Error Handling

### Verification path

`AuthplaneTokenVerifier.verify_token` catches every `AuthplaneError` raised by `AuthplaneResource.verify()` (missing/expired/invalid/revoked token, DPoP failure, etc.) and returns `None`. The MCP server turns that into a uniform **401 Unauthorized** for the request — the adapter does not differentiate by error type.

### Scope enforcement

Scope checks happen *after* token validation succeeds and are a separate enforcement layer — see [Scope Enforcement](#scope-enforcement) above for the `require_scope()` helper. Inside a handler, `claims.require_scope("…")` raises `InsufficientScopeError` (which `http_status()` maps to 403 if you call it).

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

### `authplane_mcp_auth()`

```python
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
) -> AuthplaneAuthResult
```

Async factory that performs metadata discovery, fetches JWKS, and returns an `AuthplaneAuthResult` ready to unpack into `FastMCP()` (only `token_verifier` and `auth` are exposed in the mapping view; `client` is on the result for advanced use).

**Raises:**
- `ValueError` — invalid configuration (e.g., HMAC algorithm)
- `JWKSFetchError` — metadata discovery or JWKS fetch failed

### `require_scope()`

```python
def require_scope(scope: str) -> None
```

Enforce a scope requirement inside a tool handler. Raises `PermissionError` if the current request token is missing the scope.

### `AuthplaneTokenVerifier`

MCP SDK `TokenVerifier` implementation.

| Method/Property | Description |
|-----------------|-------------|
| `verify_token(token: str) -> AccessToken \| None` | Validate JWT, return `AccessToken` or `None` |
| `verifier` (property) | Access underlying `AuthplaneResource` |

### `AuthplaneAuthResult`

Returned by `authplane_mcp_auth()`. Supports `**` unpacking into `FastMCP()` — the mapping view yields `token_verifier` and `auth`. `client` is exposed as a plain attribute for RFC 8693 token exchange. Call `await result.aclose()` on shutdown to release background tasks and HTTP connections.

| Attribute | Type | Description |
|-----------|------|-------------|
| `token_verifier` | `AuthplaneTokenVerifier` | Token verifier for MCP |
| `auth` | `AuthSettings` | Auth settings for MCP |
| `client` | `AuthplaneClient` | Underlying SDK client (use `client.exchange()` for RFC 8693) |

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
