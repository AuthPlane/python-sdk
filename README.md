# Authplane Python SDK

[![CI](https://img.shields.io/github/actions/workflow/status/AuthPlane/python-sdk/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AuthPlane/python-sdk/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/AuthPlane/python-sdk/release.yml?style=flat-square&label=release)](https://github.com/AuthPlane/python-sdk/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

OAuth 2.1 JWT validation and token operations for Python resource servers, with first-class adapters for Model Context Protocol (MCP) servers.

## Why Authplane

- **One call wires up everything.** `authplane_auth()` (FastMCP) or `authplane_mcp_auth()` (MCP) does RFC 8414 metadata discovery, fetches the JWKS, validates RFC 9068 access tokens, and serves RFC 9728 Protected Resource Metadata — unpacked straight into your MCP server.
- **Secure defaults.** Asymmetric algorithms only, strict claim validation, SSRF-hardened fetches, background JWKS refresh, and a circuit breaker around the AS — out of the box.
- **Standards-aligned.** OAuth 2.1, DPoP (RFC 9449), Token Exchange (RFC 8693), Token Introspection (RFC 7662), Token Revocation (RFC 7009), Resource Indicators (RFC 8707).

## Quickstart — FastMCP server with auth

```python
import asyncio
from authplane_fastmcp import authplane_auth
from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes

async def main() -> None:
    result = await authplane_auth(
        issuer="https://auth.company.com",
        base_url="https://mcp.company.com",
        scopes=["tools/query"],
    )
    mcp = FastMCP("My Server", **result)

    @mcp.tool(auth=require_scopes("tools/query"))
    def query(sql: str) -> str:
        return f"Ran: {sql}"  # replace with your real handler

    try:
        await mcp.run_async(transport="http", port=8080)
    finally:
        await result.aclose()

asyncio.run(main())
```

That's a complete, secure, standards-compliant MCP resource server. Swap `authplane-fastmcp` for `authplane-mcp` to use the official MCP Python SDK instead — see each adapter's README for the equivalent snippet.

## Packages

| Package | Install | Purpose |
|---|---|---|
| [`authplane-sdk`](authplane/README.md) | `pip install authplane-sdk` | Framework-agnostic JWT validation, AS metadata discovery, and token operations |
| [`authplane-mcp`](authplane-mcp/README.md) | `pip install authplane-mcp` | Adapter for the official MCP Python SDK |
| [`authplane-fastmcp`](authplane-fastmcp/README.md) | `pip install authplane-fastmcp` | Adapter for [FastMCP](https://github.com/PrefectHQ/fastmcp) |

Adapter packages depend on `authplane-sdk`, so installing one adapter brings the core SDK along. Adapter packages export only the adapter-specific glue (`authplane_auth`, `AuthplaneAuthResult`, `AuthplaneTokenVerifier`, etc.); core types (`ASCredentials`, `FetchSettings`, `IntrospectionRevocation`, errors) come from `authplane`, and `TokenExchangeOptions` / `TokenResponse` from `authplane.oauth`.

Requires Python 3.11+.

## Capabilities

### Standards and RFCs

- OAuth 2.1 (draft-ietf-oauth-v2-1)
- RFC 8414 — Authorization Server Metadata discovery
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- RFC 7662 — Token Introspection
- RFC 7009 — Token Revocation
- RFC 8693 — Token Exchange
- RFC 8707 — Resource Indicators
- RFC 9449 — DPoP (sender-constrained access tokens)
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 6750 — Bearer Token Usage
- RFC 7234 — HTTP caching semantics on discovery responses
- RFC 7519 / 7517 — JWT and JWKS

### Security

- JWT signature, issuer, audience, `exp` / `nbf` / `iat`, and `typ` (`at+jwt`) validation; required claims enforced (`sub`, `client_id`, `exp`, `iat`, `jti`)
- Algorithm-confusion defenses: only `RS256` and `ES256` (asymmetric) are accepted; `none`, `HS256`, `HS384`, `HS512` are always rejected at construction
- AS metadata hardening: discovered `issuer` must match configured issuer exactly; required endpoints must be present
- SSRF hardening on outbound HTTP: DNS pinning, private/loopback/link-local/cloud-metadata IP blocking, HTTPS-only, response size limits, no redirects
- HTTPS-only by default with a `dev_mode` toggle for `localhost` and private networks
- JWKS resilience: stale-cache fallback, background refresh at 80% TTL, force-refresh on `kid` miss, coordinated fetches
- Inbound DPoP proof verification: binding, replay, `htm` / `htu` / `ath` checks
- Outbound DPoP proof generation with nonce retry and pluggable nonce storage
- Circuit breaker around authorization-server calls
- Token caching with TTL buffers

### Framework integrations

- Official MCP Python SDK → [`authplane-mcp`](authplane-mcp/README.md)
- FastMCP → [`authplane-fastmcp`](authplane-fastmcp/README.md)

### Observability

- Structured logging (`logging` module) across JWKS refresh, metadata discovery, circuit breaker transitions, token verification, and DPoP binding outcomes
- Strict Pyright typing and immutable validated claims

## Documentation

- Core SDK: [`authplane/README.md`](authplane/README.md) · [User Guide](authplane/docs/user-guide.md)
- MCP adapter: [`authplane-mcp/README.md`](authplane-mcp/README.md) · [User Guide](authplane-mcp/docs/user-guide.md)
- FastMCP adapter: [`authplane-fastmcp/README.md`](authplane-fastmcp/README.md) · [User Guide](authplane-fastmcp/docs/user-guide.md)
- Release history: [`CHANGELOG.md`](CHANGELOG.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Release policy: [`RELEASE_POLICY.md`](RELEASE_POLICY.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
