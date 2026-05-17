# Calculator Service Example

A minimal FastMCP server demonstrating Authplane JWT authentication with per-tool scope enforcement.

The server exposes two tools:

| Tool | Required scope |
|------|---------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |

Tokens must carry the scope for the specific tool being called. A token with only `tools/add` can call `add` but not `multiply`.

## Prerequisites

- Python 3.11+
- The **Authplane authserver** running locally — from a checkout of the `authserver` repo, run:

  ```bash
  bash demo/mcp-demo-server-start.sh
  ```

  This starts the auth server on `http://localhost:9000`, registers the calculator client and scopes, and creates a demo user.

## Run

```bash
cd authplane-fastmcp
./demo/run.sh
```

`run.sh` creates a virtualenv, installs dependencies, and starts the server on port `8080`. All demo credentials are pre-configured — no additional setup needed.

## How it works

Note that FastMCP filters tools if the scope is not available.

```
MCP Client ──Bearer JWT──► mcpserver.py (port 8080)
                                │
                                ├─ authplane_auth()
                                │    • Discovers JWKS from ISSUER_URL
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token (revocation check)
                                │
                                └─ @mcp.tool(auth=require_scopes("tools/add"))
                                     • FastMCP enforces scope before calling handler
                                       → Returns 403 to client if scope missing
```

## Key patterns shown

**`authplane_auth()`** — wires up the verifier and auth provider in one call. The `scopes` list advertises supported scopes in the Protected Resource Metadata (`/.well-known/oauth-protected-resource`); it does **not** require all scopes to be present in every token.

**`@mcp.tool(auth=require_scopes(scope))`** — FastMCP's native per-tool scope enforcement. Scope is checked by the framework before the handler runs, returning a proper error to the client if the token is missing the scope.
