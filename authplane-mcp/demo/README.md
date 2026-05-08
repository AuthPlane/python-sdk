# Calculator Service Example

A minimal MCP server demonstrating Authplane JWT authentication with per-tool scope enforcement and RFC 8693 token exchange surfaced via MCP URL elicitation.

The server exposes three tools:

| Tool | Per-tool scope |
|------|---------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |
| `consent_demo` | `tools/consent_demo` |

`consent_demo` calls `client.exchange(...)` to swap the inbound user token for a Google Calendar token. The local authserver responds with `consent_required` plus a `consent_url`; the wrapped client translates that into `UrlElicitationRequiredError` (JSON-RPC `-32042`), and the MCP client surfaces the URL elicitation prompt to the user.

## Scope advertisement and consent prompt

This demo passes `enforce_scopes_on_all_requests=True` to `authplane_mcp_auth`. With that flag set, the three demo scopes are listed in the Protected Resource Metadata's `scopes_supported` and your MCP client requests all of them when minting a token — so the **OAuth consent prompt asks you to grant all three scopes at once**. Approve all of them; declining any one will cause the AS to reject the token.

This is a workaround for an MCP reference SDK limitation: `AuthSettings` has no separate "supported" field, so the SDK uses `required_scopes` for both PRM advertisement and request-layer enforcement. The flag is opt-in; production deployments that don't need OAuth-discovery clients to know the scope list can leave it off and rely solely on per-tool `require_scope()`.

The per-tool `require_scope()` calls remain in the demo on purpose — they are the granular enforcement pattern, become no-ops under request-level enforcement, and stay correct once the upstream SDK gains a separate "supported" field and the flag goes away.

## Prerequisites

- Python 3.11+
- The **Authplane authserver** running locally — from a checkout of the `authserver` repo, run:

  ```bash
  bash demo/mcp-demo-server-start.sh
  ```

  This starts the auth server on `http://localhost:9000`, registers the calculator client and scopes, and creates a demo user.

## Run

```bash
cd authplane-mcp
./demo/run.sh
```

`run.sh` creates a virtualenv, installs dependencies, and starts the server on port `8080`. All demo credentials are pre-configured — no additional setup needed.

## How it works

```
MCP Client ──Bearer JWT──► mcpserver.py (port 8080)
                                │
                                ├─ authplane_mcp_auth()
                                │    • Discovers JWKS from ISSUER_URL
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token (revocation check)
                                │
                                └─ require_scope("tools/add")
                                     • Reads token from request context
                                     • Raises PermissionError if scope missing
                                       → MCP returns isError=true to client
```

## Key patterns shown

**`authplane_mcp_auth()`** — wires up the verifier and auth settings in one call. By default the `scopes` list is **not** propagated to the PRM — see "Scope advertisement and consent prompt" above for why this demo opts in via `enforce_scopes_on_all_requests=True` and what that means.

**`require_scope(scope)`** — call at the top of any tool handler to enforce per-tool scope. If the token is missing the scope the tool returns an error result (`isError: true`) to the MCP client.

**`client.exchange(...)`** — performs RFC 8693 token exchange. If the AS responds with `consent_required` and a `consent_url`, the wrapped client raises `UrlElicitationRequiredError` (JSON-RPC `-32042`) instead of `ConsentRequiredError`, and the MCP client surfaces it as a URL elicitation prompt — no try/except needed in the tool handler. See `consent_demo` in `mcpserver.py`.
