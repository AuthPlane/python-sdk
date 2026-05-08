---
name: MCP Compatibility Report
about: Report compatibility of an MCP client or server with the Authplane Python adapters
title: "[Compat] <Client or Server> <Version>"
labels: compatibility, mcp
assignees: ""
---

## Adapter

- [ ] `authplane-mcp` (official MCP Python SDK adapter)
- [ ] `authplane-fastmcp` (FastMCP adapter)

## MCP Library Version

- **Library:** (e.g., `mcp`, `fastmcp`)
- **Version:**
- **Transport:** (e.g., streamable-http, stdio)

## MCP Client (if reporting a client-side issue)

- **Client:** (e.g., Claude Code, MCP Inspector, Cursor)
- **Version:**
- **Platform:** (macOS / Linux / Windows)

## Authplane SDK Version

- `authplane-sdk`:
- `authplane-mcp` / `authplane-fastmcp`:
- `authserver` (issuer):

## Description

Brief summary of the compatibility observation.

## Compatibility Scenarios

Check each that was tested. Mark pass / fail / skip.

- [ ] **JWT validation** — protected tool accepts valid bearer token
- [ ] **Scope enforcement** — tool-specific scope required and checked
- [ ] **DPoP-bound tokens** — proof-of-possession verified end-to-end (if applicable)
- [ ] **Token refresh** — client refreshes without losing session
- [ ] **Metadata discovery** — adapter surfaces `WWW-Authenticate` / protected-resource metadata correctly
- [ ] **Error handling** — expired, revoked, malformed tokens produce the expected error shape

## Reproduction Steps

1. Install adapter ...
2. Configure MCP server with Authplane middleware ...
3. Connect client ...
4. Observe results

## Logs

<details>
<summary>Server logs (adapter)</summary>

```
(paste relevant logs here)
```

</details>

<details>
<summary>Client logs</summary>

```
(paste relevant logs here)
```

</details>

## Additional Context

Screenshots, network traces, spec references, or upstream issues.
