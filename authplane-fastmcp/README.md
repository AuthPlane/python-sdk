# authplane-fastmcp

[![PyPI](https://img.shields.io/pypi/v/authplane-fastmcp?style=flat-square&label=authplane-fastmcp)](https://pypi.org/project/authplane-fastmcp/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Authplane JWT validation for servers built on [FastMCP](https://github.com/PrefectHQ/fastmcp).

## Install

```bash
pip install authplane-fastmcp
```

## Compatibility

Supported `fastmcp` range: **`>=3.2, <4.0.0`**. This adapter also imports the top-level `mcp` package directly (`mcp.shared.exceptions`, `mcp.types`), so it carries its own `mcp` constraint: **`>=1.28.1, <2.0.0`**. The floor is `1.28.1` because earlier releases (`<=1.28.0`) are affected by [PYSEC-2026-3483](https://osv.dev/vulnerability/PYSEC-2026-3483), fixed in `1.28.1`; `fastmcp>=3.2` alone does not guarantee that floor. The adapter targets the mcp 1.x camelCase URL-elicitation field (`ElicitRequestURLParams(elicitationId=...)`), which is the shape of the current 1.x line. As a belt-and-braces measure the adapter does not hard-code that spelling: it resolves the elicitation-id field name from the model's own schema — a known spelling is checked at import, then resolved per call — so a rename within 1.x would be picked up automatically rather than breaking the consent path. mcp 2.0 is not yet supported: it renames the elicitation field to snake_case `elicitation_id`, which is a separate port. If your project needs mcp 2.0, please open an issue.

## Quickstart

```python
import asyncio
from authplane_fastmcp import authplane_auth
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, require_scopes
from fastmcp.dependencies import CurrentAccessToken


async def main():
    mcp = FastMCP(
        "My MCP Server",
        **await authplane_auth(
            issuer="https://auth.company.com",
            base_url="https://mcp.company.com",
            scopes=["tools/query", "tools/write"],
        ),
    )

    @mcp.tool(auth=require_scopes("tools/query"))
    async def query_database(query: str, token: AccessToken = CurrentAccessToken()) -> str:
        user_id = token.claims.get("sub")
        return f"Query: {query}, User: {user_id}"

    await mcp.run_async(transport="http", host="0.0.0.0", port=8080)


asyncio.run(main())
```

`authplane_auth()` holds background JWKS and metadata refresh tasks; call `aclose()` on the returned `client` during server shutdown.

## Hand-rolling the auth provider

`authplane_auth()` returns a `VerbatimPRMRemoteAuthProvider`, a `RemoteAuthProvider`
subclass that serves the Protected Resource Metadata identifiers byte-for-byte.
It matters: upstream builds the PRM from `pydantic.AnyHttpUrl` fields, which append
a trailing slash to an empty-path authority, and the core SDK compares identifiers
verbatim — so a client that follows the advertised value literally is rejected.

If you build a `RemoteAuthProvider` yourself instead of calling `authplane_auth()`
— a documented FastMCP pattern — use the subclass rather than the base class:

```python
from authplane_fastmcp import VerbatimPRMRemoteAuthProvider
from pydantic import AnyHttpUrl

provider = VerbatimPRMRemoteAuthProvider(
    token_verifier=token_verifier,
    authorization_servers=[AnyHttpUrl(issuer)],
    base_url=AnyHttpUrl(base_url),
    scopes_supported=scopes,
    # The two that make it verbatim. Pass the identifiers exactly as configured,
    # not the AnyHttpUrl forms above — that is the whole point: those normalize.
    verbatim_issuer=issuer,
    verbatim_resource=resource,
)
```

`base_url` is the server's base URL and `verbatim_resource` is the full resource
identifier; they are not the same value when the MCP server is mounted under a
path.

If you cannot subclass, `rewrite_prm_routes_verbatim(routes, issuer=..., resource=...)`
is exported as a supported hook — apply it to the route list your provider returns.

## Documentation

PRM behavior, dev mode, revocation checking, manual setup, scope enforcement semantics, claim access, the full `authplane_auth` / `AuthplaneTokenVerifier` API, and error handling: **[User Guide](https://github.com/AuthPlane/python-sdk/blob/main/authplane-fastmcp/docs/user-guide.md)**.
