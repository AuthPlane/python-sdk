# authplane-fastmcp

[![PyPI](https://img.shields.io/pypi/v/authplane-fastmcp?style=flat-square&label=authplane-fastmcp)](https://pypi.org/project/authplane-fastmcp/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Authplane JWT validation for servers built on [FastMCP](https://github.com/PrefectHQ/fastmcp).

## Install

```bash
pip install authplane-fastmcp
```

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
    async def query_database(
        query: str, token: AccessToken = CurrentAccessToken()
    ) -> str:
        user_id = token.claims.get("sub")
        return f"Query: {query}, User: {user_id}"

    await mcp.run_async(transport="http", host="0.0.0.0", port=8080)


asyncio.run(main())
```

`authplane_auth()` holds background JWKS and metadata refresh tasks; call `aclose()` on the returned `client` during server shutdown.

## Documentation

PRM behavior, dev mode, revocation checking, manual setup, scope enforcement semantics, claim access, the full `authplane_auth` / `AuthplaneTokenVerifier` API, and error handling: **[User Guide](https://github.com/AuthPlane/python-sdk/blob/main/authplane-fastmcp/docs/user-guide.md)**.
