# authplane-mcp

[![PyPI](https://img.shields.io/pypi/v/authplane-mcp?style=flat-square&label=authplane-mcp)](https://pypi.org/project/authplane-mcp/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Authplane JWT validation for servers built on the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).

## Install

```bash
pip install authplane-mcp
```

## Compatibility

Supported `mcp` range: **`>=1.23.0, <1.28.0`**. MCP 1.28 renamed the elicitation field from `elicitationId` (camelCase) to `elicitation_id` (snake_case), which breaks this adapter's current wire handling. If your project needs MCP 1.28+, please open an issue — the adapter update is straightforward, we just haven't cut it yet.

## Quickstart

```python
import asyncio

from authplane_mcp import authplane_mcp_auth, require_scope
from mcp.server.fastmcp import FastMCP


async def main() -> None:
    auth_result = await authplane_mcp_auth(
        issuer="https://auth.company.com",
        resource="https://mcp.company.com",
        scopes=["tools/query", "tools/write"],
    )
    mcp = FastMCP("My MCP Server", port=8080, json_response=True, **auth_result)

    @mcp.tool()
    async def query_database(query: str) -> str:
        require_scope("tools/query")
        return f"Result for: {query}"

    try:
        await mcp.run_streamable_http_async()
    finally:
        await auth_result.aclose()


asyncio.run(main())
```

`auth_result` holds background JWKS and metadata refresh tasks bound to the running event loop. Keep the setup, server, and `aclose()` inside a single `asyncio.run(main())` so those tasks stay alive for the server's lifetime.

## Documentation

PRM behavior, dev mode, revocation checking, manual setup, the full `authplane_mcp_auth` / `AuthplaneTokenVerifier` API, and error handling: **[User Guide](https://github.com/AuthPlane/python-sdk/blob/main/authplane-mcp/docs/user-guide.md)**.
