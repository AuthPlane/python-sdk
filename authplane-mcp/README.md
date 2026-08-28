# authplane-mcp

[![PyPI](https://img.shields.io/pypi/v/authplane-mcp?style=flat-square&label=authplane-mcp)](https://pypi.org/project/authplane-mcp/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Authplane JWT validation for servers built on the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).

## Install

```bash
pip install authplane-mcp
```

## Compatibility

Supported `mcp` range: **`>=1.28.1, <2.0.0`**. The floor is `1.28.1` because earlier releases (`<=1.28.0`) are affected by [PYSEC-2026-3483](https://osv.dev/vulnerability/PYSEC-2026-3483), fixed in `1.28.1`. The adapter targets the mcp 1.x server API (`mcp.server.fastmcp.FastMCP`) and the camelCase URL-elicitation field (`ElicitRequestURLParams(elicitationId=...)`), which are the shape of the current 1.x line. As a belt-and-braces measure the adapter does not hard-code that spelling: it resolves the elicitation-id field name from the model's own schema — a known spelling is checked at import, then resolved per call — so a rename within 1.x would be picked up automatically rather than breaking the consent path. mcp 2.0 is not yet supported: it removes `mcp.server.fastmcp` and renames the elicitation field to snake_case `elicitation_id`, which is a separate port. If your project needs mcp 2.0, please open an issue.

## Quickstart

```python
import asyncio

from authplane_mcp import authplane_mcp_auth, install_request_context, require_scope
from mcp.server.fastmcp import FastMCP


async def main() -> None:
    auth_result = await authplane_mcp_auth(
        issuer="https://auth.company.com",
        resource="https://mcp.company.com",
        scopes=["tools/query", "tools/write"],
    )
    mcp = FastMCP("My MCP Server", port=8080, json_response=True, **auth_result)
    # Wires Authplane's per-app hooks onto the server: advertises the issuer /
    # resource identifiers verbatim in the Protected Resource Metadata and
    # installs the request-context middleware used by inbound DPoP enforcement.
    install_request_context(mcp)

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
