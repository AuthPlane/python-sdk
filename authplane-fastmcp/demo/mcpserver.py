"""Run from the repository root:

cp demo/.env.example demo/.env
python demo/mcpserver.py
"""

import asyncio
import logging
import os
from urllib.parse import urlparse

from authplane import ASCredentials, IntrospectionRevocation
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes

from authplane_fastmcp import authplane_auth


async def main() -> None:
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

    resource = os.environ.get("RESOURCE_URL", "http://localhost:8080/mcp")
    base_url = os.environ.get("BASE_URL", resource.removesuffix("/mcp"))
    parsed_base = urlparse(base_url)
    port = parsed_base.port or (443 if parsed_base.scheme == "https" else 80)
    issuer = os.environ.get("ISSUER_URL", "http://localhost:9000")
    resource = base_url.rstrip("/") + "/mcp"
    client_id = os.environ.get("CLIENT_ID", resource)
    client_secret = os.environ["CLIENT_SECRET"]

    auth_result = await authplane_auth(
        issuer=issuer,
        base_url=base_url,
        scopes=["tools/add", "tools/multiply"],
        dev_mode=True,  # Enables local testing
        as_credentials=ASCredentials(
            client_id=client_id,
            client_secret=client_secret,
        ),
        revocation_checker=IntrospectionRevocation(),
    )

    mcp = FastMCP("Calculator Service", **auth_result)

    @mcp.tool(auth=require_scopes("tools/add"))
    def add(a: float, b: float) -> float:
        """Add two numbers"""
        return a + b

    @mcp.tool(auth=require_scopes("tools/multiply"))
    def multiply(a: float, b: float) -> float:
        """Multiply two numbers"""
        return a * b

    # NOTE: a ``consent_demo`` tool that exercises the URL elicitation path
    # was intentionally omitted from this demo. fastmcp 3.2 does not
    # propagate ``UrlElicitationRequiredError`` (an ``McpError`` subclass)
    # raised inside a tool handler — its tool-call dispatch catches only
    # ``FastMCPError`` and wraps everything else as an ``isError: true``
    # tool result, so the client never sees JSON-RPC ``-32042``. See the
    # equivalent demo in ``authplane-mcp/demo/mcpserver.py``, which uses the
    # low-level MCP server and surfaces the elicitation correctly.

    # The adapter setup, server, and aclose() must share one event loop —
    # auth_result holds async resources (locks, httpx pool, background JWKS
    # refresh tasks) bound to the running loop. ``run_async`` is FastMCP's
    # async entry point and keeps everything on the same loop.
    try:
        await mcp.run_async(transport="http", port=port, log_level="DEBUG")
    finally:
        await auth_result.aclose()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )

    asyncio.run(main())
