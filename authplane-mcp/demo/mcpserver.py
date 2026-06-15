"""Run from the repository root:

cp demo/.env.example demo/.env  # then fill in CLIENT_SECRET
python demo/mcpserver.py
"""

import asyncio
import os
from urllib.parse import urlparse

from authplane import ASCredentials, DPoPKeyMaterial, DPoPProvider, IntrospectionRevocation
from authplane.oauth import TokenExchangeOptions
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from dotenv import load_dotenv
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.fastmcp import FastMCP

from authplane_mcp import authplane_mcp_auth, install_request_context, require_scope

GOOGLE_CALENDAR_RESOURCE_URI = "https://www.googleapis.com/calendar/v3"
GOOGLE_CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar"


async def main() -> None:
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

    resource = os.environ.get("RESOURCE_URL", "http://localhost:8080/mcp")
    parsed_resource = urlparse(resource)
    port = parsed_resource.port or (443 if parsed_resource.scheme == "https" else 80)
    client_id = os.environ.get("CLIENT_ID", resource)

    # Generate an ephemeral EC key for DPoP proof-of-possession on outbound
    # calls (introspection, token exchange) to the authorization server.
    dpop_key = ec.generate_private_key(ec.SECP256R1())
    dpop_pem = dpop_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    dpop_provider = DPoPProvider(DPoPKeyMaterial.from_pem(dpop_pem))

    auth_result = await authplane_mcp_auth(
        issuer=os.environ.get("ISSUER_URL", "http://localhost:9000"),
        resource=resource,
        scopes=["tools/add", "tools/multiply", "tools/consent_demo"],
        # Advertise scopes in the PRM so OAuth-discovery clients (Claude
        # Code, Inspector, etc.) request them on token mint.  Side effect:
        # every request must carry all three scopes.  See the docstring
        # on ``enforce_scopes_on_all_requests`` for why this exists, and
        # the demo README for what users see in the consent prompt.  The
        # per-tool ``require_scope()`` calls below intentionally stay —
        # they are the granular pattern, become no-ops under request-level
        # enforcement, and remain correct once the upstream SDK gains a
        # separate "supported" field and this flag goes away.
        enforce_scopes_on_all_requests=True,
        dev_mode=True,  # Enables local testing
        dpop=dpop_provider,
        as_credentials=ASCredentials(
            client_id=client_id,
            client_secret=os.environ["CLIENT_SECRET"],
        ),
        revocation_checker=IntrospectionRevocation(),
    )

    mcp = FastMCP("Calculator Service", port=port, json_response=True, **auth_result)

    # Required for inbound DPoP enforcement: publishes the active HTTP request
    # on a ContextVar so the verifier can build a DPoPRequestContext and
    # forward it to AuthplaneResource.verify. Without this call DPoP-bound
    # requests fail closed (DPoPBindingMismatchError) — the misconfiguration
    # surfaces as a 401, not as a silent bypass.
    install_request_context(mcp)

    @mcp.tool()
    async def add(a: float, b: float) -> float:
        """Add two numbers"""
        require_scope("tools/add")
        return a + b

    @mcp.tool()
    async def multiply(a: float, b: float) -> float:
        """Multiply two numbers"""
        require_scope("tools/multiply")
        return a * b

    @mcp.tool()
    async def consent_demo() -> dict[str, str]:
        """Exchange the inbound user token for a Google Calendar token via RFC 8693.

        The demo authserver registers ``google-calendar`` as a Broker resource
        with fake upstream credentials.  Until the user has connected Google
        Calendar (which they cannot, in the demo — the credentials are fake),
        the AS responds to this exchange with ``consent_required`` and a
        ``consent_url`` pointing at the AS's connect endpoint.

        The wrapped client translates that into ``UrlElicitationRequiredError``
        (MCP error code ``-32042``) before this handler returns.  The MCP
        SDK's ``FastMCP`` re-raises ``UrlElicitationRequiredError`` from tool
        handlers (see ``mcp/server/fastmcp/tools/base.py``), so the client
        sees a JSON-RPC ``-32042`` and prompts the user to visit the URL —
        no try/except in this handler.
        """
        require_scope("tools/consent_demo")
        token = get_access_token()
        if token is None:
            raise PermissionError("missing access token")
        downstream = await auth_result.client.exchange(
            TokenExchangeOptions(
                subject_token=token.token,
                scope=GOOGLE_CALENDAR_SCOPE,
                resources=(GOOGLE_CALENDAR_RESOURCE_URI,),
            )
        )
        return {
            "token_type": downstream.token_type,
            "scope": downstream.scope or "",
        }

    # The adapter setup, server, and aclose() must share one event loop —
    # auth_result holds async resources (locks, httpx pool, background JWKS
    # refresh tasks) bound to the running loop. Using the async server entry
    # point keeps everything on the same loop.
    try:
        await mcp.run_streamable_http_async()
    finally:
        await auth_result.aclose()


if __name__ == "__main__":
    import logging

    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )

    asyncio.run(main())
