"""Shared test fixtures for authplane-fastmcp tests."""

import time
from collections.abc import AsyncGenerator
from typing import Protocol
from unittest.mock import AsyncMock, PropertyMock

import pytest
from authplane import AuthplaneResource, VerifiedClaims
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken, require_scopes
from httpx import ASGITransport, AsyncClient
from pydantic import AnyHttpUrl

from authplane_fastmcp import AuthplaneTokenVerifier
from authplane_fastmcp.auth import VerbatimPRMRemoteAuthProvider


@pytest.fixture
def valid_claims() -> VerifiedClaims:
    """Fixed VerifiedClaims for testing.

    Returns:
        VerifiedClaims with sub="user_123", client_id="client_456",
        scopes=["tools/query", "tools/write"], and tenant_id in raw
    """
    now = int(time.time())
    raw_claims = {
        "iss": "https://auth.example.com",
        "aud": "https://api.example.com",
        "sub": "user_123",
        "client_id": "client_456",
        "scope": "tools/query tools/write",
        "exp": now + 3600,
        "nbf": now,
        "iat": now,
        "jti": "token-id-123",
        "tenant_id": "tenant_789",
    }

    return VerifiedClaims(
        sub="user_123",
        client_id="client_456",
        scopes=("tools/query", "tools/write"),
        issuer="https://auth.example.com",
        audience=("https://api.example.com",),
        expires_at=now + 3600,
        issued_at=now,
        jti="token-id-123",
        kid="test-key-1",
        raw=raw_claims,
    )


@pytest.fixture
def mock_verifier(valid_claims: VerifiedClaims) -> AsyncMock:
    """Mock AuthplaneResource.

    Returns:
        Mock AuthplaneResource where verify("valid_token") returns valid_claims
        and verify("invalid_token") raises AuthplaneError
    """
    from authplane import AuthplaneError

    mock = AsyncMock(spec=AuthplaneResource)
    type(mock).scopes = PropertyMock(return_value=["tools/query", "tools/write"])
    type(mock).resource = PropertyMock(return_value="https://api.example.com/mcp")

    async def verify_side_effect(
        token: str, *, dpop_request: object | None = None
    ) -> VerifiedClaims:
        _ = dpop_request  # accept but ignore — covered by dedicated DPoP tests
        if token == "valid_token":
            return valid_claims
        raise AuthplaneError("Invalid token")

    mock.verify = AsyncMock(side_effect=verify_side_effect)
    return mock


@pytest.fixture
def token_verifier(mock_verifier: AsyncMock) -> AuthplaneTokenVerifier:
    """AuthplaneTokenVerifier with mocked AuthplaneResource.

    Deliberately not built on ``build_token_verifier`` below, despite the shape
    overlapping. This one exists to drive ``verify()`` — it carries a side effect
    distinguishing a valid token from an invalid one, and a fixed resource — while
    ``build_token_verifier`` serves the PRM and derivation tests, which never call
    ``verify`` and need the resource to follow their parameters. Folding them
    together would mean one constructor with a `verify` argument nobody in the
    second group passes.

    Returns:
        AuthplaneTokenVerifier(mock_verifier)
    """
    return AuthplaneTokenVerifier(mock_verifier, base_url="https://api.example.com")


@pytest.fixture
def fastmcp_app(token_verifier: AuthplaneTokenVerifier) -> FastMCP:
    """Minimal FastMCP app with three tools for testing.

    Tools:
    - echo: no scope, no token param
    - query: auth=require_scopes("tools/query"), injects token
    - admin: auth=require_scopes("tools/admin"), injects token (not in test token)

    Returns:
        FastMCP application instance
    """
    auth_provider = VerbatimPRMRemoteAuthProvider(
        token_verifier=token_verifier,
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
        base_url=AnyHttpUrl("https://api.example.com"),
        scopes_supported=["tools/query", "tools/write", "tools/admin"],
        verbatim_issuer="https://auth.example.com",
        verbatim_resource="https://api.example.com/mcp",
    )

    mcp = FastMCP("Test Server", auth=auth_provider)

    @mcp.tool()
    async def echo(message: str) -> str:
        """Echo tool - no scope, no token param."""
        return f"echo: {message}"

    @mcp.tool(auth=require_scopes("tools/query"))
    async def query(q: str, token: AccessToken = CurrentAccessToken()) -> str:  # noqa: B008
        """Query tool - requires tools/query scope, injects token."""
        sub = token.claims.get("sub")
        tenant_id = token.claims.get("tenant_id")
        return f"query={q}, sub={sub}, tenant={tenant_id}"

    @mcp.tool(auth=require_scopes("tools/admin"))
    async def admin(action: str, token: AccessToken = CurrentAccessToken()) -> str:  # noqa: B008
        """Admin tool - requires tools/admin scope (not in test token)."""
        return f"admin: {action}"

    _ = echo, query, admin  # registered with mcp, not referenced directly
    return mcp


@pytest.fixture
async def test_client(fastmcp_app: FastMCP) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client pointed at fastmcp_app.

    Returns:
        AsyncClient configured to talk to the FastMCP app HTTP endpoints
    """
    asgi_app = fastmcp_app.http_app(transport="streamable-http")

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
    ) as client:
        yield client


# Shared by test_integration.py and test_auth_factory.py.
#
# It lives in conftest rather than in a module of its own because this package
# runs pytest with `--import-mode=importlib`: the test directory is not put on
# `sys.path`, so `import _helpers` does not resolve, and making `tests/` a
# package to allow `from ._helpers import ...` names it `tests` — which collides
# with the repo-root `tests/` package in release.yml's combined invocation and
# takes the whole run down with "Plugin already registered under a different
# name". conftest is the one module pytest guarantees is importable from every
# test module in the tree, via the fixture below.
def build_token_verifier(
    base_url: str, resource: str, *, scopes: list[str] | None = None
) -> AuthplaneTokenVerifier:
    """A production ``AuthplaneTokenVerifier`` over a mocked ``AuthplaneResource``.

    One definition rather than three. ``test_integration.py`` had two
    byte-identical copies of this construction and ``test_auth_factory.py`` a
    third variant, which is the same "two expressions required to agree, neither
    referencing the other" shape that motivated extracting
    ``_derive_resource_url`` in the first place.

    The verifier itself is the production class, deliberately: it is the
    argument ``auth.py``'s comment says PRM generation can read
    (``token_verifier.base_url``), and upstream's ``__init__`` reads
    ``required_scopes`` off it. A bare mock there would collapse the two
    coercion paths production uses — a raw ``str`` ``base_url`` into the
    verifier, an ``AnyHttpUrl`` into the provider — into one.
    """
    resource_mock = AsyncMock(spec=AuthplaneResource)
    type(resource_mock).resource = PropertyMock(return_value=resource)
    if scopes is not None:
        type(resource_mock).scopes = PropertyMock(return_value=scopes)
    return AuthplaneTokenVerifier(resource_mock, base_url=base_url)


class TokenVerifierFactory(Protocol):
    """The shared constructor's signature, preserved across the fixture.

    `Callable[..., AuthplaneTokenVerifier]` erases exactly the parameter checking
    that importing `build_token_verifier` directly used to provide — and
    `base_url` and `resource` are both `str`, so swapping them type-checks and
    silently builds a verifier whose resource origin comes from the wrong string.
    That is the class of mis-wiring `verifier.py`'s `isinstance` guard exists to
    catch, so the indirection should not be what reintroduces it.
    """

    def __call__(
        self, base_url: str, resource: str, *, scopes: list[str] | None = None
    ) -> AuthplaneTokenVerifier:
        """Build a verifier for ``resource`` against the server at ``base_url``."""


@pytest.fixture
def token_verifier_factory() -> TokenVerifierFactory:
    """`build_token_verifier`, for tests that cannot import across modules."""
    return build_token_verifier
