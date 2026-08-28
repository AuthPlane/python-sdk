"""Integration tests for authplane-fastmcp with a real FastMCP app.

These tests verify that the adapter correctly integrates with FastMCP's HTTP layer,
specifically testing the Protected Resource Metadata (PRM) endpoint which FastMCP
exposes when an auth provider is configured.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.auth import RemoteAuthProvider
from httpx import ASGITransport, AsyncClient
from pydantic import AnyHttpUrl
from starlette.routing import Route

from authplane_fastmcp._prm import _PRM_PATH_PREFIX
from authplane_fastmcp.auth import VerbatimPRMRemoteAuthProvider, _derive_resource_url

# Type-only: pytest never executes it under --import-mode=importlib, and
# pyright resolves it through `extraPaths: ["tests"]`.
if TYPE_CHECKING:
    from conftest import TokenVerifierFactory


def _build_app(
    *,
    issuer: str,
    base_url: str,
    mount_path: str,
    make_verifier: TokenVerifierFactory,
) -> tuple[FastMCP, str]:
    """A FastMCP app whose PRM route comes from ``VerbatimPRMRemoteAuthProvider``.

    Returns the app and the resource identifier upstream derives for it.

    Upstream composes the resource URL as ``base_url`` joined with the transport
    mount path (``RemoteAuthProvider.get_routes(mcp_path)``) and derives the
    well-known route from that — so the mount path, not a hand-passed string, is
    how a trailing-slash resource actually arises on this side. The shared
    ``test_client`` fixture only ever exercises the default ``/mcp`` mount.

    The identifier comes from :func:`_derive_resource_url`, the same call
    ``authplane_auth`` makes, rather than from a second copy of the expression:
    the claim above is that this helper reproduces what production derives, so
    it has to be production's derivation and not one that merely agrees on the
    inputs the tests happen to use.

    Which half the tests below check: they check that *we* serve our own
    identifier verbatim, not that our identifier equals upstream's. They cannot
    check the latter — ``rewrite_prm_routes_verbatim`` forces the served
    ``resource`` to our string, route selection compares right-stripped, and
    ``follow_redirects=True`` absorbs the 307 a differing registered path would
    produce, so a divergence would leave them green. That half is pinned
    separately, by ``test_derive_resource_url_matches_fastmcp`` in
    ``test_auth_factory.py``, which compares the two derivations directly.
    """
    resource = _derive_resource_url(base_url, mount_path)

    auth_provider = VerbatimPRMRemoteAuthProvider(
        token_verifier=make_verifier(base_url, resource, scopes=["tools/query"]),
        authorization_servers=[AnyHttpUrl(issuer)],
        base_url=AnyHttpUrl(base_url),
        scopes_supported=["tools/query"],
        verbatim_issuer=issuer,
        verbatim_resource=resource,
    )
    return FastMCP("Test Server", auth=auth_provider), resource


def _under_prm_prefix(path: str) -> bool:
    """The prefix test `_prm.py:148` uses, not a looser `startswith`.

    `startswith(_PRM_PATH_PREFIX)` also matches
    `/.well-known/oauth-protected-resource-other`, which production does not
    count. Harmless in this fixture, but the docstring below says this helper
    narrows "for the same reason `_prm.py:143` narrows" — so it should narrow
    the same way rather than approximately.
    """
    return path == _PRM_PATH_PREFIX or path.startswith(_PRM_PATH_PREFIX + "/")


def _registered_prm_paths(provider: RemoteAuthProvider, mount_path: str) -> list[str]:
    """Right-stripped paths of the provider's routes under the PRM prefix.

    Filtered by prefix, not "every route the provider returns": comparing the
    whole list against a one-element expectation made any unrelated route
    upstream adds fail these tests illegibly — the failure mode
    ``_upstream_resource_url``'s guard goes out of its way to avoid.

    ``isinstance(route, Route)`` for the same reason ``_prm.py:143`` narrows:
    ``BaseRoute`` has no ``.path``, and a ``Host`` route would land as an
    ``AttributeError`` rather than as a result.

    Right-stripping mirrors ``_prm.py:158``: upstream keeps a terminating path
    slash when deriving the well-known path while our target strips it, which is
    the documented, deliberate half-slash of divergence.
    """
    return [
        route.path.rstrip("/")
        for route in provider.get_routes(mount_path)
        if isinstance(route, Route) and _under_prm_prefix(route.path)
    ]


@pytest.mark.parametrize(
    ("base_url", "mount_path"),
    [
        ("https://api.example.com", "/mcp"),
        ("https://api.example.com", "/mcp/"),
        ("https://api.example.com", "mcp"),
        ("https://api.example.com/base", "api/v1/mcp"),
        ("https://api.example.com", "/"),
    ],
)
def test_upstream_registers_the_route_our_rewrite_targets(
    base_url: str, mount_path: str, token_verifier_factory: TokenVerifierFactory
) -> None:
    """A plain upstream provider registers the PRM route ``_prm.py`` looks for.

    ``test_auth_factory.py::test_derive_resource_url_matches_fastmcp`` pins a
    *helper*: it asserts our derivation equals ``_get_resource_url``'s output.
    What can break a deployment is one step further out — the path upstream
    actually **registers** a PRM route on, because that is what
    ``rewrite_prm_routes_verbatim`` matches against (``_prm.py:148``,
    ``:158``). A future fastmcp could keep ``_get_resource_url`` and stop
    routing the advertised resource through it, and the helper pin would stay
    green through exactly the change it exists to catch.

    So this asserts the composition end to end: the RFC 9728 §3.1 derivation of
    our resource is the path on the route upstream registers for the same
    mount. It survives a rename of the private helper, and it is the assumption
    whose only other signal is the ``RuntimeWarning`` at ``_prm.py:181-190``.

    Deliberately a **plain** ``RemoteAuthProvider``, not
    :class:`VerbatimPRMRemoteAuthProvider`: the subclass wraps the matching
    route's ``app``, which is the behaviour under test here, and its
    ``RuntimeWarning`` would report a mismatch that this assertion should be
    the one to show.

    Both sides are right-stripped, mirroring ``_prm.py:158``: upstream keeps a
    terminating path slash when deriving the well-known path while our target
    strips it, which is the documented, deliberate half-slash of divergence.
    """
    resource = _derive_resource_url(base_url, mount_path)

    provider = RemoteAuthProvider(
        token_verifier=token_verifier_factory(base_url, resource, scopes=["tools/query"]),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
        base_url=AnyHttpUrl(base_url),
        scopes_supported=["tools/query"],
    )

    target = _PRM_PATH_PREFIX + urlsplit(resource).path.rstrip("/")

    assert _registered_prm_paths(provider, mount_path) == [target]


@pytest.mark.parametrize(
    ("base_url", "mount_path"),
    [
        # Upstream registers /a/mcp; our target is /a/./mcp.
        ("https://api.example.com", "/a/./mcp"),
        # Upstream percent-encodes; our target carries the literal space.
        ("https://api.example.com", "/mcp path"),
    ],
)
def test_upstream_registers_a_different_route_when_the_path_moves(
    base_url: str, mount_path: str, token_verifier_factory: TokenVerifierFactory
) -> None:
    """The divergences with a registration-level consequence, pinned as such.

    ``test_auth_factory.py::test_derive_resource_url_diverges_from_fastmcp``
    argues in prose that these two rows do more than mismatch an audience
    string — they move ``urlsplit(resource).path``, which is what
    ``rewrite_prm_routes_verbatim`` selects on (``_prm.py:148``), so the wrap
    silently does not happen and a ``RuntimeWarning`` is the only signal. That
    argument was unpinned: the case above is parametrized only over slash
    placement, so nothing asserted the claim it makes about what upstream
    registers.

    Asserting the *inequality* rather than upstream's exact normalized path is
    deliberate. The consequence is "our target misses the registered route",
    which is a property of the pair; pinning `/a/mcp` and `/mcp%20path` as
    literals would additionally pin upstream's normalization, which is not this
    SDK's to guarantee and is the thing free to change across `fastmcp>=3.2,<4`.
    """
    resource = _derive_resource_url(base_url, mount_path)

    provider = RemoteAuthProvider(
        token_verifier=token_verifier_factory(base_url, resource, scopes=["tools/query"]),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
        base_url=AnyHttpUrl(base_url),
        scopes_supported=["tools/query"],
    )

    target = _PRM_PATH_PREFIX + urlsplit(resource).path.rstrip("/")

    # `!= [target]` alone is green when the helper returns `[]` too, so it would
    # survive upstream dropping the prefix entirely — asserting nothing about the
    # divergence this case is named for while the sibling positive case above
    # carries the redness. Pin that exactly one route was registered first.
    registered = _registered_prm_paths(provider, mount_path)
    assert len(registered) == 1
    assert registered != [target]


@pytest.mark.asyncio
async def test_prm_endpoint(test_client: AsyncClient) -> None:
    """GET /.well-known/oauth-protected-resource/mcp returns valid PRM JSON."""
    response = await test_client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    prm = response.json()

    # Verify PRM structure per RFC 9728
    assert "resource" in prm
    assert "authorization_servers" in prm
    # The advertised issuer must be byte-for-byte the configured identifier.
    # Upstream serializes it through pydantic AnyHttpUrl, which would append a
    # trailing slash to the empty-path authority; the adapter rewrites the
    # served value back to the verbatim form so it matches the core SDK's
    # strict comparison (RFC 8414 §3.3, RFC 9728 §3.3).
    assert prm["authorization_servers"] == ["https://auth.example.com"]

    # The advertised resource is likewise verbatim (no trailing slash added).
    assert prm["resource"] == "https://api.example.com/mcp"

    assert "scopes_supported" in prm
    assert set(prm["scopes_supported"]) == {
        "tools/query",
        "tools/write",
        "tools/admin",
    }

    assert "bearer_methods_supported" in prm
    assert "header" in prm["bearer_methods_supported"]


@pytest.mark.asyncio
async def test_prm_advertises_configured_issuer_without_trailing_slash(
    test_client: AsyncClient,
) -> None:
    """An issuer configured without a trailing slash is advertised verbatim.

    An empty-path authority is exactly where ``pydantic.AnyHttpUrl`` inserts a
    trailing slash, so this pins the rewrite that keeps the advertised
    identifier byte-for-byte the configured value.
    """
    response = await test_client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    prm = response.json()
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert not prm["authorization_servers"][0].endswith("/")
    # The resource keeps its exact configured form (path preserved, no slash added).
    assert prm["resource"] == "https://api.example.com/mcp"


@pytest.mark.asyncio
async def test_prm_advertises_trailing_slash_resource_verbatim(
    token_verifier_factory: TokenVerifierFactory,
) -> None:
    """A resource whose path ends in a slash is advertised verbatim.

    The mirror of ``authplane-mcp``'s test of the same name, and the gap is
    strictly larger on this side. ``_prm.py`` is duplicated byte-for-byte
    between the two adapters, but the PRM *route* is not: this one comes from
    ``fastmcp.server.auth.RemoteAuthProvider.get_routes()`` via
    :class:`VerbatimPRMRemoteAuthProvider`, a different upstream project from
    ``modelcontextprotocol/python-sdk``, so its registration rule can drift
    independently. The hand-written-route unit test
    (``test_prm.py::test_matches_the_route_upstream_registers_for_a_trailing_slash_resource``)
    encodes an assumption about that rule; this one does not.

    ``follow_redirects=True`` for the reason the mcp copy documents: the request
    path is fixed, so a change in upstream's registration would otherwise show
    up as a 307 and a false failure on ``status_code == 200``.

    **The load-bearing assertion is the one on ``authorization_servers``, not
    the one this test is named for.** ``pydantic.AnyHttpUrl`` only appends a
    slash to an *empty-path* authority, so ``https://api.example.com/mcp/``
    round-trips through it unchanged: both ``resource`` assertions below hold
    with the rewrite entirely absent. The issuer *is* the empty-path case
    (``https://auth.example.com`` becomes ``https://auth.example.com/``), so it
    is the only served field that moves when the route is not wrapped, and
    therefore the only one that can witness route selection. Do not prune it as
    an unrelated issuer check in a resource-named test — that guts the test
    while leaving it green.
    """
    mcp, resource = _build_app(
        make_verifier=token_verifier_factory,
        issuer="https://auth.example.com",
        base_url="https://api.example.com",
        mount_path="/mcp/",
    )
    assert resource == "https://api.example.com/mcp/"
    asgi_app = mcp.http_app(transport="streamable-http", path="/mcp/")

    async with AsyncClient(
        transport=ASGITransport(app=asgi_app),
        base_url="http://testserver",
        follow_redirects=True,
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp/")

    assert response.status_code == 200
    prm = response.json()
    # This is the assertion that pins route selection — see the docstring.
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["resource"] == "https://api.example.com/mcp/"
    assert prm["resource"].endswith("/")
