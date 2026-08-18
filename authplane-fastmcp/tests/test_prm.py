"""Unit tests for the verbatim-PRM body rewrite.

``_rewrite_body`` swaps the configured identifiers back to their verbatim form
(the upstream MCP machinery serializes them through ``pydantic.AnyHttpUrl``,
which appends a trailing slash to an empty-path authority) without disturbing
any other advertised field.
"""

import json
import warnings

import pytest
from starlette.responses import Response
from starlette.routing import Route

from authplane_fastmcp._prm import _rewrite_body, rewrite_prm_routes_verbatim

_ISSUER = "https://auth.example.com"
_RESOURCE = "https://api.example.com/mcp"


def _rewrite(doc: dict[str, object]) -> dict[str, object]:
    out = _rewrite_body(json.dumps(doc).encode("utf-8"), issuer=_ISSUER, resource=_RESOURCE)
    return json.loads(out)


def test_swaps_slashed_issuer_for_verbatim() -> None:
    result = _rewrite({"authorization_servers": [_ISSUER + "/"], "resource": _RESOURCE + "/"})
    assert result["authorization_servers"] == [_ISSUER]
    assert result["resource"] == _RESOURCE


def test_preserves_extra_authorization_server_entries() -> None:
    other = "https://other-as.example.com/"
    result = _rewrite({"authorization_servers": [_ISSUER + "/", other]})
    # Only the entry matching the configured issuer is rewritten; the extra AS
    # entry is left exactly as advertised.
    assert result["authorization_servers"] == [_ISSUER, other]


def test_preserves_unrelated_fields() -> None:
    result = _rewrite(
        {
            "authorization_servers": [_ISSUER + "/"],
            "resource": _RESOURCE,
            "scopes_supported": ["tools/query"],
            "bearer_methods_supported": ["header"],
        }
    )
    assert result["scopes_supported"] == ["tools/query"]
    assert result["bearer_methods_supported"] == ["header"]


def test_non_json_body_returned_unchanged() -> None:
    assert _rewrite_body(b"", issuer=_ISSUER, resource=_RESOURCE) == b""


def test_body_untouched_when_nothing_to_rewrite() -> None:
    # Already verbatim: the function returns the original bytes rather than
    # re-serializing (so downstream Content-Length stays correct for a no-op).
    original = json.dumps({"authorization_servers": [_ISSUER], "resource": _RESOURCE}).encode(
        "utf-8"
    )
    assert _rewrite_body(original, issuer=_ISSUER, resource=_RESOURCE) == original


def test_swaps_the_resource_whatever_the_normalization() -> None:
    # The swap is unconditional by design: route matching already decided this
    # document belongs to the configured resource. Gating on the served value
    # would only cover the trailing slash and skip every other normalization the
    # URL layer can apply — the mismatch this module exists to fix.
    for served in (
        _RESOURCE + "/",
        "https://API.example.com/mcp",
        "https://api.example.com:443/mcp",
        "https://api.example.com/mcp/./",
    ):
        out = _rewrite({"resource": served})
        assert out["resource"] == _RESOURCE, served


def _prm_route(path: str) -> Route:
    async def endpoint(request: object) -> Response:  # pragma: no cover - never called
        return Response(b"{}")

    return Route(path, endpoint)


def test_only_the_route_for_this_resource_is_wrapped() -> None:
    # RFC 9728 §3.1 derives the well-known path from the identifier, so the path
    # is what says which resource a document describes. An app serving PRM for
    # two resources registers one route each; wrapping both would make the
    # sibling advertise this resource's identifier.
    mine = _prm_route("/.well-known/oauth-protected-resource/mcp")
    theirs = _prm_route("/.well-known/oauth-protected-resource/other")
    original_theirs = theirs.app

    rewrite_prm_routes_verbatim([mine, theirs], issuer=_ISSUER, resource=_RESOURCE)

    assert theirs.app is original_theirs
    assert mine.app is not None


def test_warns_when_no_route_matches_the_derivation() -> None:
    # A silent no-op here ships a PRM advertising identifiers the core SDK's
    # byte-for-byte comparison rejects, so a derivation/registration mismatch has
    # to be audible rather than skipped.
    stray = _prm_route("/.well-known/oauth-protected-resource/somewhere-else")
    with pytest.warns(RuntimeWarning, match="no Protected Resource Metadata route matches"):
        rewrite_prm_routes_verbatim([stray], issuer=_ISSUER, resource=_RESOURCE)


def test_no_warning_when_there_are_no_prm_routes_at_all() -> None:
    # Nothing under the prefix means there is nothing to rewrite — not a
    # mismatch. Warning here would fire on every app without a PRM route.
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        rewrite_prm_routes_verbatim([_prm_route("/health")], issuer=_ISSUER, resource=_RESOURCE)


def test_matches_the_route_upstream_registers_for_a_trailing_slash_resource() -> None:
    # Upstream derives the well-known path keeping a trailing path slash — its
    # rule is "the path unless it is exactly /" — while the derivation here
    # strips it. Every other shape agrees; only this one diverges. An equality
    # check matched nothing for a resource configured as `/mcp/`, and skipping
    # the wrap skips the issuer rewrite too, so authorization_servers kept the
    # slash-normalized form the core SDK rejects.
    resource = "https://api.example.com/mcp/"
    route = _prm_route("/.well-known/oauth-protected-resource/mcp/")
    original = route.app

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        rewrite_prm_routes_verbatim([route], issuer=_ISSUER, resource=resource)

    assert route.app is not original
