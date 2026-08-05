"""Unit tests for the verbatim-PRM body rewrite.

``_rewrite_body`` swaps the configured identifiers back to their verbatim form
(the upstream MCP machinery serializes them through ``pydantic.AnyHttpUrl``,
which appends a trailing slash to an empty-path authority) without disturbing
any other advertised field.
"""

import json

from authplane_mcp._prm import _rewrite_body

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
