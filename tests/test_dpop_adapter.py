"""Tests for the shared _dpop_adapter helpers.

These pin the cross-adapter contracts (cardinality enforcement, raw-path
reading) without requiring either adapter package's full plumbing — the
helpers duck-type against a structural Protocol so tests can drive them
with a small fake Headers/Request shape.

The ``*_from_scope`` helpers take a raw ASGI ``scope`` mapping instead,
for middleware protecting a long-lived ``text/event-stream`` body, which
cannot run under Starlette's ``BaseHTTPMiddleware``. Those tests build
the scope dict directly.
"""

from __future__ import annotations

from collections.abc import Iterator, MutableMapping

import pytest

from authplane._dpop_adapter import (
    get_or_create_verify_cache,
    get_or_create_verify_cache_from_scope,
    raw_request_path,
    raw_request_path_from_scope,
    read_dpop_header,
    read_dpop_header_from_scope,
)
from authplane.errors import DPoPMultipleProofsError


class _FakeHeaders:
    """Minimal stand-in for ``starlette.datastructures.Headers``.

    Returns the configured multi-value list from ``getlist``; ``get``
    is implemented for protocol conformance but is intentionally not
    exercised here — :func:`read_dpop_header` reads via ``getlist``.
    """

    def __init__(self, values: list[str]) -> None:
        self._values = values

    def get(self, key: str, default: str | None = None) -> str | None:
        _ = key
        return self._values[0] if self._values else default

    def getlist(self, key: str) -> list[str]:
        _ = key
        return list(self._values)


class _FakeRequest:
    def __init__(self, dpop_values: list[str]) -> None:
        self._headers = _FakeHeaders(dpop_values)

    @property
    def headers(self) -> _FakeHeaders:
        return self._headers

    @property
    def scope(self) -> dict[str, object]:
        return {}

    @property
    def state(self) -> object:  # pragma: no cover - unused here
        return object()

    @property
    def url(self) -> object:  # pragma: no cover - unused here
        return object()


def test_no_dpop_header_returns_none() -> None:
    assert read_dpop_header(_FakeRequest([])) is None  # pyright: ignore[reportArgumentType]


def test_single_dpop_header_returns_proof() -> None:
    assert read_dpop_header(_FakeRequest(["a.b.c"])) == "a.b.c"  # pyright: ignore[reportArgumentType]


def test_whitespace_only_header_is_treated_as_absent() -> None:
    """``DPoP: `` (whitespace only) must not be miscounted as one value."""
    assert read_dpop_header(_FakeRequest(["   "])) is None  # pyright: ignore[reportArgumentType]


def test_two_dpop_headers_reject() -> None:
    """Duplicate ``DPoP`` headers on the request fail §4.3 #1."""
    with pytest.raises(DPoPMultipleProofsError, match="2 DPoP proofs"):
        read_dpop_header(_FakeRequest(["a.b.c", "x.y.z"]))  # pyright: ignore[reportArgumentType]


def test_comma_joined_proxy_shape_reject() -> None:
    """RFC 9110 §5.3 lets proxies join repeated headers with `,`.

    JWS compact serialization never carries a literal `,`, so a comma in
    a single ``DPoP`` value is unambiguously the proxy-joined shape and
    must trip the same cardinality guard as two separate headers.
    """
    with pytest.raises(DPoPMultipleProofsError, match="2 DPoP proofs"):
        read_dpop_header(_FakeRequest(["a.b.c, x.y.z"]))  # pyright: ignore[reportArgumentType]


def test_three_values_across_shapes_reject() -> None:
    """Mixed multi-header + comma-joined still trips the guard."""
    with pytest.raises(DPoPMultipleProofsError, match=r"3 DPoP proofs"):
        read_dpop_header(_FakeRequest(["a.b.c", "x.y.z, p.q.r"]))  # pyright: ignore[reportArgumentType]


def test_single_value_is_trimmed() -> None:
    """Leading/trailing whitespace around a sole proof is stripped."""
    assert (
        read_dpop_header(_FakeRequest(["  a.b.c  "]))  # pyright: ignore[reportArgumentType]
        == "a.b.c"
    )


def test_all_blank_pieces_treated_as_absent() -> None:
    """``", ,"`` carries no real proof — return ``None``, do not reject."""
    assert read_dpop_header(_FakeRequest([" , , "])) is None  # pyright: ignore[reportArgumentType]


class _FakeURL:
    def __init__(self, path: str) -> None:
        self.path = path


class _FakePathRequest:
    """Request shape for the path helper: a ``scope`` and a ``url``."""

    def __init__(self, scope: dict[str, object], url_path: str = "/decoded") -> None:
        self._scope = scope
        self._url = _FakeURL(url_path)

    @property
    def headers(self) -> _FakeHeaders:  # pragma: no cover - unused here
        return _FakeHeaders([])

    @property
    def scope(self) -> dict[str, object]:
        return self._scope

    @property
    def state(self) -> object:  # pragma: no cover - unused here
        return object()

    @property
    def url(self) -> _FakeURL:
        return self._url


def _http_scope(**extra: object) -> dict[str, object]:
    return {"type": "http", "method": "GET", "headers": [], **extra}


def test_scope_raw_path_strips_query_string() -> None:
    """RFC 9449 §4.2: ``htu`` carries no query component.

    The MCP SSE transport puts a per-session id in the query string of
    ``POST /messages/``, so a leaked query would change the URL on every
    request and no proof would ever verify.
    """
    scope = _http_scope(raw_path=b"/messages/?session_id=abc123", path="/messages/")
    assert raw_request_path_from_scope(scope) == "/messages/"


def test_request_raw_path_strips_query_string() -> None:
    """The request-based reader applies the same rule as the scope one."""
    request = _FakePathRequest(_http_scope(raw_path=b"/messages/?session_id=abc123"))
    assert raw_request_path(request) == "/messages/"  # pyright: ignore[reportArgumentType]


def test_raw_path_without_query_is_unchanged() -> None:
    scope = _http_scope(raw_path=b"/mcp", path="/mcp")
    assert raw_request_path_from_scope(scope) == "/mcp"
    assert raw_request_path(_FakePathRequest(scope)) == "/mcp"  # pyright: ignore[reportArgumentType]


def test_raw_path_preserves_percent_encoding() -> None:
    """``%2F`` must survive: the client signed ``htu`` over the on-wire target.

    ASGI populates ``scope["path"]`` percent-*decoded*, which would turn
    ``%2F`` into a real separator and bind an ``htu`` the client never
    signed.
    """
    scope = _http_scope(raw_path=b"/tools/a%2Fb", path="/tools/a/b")
    assert raw_request_path_from_scope(scope) == "/tools/a%2Fb"
    assert raw_request_path(_FakePathRequest(scope)) == "/tools/a%2Fb"  # pyright: ignore[reportArgumentType]


def test_raw_path_query_strip_keeps_encoded_question_mark() -> None:
    """Only the real delimiter splits; a percent-encoded ``?`` is path data."""
    scope = _http_scope(raw_path=b"/tools/a%3Fb?x=1")
    assert raw_request_path_from_scope(scope) == "/tools/a%3Fb"


def test_scope_without_raw_path_falls_back_to_path() -> None:
    """Rare ASGI server that omits ``raw_path``: use the decoded path."""
    assert raw_request_path_from_scope(_http_scope(path="/mcp")) == "/mcp"


def test_scope_without_raw_path_or_path_returns_empty() -> None:
    assert raw_request_path_from_scope(_http_scope()) == ""


def test_request_without_raw_path_falls_back_to_url_path() -> None:
    """The request reader falls back to ``request.url.path``, not ``scope["path"]``.

    ``_RequestLike`` is structural, so an implementation may carry a
    non-ASGI ``scope``; its own URL stays authoritative there.
    """
    request = _FakePathRequest(_http_scope(path="/from-scope"), url_path="/from-url")
    assert raw_request_path(request) == "/from-url"  # pyright: ignore[reportArgumentType]


def test_read_dpop_header_from_scope_picks_the_dpop_header() -> None:
    """Case-insensitive pick out of a multi-header ASGI header list."""
    scope = _http_scope(
        headers=[
            (b"host", b"api.example.com"),
            (b"authorization", b"DPoP token"),
            (b"DPoP", b"a.b.c"),
            (b"accept", b"text/event-stream"),
        ]
    )
    assert read_dpop_header_from_scope(scope) == "a.b.c"


def test_read_dpop_header_from_scope_absent_returns_none() -> None:
    scope = _http_scope(headers=[(b"host", b"api.example.com")])
    assert read_dpop_header_from_scope(scope) is None


def test_read_dpop_header_from_scope_rejects_two_headers() -> None:
    """Duplicate ``DPoP`` headers fail §4.3 #1 on the scope path too."""
    scope = _http_scope(headers=[(b"dpop", b"a.b.c"), (b"dpop", b"x.y.z")])
    with pytest.raises(DPoPMultipleProofsError, match="2 DPoP proofs"):
        read_dpop_header_from_scope(scope)


def test_read_dpop_header_from_scope_rejects_comma_joined() -> None:
    scope = _http_scope(headers=[(b"dpop", b"a.b.c, x.y.z")])
    with pytest.raises(DPoPMultipleProofsError, match="2 DPoP proofs"):
        read_dpop_header_from_scope(scope)


def test_read_dpop_header_from_scope_trims_and_ignores_blank() -> None:
    assert read_dpop_header_from_scope(_http_scope(headers=[(b"dpop", b"  a.b.c  ")])) == "a.b.c"
    assert read_dpop_header_from_scope(_http_scope(headers=[(b"dpop", b"   ")])) is None


def test_read_dpop_header_from_scope_without_headers_key() -> None:
    assert read_dpop_header_from_scope({"type": "http"}) is None


class _FakeState:
    """Stand-in for ``starlette.datastructures.State``.

    Starlette's ``request.state`` is exactly this: attribute access over
    the ``scope["state"]`` dict. Reproduced here so the shared-slot
    contract is pinned without a Starlette dependency in the core tests.
    """

    _state: dict[str, object]

    def __init__(self, state: dict[str, object]) -> None:
        object.__setattr__(self, "_state", state)

    def __setattr__(self, key: str, value: object) -> None:
        self._state[key] = value

    def __getattr__(self, key: str) -> object:
        try:
            return self._state[key]
        except KeyError:
            raise AttributeError(key) from None


class _FakeStatefulRequest:
    def __init__(self, scope: dict[str, object]) -> None:
        self._scope = scope
        scope.setdefault("state", {})
        self._state = _FakeState(scope["state"])  # type: ignore[arg-type]

    @property
    def headers(self) -> _FakeHeaders:  # pragma: no cover - unused here
        return _FakeHeaders([])

    @property
    def scope(self) -> dict[str, object]:
        return self._scope

    @property
    def state(self) -> _FakeState:
        return self._state

    @property
    def url(self) -> _FakeURL:  # pragma: no cover - unused here
        return _FakeURL("/")


def test_scope_verify_cache_is_created_once() -> None:
    scope = _http_scope()
    first = get_or_create_verify_cache_from_scope(scope)
    assert get_or_create_verify_cache_from_scope(scope) is first


def test_scope_verify_cache_is_not_shared_across_scopes() -> None:
    assert get_or_create_verify_cache_from_scope(_http_scope()) is not (
        get_or_create_verify_cache_from_scope(_http_scope())
    )


def test_scope_and_request_verify_caches_are_the_same_slot() -> None:
    """A raw-ASGI middleware and a Starlette layer above it share one cache.

    Otherwise the second layer re-enters the inbound DPoP replay store
    for a proof the first one already consumed.
    """
    scope = _http_scope()
    request = _FakeStatefulRequest(scope)
    from_scope = get_or_create_verify_cache_from_scope(scope)
    assert get_or_create_verify_cache(request) is from_scope  # pyright: ignore[reportArgumentType]


def test_request_verify_cache_seen_from_scope() -> None:
    """Same slot in the other direction: request first, scope second."""
    scope = _http_scope()
    request = _FakeStatefulRequest(scope)
    from_request = get_or_create_verify_cache(request)  # pyright: ignore[reportArgumentType]
    assert get_or_create_verify_cache_from_scope(scope) is from_request


def test_scope_verify_cache_preserves_a_non_dict_state_mapping() -> None:
    """A non-``dict`` mapping in ``scope["state"]`` is used, not replaced.

    The ASGI lifespan-state extension specifies a *mapping*, not a ``dict``.
    Replacing it drops whatever the application put in lifespan state for the
    rest of the request, and splits the shared slot: Starlette's
    ``Request.state`` uses ``scope.setdefault``, so a ``Request`` built first
    would wrap the original while this helper pointed at a fresh dict — and the
    two layers would each re-enter the replay store for one ``jti``.
    """

    class _MappingState(MutableMapping[str, object]):
        """A MutableMapping that is deliberately not a ``dict``."""

        def __init__(self) -> None:
            self._data: dict[str, object] = {}

        def __getitem__(self, key: str) -> object:
            return self._data[key]

        def __setitem__(self, key: str, value: object) -> None:
            self._data[key] = value

        def __delitem__(self, key: str) -> None:
            del self._data[key]

        def __iter__(self) -> Iterator[str]:
            return iter(self._data)

        def __len__(self) -> int:
            return len(self._data)

    state = _MappingState()
    state["lifespan-value"] = "must survive"
    scope = _http_scope()
    scope["state"] = state

    cache = get_or_create_verify_cache_from_scope(scope)

    assert scope["state"] is state, "the server's own state mapping was replaced"
    assert state["lifespan-value"] == "must survive"
    assert get_or_create_verify_cache_from_scope(scope) is cache
