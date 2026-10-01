"""Shared DPoP-context plumbing for the MCP and FastMCP adapters.

The ``authplane-mcp`` and ``authplane-fastmcp`` packages both bridge
``AuthplaneResource.verify`` to a Starlette-based ``TokenVerifier``.
They each need the same four pieces of glue:

* a concrete ``DPoPRequestContext`` shape built from the active request,
* a case-insensitive ``DPoP`` header reader,
* a path reader that preserves the on-wire percent-encoding (so
  ``htu`` binds against the target the client actually signed), and
* a per-request verify-task cache anchored on ``request.state`` so
  repeated ``verify_token`` invocations within one HTTP request do
  not re-enter the inbound DPoP replay store.

These live here so the two adapters do not drift. The module stays
underscore-prefixed and the request-based helpers are internal to the
adapter packages.

The three ``*_from_scope`` helpers are the exception: they are
re-exported from ``authplane.__init__`` and are supported API. They
exist for third-party raw-ASGI middleware, which is code outside this
repository — so leaving them reachable only as
``authplane._dpop_adapter`` would mean the only way to use them is to
import a private module of a ``0.x`` package, and a rename in any patch
release would break an installed resource server at import time. That is
the same reasoning that promoted ``validate_prm_resource_identifier`` to
the package root. Import them from ``authplane``, not from here.

The core ``authplane-sdk`` wheel does *not* take a runtime dependency
on Starlette. The helpers below duck-type the few attributes they
need; the ``_RequestLike`` Protocol pins that contract structurally
so the adapter packages can pass ``starlette.requests.Request`` and
type-check without forcing Starlette into the core's import graph.

Each helper comes in two shapes: a request-based one taking
``_RequestLike``, and a ``*_from_scope`` one taking the raw ASGI
``scope`` mapping. The scope shape exists because a resource server
protecting a long-lived ``text/event-stream`` body cannot go through
Starlette's ``BaseHTTPMiddleware`` — it pumps the response through an
internal queue, which buffers and stalls the stream — so that
middleware has to be raw ASGI, where there is no ``Request`` and no
``request.state``. Both shapes route through one implementation of
each rule, so the two entry points cannot drift from each other.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import TYPE_CHECKING, Any, Protocol, cast

from .errors import DPoPMultipleProofsError

if TYPE_CHECKING:
    import asyncio
    from collections.abc import Iterable, Mapping

    from .verifier import VerifiedClaims


__all__ = [
    "BuiltDPoPRequestContext",
    "VerifyTaskCache",
    "get_or_create_verify_cache",
    "get_or_create_verify_cache_from_scope",
    "raw_request_path",
    "raw_request_path_from_scope",
    "read_dpop_header",
    "read_dpop_header_from_scope",
]


REQ_STATE_KEY = "_authplane_verify_tasks"
"""Attribute name on ``request.state`` that holds the per-request verify-task cache.

Stringly-typed on purpose: ``request.state`` is shared per ASGI *scope*
(not per ``Request`` instance), so a ``WeakKeyDictionary[Request, ...]``
would split the cache across middleware-built and handler-built
``Request`` objects pointing at the same scope.

The same name is the key used inside ``scope["state"]`` by
:func:`get_or_create_verify_cache_from_scope`; Starlette's
``request.state`` is a thin wrapper over that dict, so both accessors
address one slot.
"""


SCOPE_STATE_KEY = "state"
"""ASGI ``scope`` key holding the per-connection state mapping.

The lifespan-state extension defines it, and Starlette's
``request.state`` wraps ``scope.setdefault("state", {})`` — which is
what lets the request-based and scope-based cache accessors agree.
"""


VerifyTaskCache = dict[str, "asyncio.Task[VerifiedClaims]"]


class _HeadersLike(Protocol):
    """Minimal slice of ``starlette.datastructures.Headers``."""

    def get(self, key: str, default: str | None = ...) -> str | None: ...

    def getlist(self, key: str) -> list[str]: ...


class _URLLike(Protocol):
    """Minimal slice of ``starlette.datastructures.URL``."""

    @property
    def path(self) -> str: ...


class _RequestLike(Protocol):
    """Structural subset of ``starlette.requests.Request`` consumed here.

    Defined as a Protocol so this module does not have to import
    Starlette — keeping it out of the core SDK's dependency graph.
    The adapters call these helpers with the real
    ``starlette.requests.Request`` and it satisfies the protocol
    structurally.
    """

    @property
    def headers(self) -> _HeadersLike: ...

    @property
    def scope(self) -> dict[str, object]: ...

    @property
    def state(self) -> object: ...

    @property
    def url(self) -> _URLLike: ...


class BuiltDPoPRequestContext:
    """Concrete ``DPoPRequestContext`` built from the active HTTP request.

    Structural conformance to ``authplane.DPoPRequestContext`` is all
    the core verifier checks. ``__slots__`` keeps the per-request
    construction cost negligible.
    """

    __slots__ = ("method", "proof", "url")

    def __init__(self, method: str, url: str, proof: str | None) -> None:
        self.method = method
        self.url = url
        self.proof = proof


def _single_proof(values: Iterable[str]) -> str | None:
    """Reduce the raw ``DPoP`` header values to the one proof, or reject.

    The RFC 9449 §4.3 #1 cardinality rule itself, shared by both header
    readers so the request-based and scope-based entry points cannot
    disagree about what counts as one proof.

    Two on-wire shapes are rejected:

    1. Multiple ``DPoP`` headers on the request (``values`` yields ≥ 2
       non-empty entries).
    2. A single ``DPoP`` header value pre-joined with ``,`` by an
       upstream proxy or framework — RFC 9110 §5.3 permits combining
       repeated headers this way. JWS compact serialization never
       contains a literal comma, so split-on-comma is sound.

    Trimming and empty-piece filtering are what make a request carrying
    ``"DPoP: "`` (whitespace only) count as header-absent rather than as
    one value.
    """
    filtered: list[str] = []
    for raw in values:
        trimmed = raw.strip()
        if not trimmed:
            continue
        # ``split(",", 2)`` caps the allocation on an attacker-controlled
        # header: we only need 0 / 1 / ≥ 2 non-blank pieces, and a third
        # entry already trips the cardinality guard below.
        for part in trimmed.split(",", 2):
            piece = part.strip()
            if piece:
                filtered.append(piece)
    if len(filtered) > 1:
        raise DPoPMultipleProofsError(
            f"request carries {len(filtered)} DPoP proofs (RFC 9449 §4.3 forbids it)"
        )
    return filtered[0] if filtered else None


def read_dpop_header_from_scope(scope: Mapping[str, Any]) -> str | None:
    """Read the ``DPoP`` header out of a raw ASGI ``scope``.

    Pure function of ``scope``, for middleware that has no ``Request``
    to hand. ``scope["headers"]`` is the ASGI iterable of
    ``(name, value)`` byte pairs; names arrive lowercased per the
    spec, and are lowercased again here so a server that does not is
    not a silent auth bypass. Values decode as latin-1, matching the
    HTTP/1.1 field-value encoding Starlette's ``Headers`` uses.

    Same return and rejection contract as :func:`read_dpop_header`.
    """
    values: list[str] = []
    for name, value in scope.get("headers") or ():
        if bytes(name).lower() == b"dpop":
            values.append(bytes(value).decode("latin-1"))
    return _single_proof(values)


def read_dpop_header(request: _RequestLike) -> str | None:
    """Read the ``DPoP`` request header, enforcing RFC 9449 §4.3 #1.

    Returns the single proof JWT when exactly one non-empty ``DPoP``
    header value is present, or ``None`` when no ``DPoP`` header is
    present. Raises :class:`DPoPMultipleProofsError` when the request
    carries more than one ``DPoP`` header value; see
    :func:`_single_proof` for the shapes that count as more than one.

    Reads through ``request.headers`` rather than ``request.scope``:
    ``_RequestLike`` is a structural Protocol, so an integration may
    well satisfy ``.headers`` without carrying ASGI-shaped raw headers
    in its ``scope``. Raw ASGI callers want
    :func:`read_dpop_header_from_scope`.
    """
    return _single_proof(request.headers.getlist("dpop"))


def _decode_raw_path(raw: bytes | bytearray) -> str:
    """Decode ``scope["raw_path"]`` into the path component of ``htu``.

    Percent-encoding is preserved — ASGI populates ``scope["path"]``
    percent-*decoded*, but the client signed its ``htu`` over the
    on-wire target, so a path containing e.g. ``%2F`` has to bind here
    exactly as it appeared in the request line.

    Everything from the first ``?`` on is dropped: RFC 9449 §4.2
    defines ``htu`` as the target URI *without* query or fragment, and
    the ASGI spec's wording on whether ``raw_path`` carries the query
    string has historically been read both ways. Every server in use
    strips it already — uvicorn on h11 and on httptools, and
    Starlette's ``TestClient`` — so this is hardening against a
    conforming-but-different server rather than a fix for a live
    break, and it is a no-op where the server already stripped it.
    """
    return bytes(raw).partition(b"?")[0].decode("latin-1")


def raw_request_path_from_scope(scope: Mapping[str, Any]) -> str:
    """Return the request path with percent-encoding preserved, from a raw ASGI ``scope``.

    Pure function of ``scope``, for middleware that has no ``Request``
    to hand. Falls back to the percent-decoded ``scope["path"]`` for
    the rare ASGI server that omits ``raw_path``.

    On that fallback branch the two entry points agree because
    Starlette's ``request.url.path`` is ``scope["path"]`` verbatim,
    including under a ``Mount`` with a non-empty ``root_path`` —
    measured on Starlette 1.3.1, since the two have historically been
    read as disagreeing about whether ``root_path`` is a prefix. Should
    a future version prefix it, the two would produce different ``htu``
    paths under a sub-mount on a server that omits ``raw_path``; every
    server this SDK targets sets ``raw_path``, so the branch is
    unreachable in practice.
    """
    raw = scope.get("raw_path")
    if isinstance(raw, (bytes, bytearray)):
        return _decode_raw_path(raw)
    path = scope.get("path")
    return path if isinstance(path, str) else ""


def raw_request_path(request: _RequestLike) -> str:
    """Return the request path with percent-encoding preserved.

    Prefers ``scope["raw_path"]`` and decodes it through
    :func:`_decode_raw_path`, which is where the percent-encoding and
    query-string rules live. Falls back to ``request.url.path`` — not
    to ``scope["path"]``, so that a ``_RequestLike`` implementation
    carrying a non-ASGI ``scope`` keeps reporting the path its own URL
    reports.
    """
    raw = request.scope.get("raw_path")
    if isinstance(raw, (bytes, bytearray)):
        return _decode_raw_path(raw)
    return request.url.path


def get_or_create_verify_cache_from_scope(scope: MutableMapping[str, Any]) -> VerifyTaskCache:
    """Return the per-request verify-task cache for a raw ASGI ``scope``.

    Anchored on ``scope["state"]``, which is the dict Starlette's
    ``request.state`` wraps — so a raw-ASGI middleware and any
    Starlette layer above it in the same request share one cache
    instead of each re-entering the inbound DPoP replay store, and
    this helper is interchangeable with
    :func:`get_or_create_verify_cache` on the requests where both
    apply.

    The cache is per *request* only insofar as the server gives each
    request its own ``state`` mapping — the ASGI lifespan-state
    extension requires a shallow copy per connection, and the
    request-based accessor already depends on exactly that invariant.
    A caller on a server that cannot promise it should keep the cache
    itself and skip this helper; the header and path readers above are
    the parts of this module a raw-ASGI integration actually needs.
    """
    # Only create when absent, and accept any mutable mapping. The ASGI
    # lifespan-state extension specifies `scope["state"]` as a *mapping*, not a
    # `dict`, so a server handing over some other MutableMapping used to get its
    # state object replaced — which drops whatever the application put in
    # lifespan state for the rest of the request, and breaks the invariant this
    # helper is built on: Starlette's `Request.state` uses `scope.setdefault`,
    # so if a `Request` was constructed first, `State` would wrap the original
    # mapping while this helper pointed at a fresh dict. The two layers would
    # then each re-enter the inbound DPoP replay store for the same `jti`,
    # which is `DPoPReplayDetectedError` on an honest request — precisely the
    # failure the shared slot exists to prevent.
    existing: object = scope.get(SCOPE_STATE_KEY)
    state: MutableMapping[str, Any]
    if isinstance(existing, MutableMapping):
        # `isinstance` cannot check the parameters; the ASGI extension specifies
        # str keys, and a server that violates that would break every other
        # reader of this slot too.
        state = cast("MutableMapping[str, Any]", existing)
    else:
        state = {}
        scope[SCOPE_STATE_KEY] = state
    cache: VerifyTaskCache | None = state.get(REQ_STATE_KEY)
    if cache is None:
        cache = {}
        state[REQ_STATE_KEY] = cache
    return cache


def get_or_create_verify_cache(request: _RequestLike) -> VerifyTaskCache:
    """Return the per-request verify-task cache, creating it on first access.

    Lives on ``request.state`` so it is scoped to the ASGI request and
    disappears with it; cross-request replay protection is preserved.
    The adapters' tests use this accessor to inspect the cache without
    manipulating ``request.state`` or the stringly-typed slot directly.

    Raw ASGI callers want :func:`get_or_create_verify_cache_from_scope`,
    which reaches the same slot through ``scope["state"]``.
    """
    state = request.state
    cache: VerifyTaskCache | None = getattr(state, REQ_STATE_KEY, None)
    if cache is None:
        cache = {}
        setattr(state, REQ_STATE_KEY, cache)
    return cache
