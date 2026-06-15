"""Shared DPoP-context plumbing for the MCP and FastMCP adapters.

The ``authplane-mcp`` and ``authplane-fastmcp`` packages both bridge
``AuthplaneResource.verify`` to a Starlette-based ``TokenVerifier``.
They each need the same four pieces of glue:

* a concrete ``DPoPRequestContext`` shape built from the active request,
* a case-insensitive ``DPoP`` header reader,
* a path reader that preserves the on-wire percent-encoding (so
  ``htu`` binds identically against the TS sibling), and
* a per-request verify-task cache anchored on ``request.state`` so
  repeated ``verify_token`` invocations within one HTTP request do
  not re-enter the inbound DPoP replay store.

These live here so the two adapters do not drift. The module is
underscore-prefixed and intentionally not re-exported from
``authplane.__init__``; nothing outside the adapter packages should
import from it.

The core ``authplane-sdk`` wheel does *not* take a runtime dependency
on Starlette. The helpers below duck-type the few attributes they
need; the ``_RequestLike`` Protocol pins that contract structurally
so the adapter packages can pass ``starlette.requests.Request`` and
type-check without forcing Starlette into the core's import graph.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import asyncio

    from .verifier import VerifiedClaims


__all__ = [
    "BuiltDPoPRequestContext",
    "VerifyTaskCache",
    "get_or_create_verify_cache",
    "raw_request_path",
    "read_dpop_header",
]


REQ_STATE_KEY = "_authplane_verify_tasks"
"""Attribute name on ``request.state`` that holds the per-request verify-task cache.

Stringly-typed on purpose: ``request.state`` is shared per ASGI *scope*
(not per ``Request`` instance), so a ``WeakKeyDictionary[Request, ...]``
would split the cache across middleware-built and handler-built
``Request`` objects pointing at the same scope.
"""


VerifyTaskCache = dict[str, "asyncio.Task[VerifiedClaims]"]


class _HeadersLike(Protocol):
    """Minimal slice of ``starlette.datastructures.Headers``."""

    def get(self, key: str, default: str | None = ...) -> str | None: ...


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


def read_dpop_header(request: _RequestLike) -> str | None:
    """Read the ``DPoP`` request header (case-insensitive, first value).

    Starlette's ``Headers.get`` already does case-insensitive lookup
    and returns the first occurrence when a header is repeated. Strict
    rejection of repeated ``DPoP`` headers (RFC 9449 §4.3 #1) is
    tracked separately and is intentionally not enforced here so this
    layer does not overlap with that work.
    """
    return request.headers.get("dpop")


def raw_request_path(request: _RequestLike) -> str:
    """Return the request path with percent-encoding preserved.

    ASGI populates ``scope["path"]`` as the percent-decoded path, but
    the client signed its DPoP ``htu`` over the on-wire (percent-encoded)
    target. Prefer ``scope["raw_path"]`` (raw bytes) so a path
    containing e.g. ``%2F`` binds identically here and in the TS
    sibling, which builds ``htu`` from ``IncomingMessage.url``. Falls
    back to the decoded path for the rare ASGI server that omits
    ``raw_path``.
    """
    raw = request.scope.get("raw_path")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("latin-1")
    return request.url.path


def get_or_create_verify_cache(request: _RequestLike) -> VerifyTaskCache:
    """Return the per-request verify-task cache, creating it on first access.

    Lives on ``request.state`` so it is scoped to the ASGI request and
    disappears with it; cross-request replay protection is preserved.
    The adapters' tests use this accessor to inspect the cache without
    manipulating ``request.state`` or the stringly-typed slot directly.
    """
    state = request.state
    cache: VerifyTaskCache | None = getattr(state, REQ_STATE_KEY, None)
    if cache is None:
        cache = {}
        setattr(state, REQ_STATE_KEY, cache)
    return cache
