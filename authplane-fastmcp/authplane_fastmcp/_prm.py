"""Serve the Protected Resource Metadata identifiers verbatim.

The core SDK stores and compares the issuer / resource identifier byte-for-byte
(RFC 8414 §3.3, RFC 9728 §3.3). The upstream MCP machinery that serves the PRM
document types ``authorization_servers`` and ``resource`` as
``pydantic.AnyHttpUrl``, which normalizes an empty-path authority by appending a
trailing slash (``https://auth.example.com`` -> ``https://auth.example.com/``).
A client that follows that advertised value literally then does discovery and
audience checks against the slashed form and is rejected by the strict
comparison ("issuer mismatch"), and a token minted for the advertised
``resource`` fails the verbatim ``aud`` check.

This module post-processes the served PRM response so the two identifier fields
carry exactly the operator-configured strings, without touching any other field
(scopes, bearer methods, cache headers, CORS) the upstream route emits.

NOTE: this module is mirrored byte-for-byte in
``authplane-mcp/authplane_mcp/_prm.py``. It is the larger and subtler of
the two duplicated modules — the rewrite gating below is easy to get wrong in one
copy only. Any fix here must be applied to both.
"""

import json
import warnings
from collections.abc import Awaitable, Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

from starlette.routing import BaseRoute, Route

_PRM_PATH_PREFIX = "/.well-known/oauth-protected-resource"

_Scope = dict[str, Any]
_Message = dict[str, Any]
_Receive = Callable[[], Awaitable[_Message]]
_Send = Callable[[_Message], Awaitable[None]]
_ASGIApp = Callable[[_Scope, _Receive, _Send], Awaitable[None]]


def _rewrite_body(body: bytes, *, issuer: str, resource: str) -> bytes:
    """Return the PRM JSON body with the configured identifiers set verbatim.

    Rewrites only the entries that match the configured identifier up to a
    trailing-slash normalization: in ``authorization_servers`` the element equal
    to ``issuer`` or ``issuer + "/"`` is swapped for the verbatim ``issuer`` and
    every other entry is left in place, so a multi-AS advertisement keeps its
    extra entries. ``resource`` is replaced outright: the caller only routes this
    function at the document belonging to the configured resource.

    Any body that is not a JSON object (e.g. a CORS preflight with an empty
    body) is returned unchanged.
    """
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return body
    if not isinstance(doc, dict):
        return body
    changed = False
    servers = doc.get("authorization_servers")
    if isinstance(servers, list):
        rewritten = [issuer if entry in (issuer, issuer + "/") else entry for entry in servers]
        if rewritten != servers:
            doc["authorization_servers"] = rewritten
            changed = True
    # Unconditional: which document this is was already decided by route
    # matching in rewrite_prm_routes_verbatim, so anything served here belongs to
    # the configured resource. Gating on the value instead would only cover the
    # trailing-slash normalization and silently skip every other one the URL
    # layer can apply (host case, an explicit default port, a doubled slash, a
    # dot segment) — which is precisely the mismatch this module exists to fix.
    if doc.get("resource") != resource:
        doc["resource"] = resource
        changed = True
    if not changed:
        return body
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def _wrap_app(inner: _ASGIApp, *, issuer: str, resource: str) -> _ASGIApp:
    """Wrap an ASGI app so a JSON PRM body is rewritten before it is sent.

    The PRM document is small and always flushed in a single body frame, so
    the wrapper buffers the whole body, rewrites it, then emits the (possibly
    resized) response in one shot.
    """

    async def app(scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope.get("type") != "http":
            await inner(scope, receive, send)
            return

        start: _Message | None = None
        chunks: list[bytes] = []

        async def capture(message: _Message) -> None:
            nonlocal start
            message_type = message["type"]
            if message_type == "http.response.start":
                # Defer the start frame until the body is assembled so the
                # Content-Length header can be corrected for the rewrite.
                start = message
                return
            if message_type == "http.response.body":
                chunks.append(message.get("body", b""))
                if message.get("more_body", False):
                    return
                if start is None:
                    # An ASGI server must send http.response.start before any
                    # http.response.body frame; guard explicitly rather than
                    # asserting, since ``assert`` is stripped under ``python -O``.
                    raise RuntimeError("http.response.body received before http.response.start")
                new_body = _rewrite_body(b"".join(chunks), issuer=issuer, resource=resource)
                headers = [
                    (key, value)
                    for (key, value) in start.get("headers", [])
                    if key.lower() != b"content-length"
                ]
                headers.append((b"content-length", str(len(new_body)).encode("latin-1")))
                await send({**start, "headers": headers})
                await send({"type": "http.response.body", "body": new_body})
                return
            await send(message)

        await inner(scope, receive, capture)

    return app


def rewrite_prm_routes_verbatim(routes: Iterable[BaseRoute], *, issuer: str, resource: str) -> None:
    """Wrap, in place, the Protected Resource Metadata route for ``resource``.

    Selects by route path, not by document contents: RFC 9728 §3.1 derives the
    well-known path *from* the resource identifier, so the path is what says
    which resource a document describes. An app serving PRM for several
    resources registers one route each, and only the matching one is wrapped.

    Matching on the path rather than on the served ``resource`` value is what
    keeps full normalization coverage. The served value has been through the
    URL layer and can differ from the configured string by more than a trailing
    slash; the path has not.

    Emits a ``RuntimeWarning`` when routes exist under the well-known prefix but
    none is the derivation of ``resource`` — that means the rewrite did nothing,
    and a silent no-op here ships a PRM advertising identifiers the core SDK's
    byte-for-byte comparison rejects.
    """
    target = _PRM_PATH_PREFIX + urlsplit(resource).path.rstrip("/")
    seen_prefix = False
    wrapped = False
    for route in routes:
        if not isinstance(route, Route):
            continue
        if route.path == _PRM_PATH_PREFIX or route.path.startswith(_PRM_PATH_PREFIX + "/"):
            seen_prefix = True
            # Compare right-stripped: upstream keeps a trailing path slash when
            # deriving the well-known path (its rule is "the path unless it is
            # exactly /"), while `target` strips it. Everything else agrees. Left
            # as an equality check, a resource configured as `/mcp/` matched no
            # route — and skipping the wrap skips the *issuer* rewrite too, so
            # `authorization_servers` kept the slash-normalized form the core
            # SDK rejects. The prefix match this replaced covered that shape.
            #
            # What it trades away: an application serving `/mcp` and `/mcp/` as
            # two distinct resources has both routes wrapped, which is the
            # sibling clobber that route selection exists to prevent. Two
            # identifiers differing only by a trailing slash collapse to one
            # document under *this* SDK's derivation, and under the TS
            # sibling's, which documents the same choice (`core/prm.ts`:
            # "Trailing slashes on the resource path are dropped"). RFC 9728
            # §3.1 does not settle the case — it says to insert the well-known
            # segment between the host and the path, and says nothing about
            # normalizing a terminating slash — and upstream keeps it, deriving
            # two documents. That divergence is where the trailing-slash bug
            # came from, and it is why this comparison is right-stripped at
            # all. Given our derivation, the pair is pathological rather than a
            # case to support.
            if route.path.rstrip("/") == target:
                route.app = _wrap_app(route.app, issuer=issuer, resource=resource)
                wrapped = True
    if seen_prefix and not wrapped:
        warnings.warn(
            f"no Protected Resource Metadata route matches {target!r} (the RFC 9728 "
            f"§3.1 derivation of {resource!r}), so the served document keeps the "
            "slash-normalized identifiers the core SDK's byte-for-byte comparison "
            "rejects. Routes under the well-known prefix were found, so the "
            "derivation and the registered path disagree.",
            RuntimeWarning,
            stacklevel=2,
        )
