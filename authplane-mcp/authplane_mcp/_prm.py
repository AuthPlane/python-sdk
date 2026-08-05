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
"""

import json
from collections.abc import Awaitable, Callable, MutableSequence
from typing import Any

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
    extra entries. ``resource`` is set verbatim.

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
    if "resource" in doc and doc["resource"] != resource:
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


def rewrite_prm_routes_verbatim(
    routes: MutableSequence[BaseRoute], *, issuer: str, resource: str
) -> None:
    """Wrap, in place, every Protected Resource Metadata route in ``routes``.

    Matches routes registered under ``/.well-known/oauth-protected-resource``
    (RFC 9728 §3) and swaps their ASGI app for one that advertises ``issuer``
    and ``resource`` verbatim.
    """
    for route in routes:
        if isinstance(route, Route) and (
            route.path == _PRM_PATH_PREFIX or route.path.startswith(_PRM_PATH_PREFIX + "/")
        ):
            route.app = _wrap_app(route.app, issuer=issuer, resource=resource)
