"""DPoP context forwarding + per-request verify cache tests for authplane-mcp.

Mirrors ``authplane-fastmcp/tests/test_verifier_dpop_cache.py`` so the
two adapters' DPoP-enforcement contracts stay observably identical. The
only adapter-specific seam is the ``get_http_request`` lookup: FastMCP
ships ``fastmcp.server.dependencies.get_http_request``; the MCP SDK has
no equivalent, so this package ships
:class:`AuthplaneRequestContextMiddleware` and the verifier reads from
:func:`authplane_mcp.get_current_request`. The tests bypass that
plumbing by injecting a fake ``get_http_request`` directly.

Covers:

* ``verify_token`` must build a ``DPoPRequestContext`` from the active
  request and forward it to ``AuthplaneResource.verify``. Without it,
  a resource configured for ``inbound_dpop=required=True`` silently
  accepts bearer-only requests even though PRM advertises the
  requirement — the same silent-pass that landed first in the FastMCP
  sibling.
* Repeated ``verify_token`` calls within the same request collapse
  onto a single underlying ``verify`` so the inbound replay store
  cannot see the same proof ``jti`` twice within one request. Distinct
  requests get distinct caches so cross-request replay protection is
  preserved.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, PropertyMock

import pytest
from authplane import AuthplaneResource, DPoPReplayDetectedError, VerifiedClaims
from authplane._dpop_adapter import get_or_create_verify_cache
from starlette.requests import Request

from authplane_mcp import AuthplaneTokenVerifier


def _make_request(
    *,
    method: str = "POST",
    path: str = "/mcp",
    query: str = "",
    host: str = "testserver",
    headers: dict[str, str] | None = None,
) -> Request:
    """Synthesize a Starlette ``Request`` suitable for driving the verifier.

    The verifier reconstructs ``htu`` from the operator-configured
    resource origin, so the ``host`` here is intentionally divergent —
    the tests assert the request's ``Host`` header is *not* what ends up
    in the proof binding.
    """
    raw_headers: list[tuple[bytes, bytes]] = []
    if headers:
        for key, value in headers.items():
            raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))
    scope: dict[str, Any] = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": query.encode("latin-1"),
        "headers": raw_headers,
        "scheme": "http",
        "server": (host, 80),
        "client": None,
        "root_path": "",
        "http_version": "1.1",
    }
    return Request(scope)


def _mock_verifier(
    *,
    resource: str = "https://api.example.com/mcp",
    claims: VerifiedClaims | None = None,
    raise_exc: BaseException | None = None,
) -> AsyncMock:
    """Build an ``AuthplaneResource`` mock with the verify contract pinned.

    Returning a ``VerifiedClaims`` (or raising) on every call lets the
    cache tests count invocations via ``mock.verify.call_count``.
    """
    if claims is None and raise_exc is None:
        now = int(time.time())
        claims = VerifiedClaims(
            sub="user_123",
            client_id="client_456",
            scopes=("tools/query",),
            issuer="https://auth.example.com",
            audience=("https://api.example.com",),
            expires_at=now + 3600,
            issued_at=now,
            jti="token-id-123",
            kid="test-key-1",
            raw={
                "iss": "https://auth.example.com",
                "aud": "https://api.example.com",
                "sub": "user_123",
                "client_id": "client_456",
                "scope": "tools/query",
                "exp": now + 3600,
                "nbf": now,
                "iat": now,
                "jti": "token-id-123",
            },
        )
    mock = AsyncMock(spec=AuthplaneResource)
    type(mock).resource = PropertyMock(return_value=resource)

    async def verify(token: str, *, dpop_request: object | None = None) -> VerifiedClaims:
        _ = token, dpop_request
        if raise_exc is not None:
            raise raise_exc
        assert claims is not None
        return claims

    mock.verify = AsyncMock(side_effect=verify)
    return mock


def _make_token_verifier(
    mock_resource: AsyncMock, request: Request | None
) -> AuthplaneTokenVerifier:
    """Token verifier wired to a fake ``get_http_request`` for tests.

    ``request=None`` simulates ``RuntimeError("No active HTTP request found.")``
    that :func:`authplane_mcp.get_current_request` raises when the ASGI
    middleware was not installed (or the call is outside any request).
    """

    def fake_get_http_request() -> Request:
        if request is None:
            raise RuntimeError("No active HTTP request found.")
        return request

    return AuthplaneTokenVerifier(mock_resource, get_http_request=fake_get_http_request)


# ---------------------------------------------------------------------------
# DPoP context is built and forwarded to AuthplaneResource.verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dpop_context_forwarded_to_verify() -> None:
    """verify_token must pass a DPoPRequestContext to verify().

    Before this change ``authplane-mcp`` carried the same silent-pass
    bug the FastMCP sibling shipped: ``verify(token)`` with no
    ``dpop_request=`` made any ``inbound_dpop=required=True`` config a
    no-op even though PRM advertised the requirement.
    """
    mock = _mock_verifier()
    request = _make_request(
        method="POST",
        path="/mcp",
        headers={"DPoP": "fake.proof.jwt"},
    )
    verifier = _make_token_verifier(mock, request)

    result = await verifier.verify_token("valid_token")

    assert result is not None
    assert mock.verify.await_count == 1
    kwargs = mock.verify.await_args.kwargs
    ctx = kwargs["dpop_request"]
    assert ctx is not None
    assert ctx.method == "POST"
    assert ctx.url == "https://api.example.com/mcp"
    assert ctx.proof == "fake.proof.jwt"


@pytest.mark.asyncio
async def test_dpop_context_proof_none_when_header_absent() -> None:
    """Context is still built (so htm/htu reach the verifier), proof=None.

    Lets the core verifier's required-mode path fail closed when the
    access token is DPoP-bound but the client did not present a proof.
    """
    mock = _mock_verifier()
    request = _make_request(headers={"authorization": "Bearer xyz"})
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("valid_token")

    ctx = mock.verify.await_args.kwargs["dpop_request"]
    assert ctx is not None
    assert ctx.proof is None
    assert ctx.method == "POST"
    assert ctx.url == "https://api.example.com/mcp"


@pytest.mark.asyncio
async def test_dpop_context_header_lookup_is_case_insensitive() -> None:
    """RFC 7230 says HTTP header names are case-insensitive; verify the wire."""
    mock = _mock_verifier()
    request = _make_request(headers={"dpop": "lower.case.proof"})
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("valid_token")

    assert mock.verify.await_args.kwargs["dpop_request"].proof == "lower.case.proof"


@pytest.mark.asyncio
async def test_duplicate_dpop_headers_fail_auth() -> None:
    """Two ``DPoP`` headers on one request violate RFC 9449 §4.3 #1.

    The adapter must fail authentication (``verify_token`` returns
    ``None``) without ever invoking the underlying ``verify`` — the
    cardinality guard runs before the resource verifier sees the proof.
    """
    mock = _mock_verifier()
    # Bypass _make_request to inject two DPoP headers; the helper's dict
    # shape cannot represent the duplicate.
    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": [
            (b"dpop", b"proof.one.x"),
            (b"dpop", b"proof.two.y"),
        ],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": None,
        "root_path": "",
        "http_version": "1.1",
    }
    request = Request(scope)
    verifier = _make_token_verifier(mock, request)

    result = await verifier.verify_token("valid_token")
    assert result is None
    mock.verify.assert_not_awaited()


@pytest.mark.asyncio
async def test_comma_joined_dpop_value_fails_auth() -> None:
    """A single comma-joined ``DPoP`` value (the proxy-collapsed shape
    permitted by RFC 9110 §5.3) is unambiguously two proofs — JWS compact
    has no literal comma — and must trip the same §4.3 guard.
    """
    mock = _mock_verifier()
    request = _make_request(headers={"DPoP": "a.b.c, x.y.z"})
    verifier = _make_token_verifier(mock, request)

    result = await verifier.verify_token("valid_token")
    assert result is None
    mock.verify.assert_not_awaited()


@pytest.mark.asyncio
async def test_htu_origin_from_configured_resource_not_host_header() -> None:
    """htu's origin comes from the configured resource, never from Host.

    Mirrors the TS sibling: an upstream that controls the Host /
    X-Forwarded-Proto headers must not be able to decide which htu the
    DPoP proof is validated against.
    """
    mock = _mock_verifier(resource="https://api.example.com/mcp")
    request = _make_request(
        host="attacker.example.com",
        headers={
            "DPoP": "p",
            "host": "attacker.example.com",
            "x-forwarded-proto": "http",
        },
    )
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("valid_token")

    ctx = mock.verify.await_args.kwargs["dpop_request"]
    assert ctx.url.startswith("https://api.example.com")
    assert "attacker" not in ctx.url


@pytest.mark.asyncio
async def test_htu_includes_request_path_and_query() -> None:
    """htu = origin + path + (?query) per RFC 9449 §4.2."""
    mock = _mock_verifier()
    request = _make_request(path="/mcp/tools", query="x=1&y=2", headers={"DPoP": "p"})
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("valid_token")

    assert (
        mock.verify.await_args.kwargs["dpop_request"].url
        == "https://api.example.com/mcp/tools?x=1&y=2"
    )


@pytest.mark.asyncio
async def test_htu_preserves_percent_encoded_path_from_raw_path() -> None:
    """htu uses ``scope['raw_path']`` so percent-encoding survives.

    ASGI populates ``scope['path']`` as the percent-decoded path, but the
    DPoP proof was signed over the on-wire (still-encoded) URL. The TS
    sibling reads ``IncomingMessage.url`` (raw bytes), so reading
    ``raw_path`` here keeps cross-SDK proof binding identical.
    """
    mock = _mock_verifier()
    # Decoded path: "/mcp/users/a/b" ; raw: "/mcp/users/a%2Fb" — a client
    # that signed the encoded form must bind against the encoded htu.
    raw_headers: list[tuple[bytes, bytes]] = [(b"dpop", b"p")]
    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/mcp/users/a/b",
        "raw_path": b"/mcp/users/a%2Fb",
        "query_string": b"",
        "headers": raw_headers,
        "scheme": "http",
        "server": ("testserver", 80),
        "client": None,
        "root_path": "",
        "http_version": "1.1",
    }
    request = Request(scope)
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("valid_token")

    assert (
        mock.verify.await_args.kwargs["dpop_request"].url
        == "https://api.example.com/mcp/users/a%2Fb"
    )


@pytest.mark.asyncio
async def test_htu_falls_back_to_decoded_path_when_raw_path_absent() -> None:
    """Servers that omit ``raw_path`` still get a sensible htu.

    Some ASGI servers (and synthetic test scopes) do not populate
    ``raw_path``. The helper must fall back to ``request.url.path``
    rather than blowing up — for the no-percent-encoding case the two
    are equal anyway.
    """
    mock = _mock_verifier()
    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "query_string": b"",
        "headers": [(b"dpop", b"p")],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": None,
        "root_path": "",
        "http_version": "1.1",
    }
    request = Request(scope)
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("valid_token")

    assert mock.verify.await_args.kwargs["dpop_request"].url == "https://api.example.com/mcp"


@pytest.mark.asyncio
async def test_no_http_request_context_falls_back_to_no_dpop() -> None:
    """Outside an HTTP request, the verifier still works (unit-test ergonomics).

    :func:`authplane_mcp.get_current_request` raises ``RuntimeError`` when
    called without an active request set by the middleware — the adapter
    must verify without a DPoP context rather than throw.
    """
    mock = _mock_verifier()
    verifier = _make_token_verifier(mock, request=None)

    result = await verifier.verify_token("valid_token")

    assert result is not None
    assert mock.verify.await_args.kwargs["dpop_request"] is None


# ---------------------------------------------------------------------------
# Per-request verify cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repeat_verify_token_collapses_onto_one_verify() -> None:
    """Two verify_token calls in one request → one underlying verify call.

    The cache is what protects DPoP-required mode from a
    DPoPReplayDetected error in case any future framework change starts
    invoking ``verify_token`` more than once per HTTP request.
    """
    mock = _mock_verifier()
    request = _make_request(headers={"DPoP": "p"})
    verifier = _make_token_verifier(mock, request)

    first = await verifier.verify_token("the_token")
    second = await verifier.verify_token("the_token")

    assert first is not None
    assert second is not None
    assert mock.verify.await_count == 1


@pytest.mark.asyncio
async def test_cache_is_scoped_per_request() -> None:
    """Distinct requests do not share the cache; replay protection survives."""
    mock = _mock_verifier()
    req_one = _make_request(headers={"DPoP": "p1"})
    req_two = _make_request(headers={"DPoP": "p2"})

    requests: list[Request] = [req_one, req_two]

    def pop_request() -> Request:
        return requests.pop(0)

    verifier = AuthplaneTokenVerifier(mock, get_http_request=pop_request)

    await verifier.verify_token("t")
    await verifier.verify_token("t")

    assert mock.verify.await_count == 2


@pytest.mark.asyncio
async def test_cache_keyed_by_token_not_by_request_slot() -> None:
    """Different tokens within one request get verified independently.

    A scenario that never arises on MCP's standard HTTP path
    (``BearerAuthBackend`` extracts one ``Authorization`` per request),
    but keying by token is cheap and removes a footgun the TS adapter
    technically carries (a different ``verify_token(otherToken)`` call
    inside one request would reuse the first call's result there).
    """
    mock = _mock_verifier()
    request = _make_request(headers={"DPoP": "p"})
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("token_a")
    await verifier.verify_token("token_b")

    assert mock.verify.await_count == 2


@pytest.mark.asyncio
async def test_cached_exception_reraises_typed_on_replay_within_request() -> None:
    """Acceptance: cached typed error re-raises on replay; not masked to None only the 2nd time.

    Both calls of ``verify_token`` map AuthplaneError → None, but the
    underlying cached task carries the typed exception unchanged so an
    operator awaiting the slot on ``request.state`` directly still
    sees the original DPoPReplayDetectedError. This is what keeps the
    failure diagnosable rather than collapsing to a generic 401 reason.
    """
    err = DPoPReplayDetectedError("DPoP proof jti has already been seen")
    mock = _mock_verifier(raise_exc=err)
    request = _make_request(headers={"DPoP": "p"})
    verifier = _make_token_verifier(mock, request)

    first = await verifier.verify_token("t")
    second = await verifier.verify_token("t")

    assert first is None
    assert second is None
    assert mock.verify.await_count == 1

    cache = get_or_create_verify_cache(request)
    cached_task = cache["t"]
    with pytest.raises(DPoPReplayDetectedError):
        await cached_task


@pytest.mark.asyncio
async def test_request_state_cache_stashes_task() -> None:
    """The cache slot is populated with an asyncio Task keyed by the access token."""
    import asyncio

    mock = _mock_verifier()
    request = _make_request(headers={"DPoP": "p"})
    verifier = _make_token_verifier(mock, request)

    await verifier.verify_token("t")

    cache = get_or_create_verify_cache(request)
    assert "t" in cache
    assert isinstance(cache["t"], asyncio.Task)


@pytest.mark.asyncio
async def test_no_request_context_means_no_cache_either() -> None:
    """Outside a request: each call hits verify(); nothing is cached anywhere."""
    mock = _mock_verifier()
    verifier = _make_token_verifier(mock, request=None)

    await verifier.verify_token("t")
    await verifier.verify_token("t")

    assert mock.verify.await_count == 2


# ---------------------------------------------------------------------------
# Constructor and request-lookup guards (mirrors fastmcp hardening)
# ---------------------------------------------------------------------------


def test_init_rejects_non_string_resource() -> None:
    """A mis-wired mock (no ``spec``) would silently corrupt htu reconstruction.

    ``urlsplit`` accepts a ``MagicMock`` without raising and produces a
    bogus ``_resource_origin`` like ``MagicMock://MagicMock`` — guard
    against this by failing fast in ``__init__``.
    """
    mock = AsyncMock(spec=AuthplaneResource)
    type(mock).resource = PropertyMock(return_value=object())  # not a str

    with pytest.raises(TypeError, match=r"verifier\.resource must be a str URI"):
        AuthplaneTokenVerifier(mock)


@pytest.mark.asyncio
async def test_unrelated_runtimeerror_from_get_http_request_propagates() -> None:
    """Only the documented 'No active HTTP request found.' is swallowed.

    A future change surfacing an unrelated ``RuntimeError`` from
    :func:`get_current_request` (ContextVar machinery breakage, etc.)
    must not be masked as ``dpop_request=None`` — that would silently
    re-introduce the no-proof-forwarded silent-pass this module fixed.
    """
    mock = _mock_verifier()

    def broken_get_http_request() -> Request:
        raise RuntimeError("ContextVar internal: scope not initialized")

    verifier = AuthplaneTokenVerifier(mock, get_http_request=broken_get_http_request)

    with pytest.raises(RuntimeError, match="scope not initialized"):
        await verifier.verify_token("t")
    assert mock.verify.await_count == 0
