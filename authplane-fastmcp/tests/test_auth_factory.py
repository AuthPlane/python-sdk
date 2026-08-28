"""Unit tests for authplane_auth factory function."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from authplane import (
    DPoPProvider,
    FetchSettings,
    IntrospectionRevocation,
    VerifiedClaims,
)
from pydantic import AnyHttpUrl

from authplane_fastmcp import AuthplaneTokenVerifier, authplane_auth
from authplane_fastmcp.auth import (
    AuthplaneAuthResult,
    VerbatimPRMRemoteAuthProvider,
    _derive_resource_url,
)

# Below both first-party imports, so the isort group stays contiguous — ruff only
# sorts contiguous blocks, so a TYPE_CHECKING block wedged between them splits
# the group without I001 firing. Type-only: pytest runs this package with
# --import-mode=importlib and never executes it, while pyright resolves it
# through `extraPaths: ["tests"]`.
if TYPE_CHECKING:
    from conftest import TokenVerifierFactory


@pytest.mark.asyncio
async def test_authplane_auth_parameter_propagation():
    """Verify that parameters are split correctly between client and verifier."""
    custom_fetch_settings = FetchSettings(ssrf_protection=False, allow_http=True, timeout=30.0)
    dpop_provider = MagicMock(spec=DPoPProvider)

    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            scopes=["read"],
            dpop=dpop_provider,
            allowed_algorithms=["RS256"],
            jwks_refresh_seconds=600,
            metadata_refresh_seconds=7200,
            cache_ttl_buffer_seconds=15.0,
            default_ttl_seconds=900.0,
            cache_max_entries=500,
            circuit_breaker_threshold=7,
            circuit_breaker_cooldown_seconds=45.0,
            clock_skew_seconds=60,
            dev_mode=True,
            fetch_settings=custom_fetch_settings,
        )

        # Client-level params
        mock_client_cls.create.assert_called_once()
        client_kwargs = mock_client_cls.create.call_args.kwargs
        assert client_kwargs["issuer"] == "https://auth.example.com"
        assert client_kwargs["dpop"] is dpop_provider
        assert client_kwargs["dev_mode"] is True
        assert client_kwargs["jwks_refresh_seconds"] == 600
        assert client_kwargs["metadata_refresh_seconds"] == 7200
        assert client_kwargs["cache_ttl_buffer_seconds"] == 15.0
        assert client_kwargs["default_ttl_seconds"] == 900.0
        assert client_kwargs["cache_max_entries"] == 500
        assert client_kwargs["circuit_breaker_threshold"] == 7
        assert client_kwargs["circuit_breaker_cooldown_seconds"] == 45.0
        assert client_kwargs["fetch_settings"] is custom_fetch_settings

        # Verifier-level params
        mock_client.resource.assert_called_once()
        verifier_kwargs = mock_client.resource.call_args
        assert verifier_kwargs.kwargs["allowed_algorithms"] == ["RS256"]
        assert verifier_kwargs.kwargs["clock_skew_seconds"] == 60
        assert verifier_kwargs.kwargs["resource"] == "https://api.example.com/mcp"  # resource
        assert verifier_kwargs.kwargs["scopes"] == ["read"]


@pytest.mark.asyncio
async def test_authplane_auth_none_filtering():
    """Verify that None values are NOT passed to AuthplaneClient.create or client.resource."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        mock_client_cls.create.assert_called_once()
        client_kwargs = mock_client_cls.create.call_args.kwargs
        # Standard params should be there
        assert "issuer" in client_kwargs

        # Optional params NOT specified should NOT be in kwargs (so SDK can use defaults)
        assert "dpop" not in client_kwargs
        assert "dev_mode" not in client_kwargs
        assert "fetch_settings" not in client_kwargs
        assert "metadata_refresh_seconds" not in client_kwargs
        assert "cache_ttl_buffer_seconds" not in client_kwargs
        assert "default_ttl_seconds" not in client_kwargs
        assert "cache_max_entries" not in client_kwargs
        assert "circuit_breaker_threshold" not in client_kwargs
        assert "circuit_breaker_cooldown_seconds" not in client_kwargs

        # Verifier-level optional params should also be filtered
        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert "clock_skew_seconds" not in verifier_kwargs
        assert "allowed_algorithms" not in verifier_kwargs


@pytest.mark.asyncio
async def test_authplane_auth_revocation_checker_default_is_none():
    """When revocation_checker is not passed, None is forwarded (no revocation checking)."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        # Default is None -> no revocation checking (offline validation only)
        assert verifier_kwargs["revocation_checker"] is None


@pytest.mark.asyncio
async def test_authplane_auth_revocation_checker_custom_callable():
    """A custom async revocation_checker is forwarded to client.resource()."""

    async def my_checker(claims: VerifiedClaims, raw_token: str) -> bool:
        return False

    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            revocation_checker=my_checker,
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert verifier_kwargs["revocation_checker"] is my_checker


@pytest.mark.asyncio
async def test_authplane_auth_fail_closed_default_is_false():
    """When fail_closed is not passed, False is forwarded (fail-open behavior)."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert verifier_kwargs["fail_closed"] is False


@pytest.mark.asyncio
async def test_authplane_auth_fail_closed_forwarded():
    """fail_closed=True is forwarded to client.resource()."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            revocation_checker=IntrospectionRevocation(),
            fail_closed=True,
        )

        verifier_kwargs = mock_client.resource.call_args.kwargs
        assert verifier_kwargs["fail_closed"] is True


@pytest.mark.asyncio
async def test_authplane_auth_resource_derivation():
    """Verify resource URL construction from base_url and mcp_path."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        # Case 1: Trailing slash on base_url, leading slash on mcp_path
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com/",
            mcp_path="/mcp",
        )
        assert mock_client.resource.call_args.kwargs["resource"] == "https://api.example.com/mcp"

        # Case 2: No trailing slash, leading slash
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            mcp_path="/mcp",
        )
        assert mock_client.resource.call_args.kwargs["resource"] == "https://api.example.com/mcp"

        # Case 3: Custom mcp_path
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            mcp_path="api/v1/mcp",
        )
        assert (
            mock_client.resource.call_args.kwargs["resource"]
            == "https://api.example.com/api/v1/mcp"
        )


def _provider_for(
    base_url: str, mcp_path: str, *, make_verifier: TokenVerifierFactory
) -> VerbatimPRMRemoteAuthProvider:
    """A provider built as :func:`authplane_auth` builds it, for this mount.

    Every collaborator is the production one. ``token_verifier`` in particular:
    a bare ``MagicMock`` would satisfy the constructor, but it is the argument
    ``auth.py``'s own comment says the PRM generation can read
    (``token_verifier.base_url``), and upstream's ``__init__`` already reads
    ``token_verifier.required_scopes`` off it. A mock there means the object
    under test is not the object production builds, and the two coercion paths
    production uses — a raw ``str`` ``base_url`` into the verifier, an
    ``AnyHttpUrl`` into the provider — collapse into one.

    ``verbatim_resource`` follows the parameters rather than being hardcoded.
    Nothing here calls ``get_routes``, so it is inert either way, but it is the
    field a reader will assume the derivation comparison involves.
    """
    resource = _derive_resource_url(base_url, mcp_path)
    return VerbatimPRMRemoteAuthProvider(
        token_verifier=make_verifier(base_url, resource),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
        base_url=AnyHttpUrl(base_url),
        scopes_supported=[],
        verbatim_issuer="https://auth.example.com",
        verbatim_resource=resource,
    )


def _upstream_resource_url(provider: VerbatimPRMRemoteAuthProvider, mcp_path: str) -> str:
    """Upstream's own derivation for ``mcp_path``, or a legible failure.

    Reaching for a private symbol across an unpinned ``fastmcp>=3.2,<4`` range
    is deliberate — a ``skip`` here would silently unpin the claim, so its
    removal has to be red. What this adds is that the redness explains itself:
    without the guard the removal lands as a bare ``AttributeError`` on every
    parametrization, on whatever unrelated PR happens to run next, and in
    ``release.yml``'s pre-publish suite.
    """
    derive = getattr(provider, "_get_resource_url", None)
    if derive is None:
        pytest.fail(
            "fastmcp no longer exposes RemoteAuthProvider._get_resource_url; re-pin "
            "_derive_resource_url against whatever now derives the advertised PRM resource"
        )
    return str(derive(mcp_path))


@pytest.mark.parametrize(
    ("base_url", "mcp_path"),
    [
        ("https://api.example.com", "/mcp"),
        ("https://api.example.com/", "/mcp"),
        ("https://api.example.com", "mcp"),
        ("https://api.example.com", "api/v1/mcp"),
        ("https://api.example.com", "/mcp/"),
        ("https://api.example.com/base", "/mcp"),
        ("https://api.example.com/base", "api/v1/mcp"),
        # Root mount: the input neither this SDK nor the TS sibling pinned.
        ("https://api.example.com", "/"),
        ("https://api.example.com/", "/"),
        ("https://api.example.com/base", "/"),
    ],
)
def test_derive_resource_url_matches_fastmcp(
    base_url: str, mcp_path: str, token_verifier_factory: TokenVerifierFactory
) -> None:
    """Our derivation reproduces FastMCP's own ``_get_resource_url``.

    ``_derive_resource_url``'s docstring claims the identifier we advertise as
    the JWT audience equals the one ``RemoteAuthProvider`` derives from the
    mount. Nothing pinned that claim: the PRM integration tests cannot witness a
    divergence, because ``rewrite_prm_routes_verbatim`` overwrites the served
    ``resource`` with our string before anything reads it. This compares the two
    derivations head-on, so a change on either side is what fails.

    **What the parameters cover, and what they do not.** Every input below
    varies slash placement, and slash placement is the one axis on which the
    two derivations are the same kind of operation. They differ in kind
    elsewhere: ours concatenates strings, upstream re-parses the join through
    ``AnyHttpUrl``. Each normalization that constructor applies is a divergence
    class no amount of slash shuffling can reach, and they are enumerated —
    with the inputs that provoke them — by
    ``test_derive_resource_url_diverges_from_fastmcp_on_url_normalization``.
    Read the two together: this one says where we agree, that one says where we
    do not.

    Reaching for upstream's private ``_get_resource_url`` is the point: it is
    the function whose output must match ours, and a rename or a rewrite there
    should break this loudly instead of silently unpinning the claim.
    """
    provider = _provider_for(base_url, mcp_path, make_verifier=token_verifier_factory)
    assert _derive_resource_url(base_url, mcp_path) == _upstream_resource_url(provider, mcp_path)


@pytest.mark.parametrize(
    ("base_url", "mcp_path", "ours", "upstream"),
    [
        # Host case: the URL parser behind ``AnyHttpUrl`` lowercases the
        # authority; string concatenation preserves whatever was configured.
        (
            "https://API.example.com",
            "/mcp",
            "https://API.example.com/mcp",
            "https://api.example.com/mcp",
        ),
        # An explicitly written default port is dropped for the scheme.
        (
            "https://api.example.com:443",
            "/mcp",
            "https://api.example.com:443/mcp",
            "https://api.example.com/mcp",
        ),
        # Dot segments are collapsed. This is the one that moves the *path*.
        (
            "https://api.example.com",
            "/a/./mcp",
            "https://api.example.com/a/./mcp",
            "https://api.example.com/a/mcp",
        ),
        # Characters illegal in a path are percent-encoded.
        (
            "https://api.example.com",
            "/mcp path",
            "https://api.example.com/mcp path",
            "https://api.example.com/mcp%20path",
        ),
    ],
)
def test_derive_resource_url_diverges_from_fastmcp_on_url_normalization(
    base_url: str,
    mcp_path: str,
    ours: str,
    upstream: str,
    token_verifier_factory: TokenVerifierFactory,
) -> None:
    """The divergence classes that follow from re-parsing versus concatenating.

    ``_prm.py:68-71`` already names them — "host case, an explicit default
    port, a doubled slash, a dot segment" — as the reason the verbatim rewrite
    cannot gate on the served value. They apply here for the same reason: only
    upstream's side goes through ``AnyHttpUrl``. Pinned as divergences rather
    than reconciled, on the same grounds as the empty-mount-path case below —
    matching upstream would mean a second, hand-written copy of that
    constructor's normalization, which is the duplication
    :func:`_derive_resource_url` exists to avoid.

    The doubled slash from that list is *not* here: it is the one entry that
    agrees, because ``lstrip("/")`` and upstream's own ``lstrip("/")`` remove
    it on both sides before either joins.

    The rows that *move the path* have consequences beyond a mismatched audience
    string: the dot segment and the percent-encoded space, by the same
    mechanism. ``rewrite_prm_routes_verbatim`` selects routes by comparing
    ``urlsplit(resource).path`` against ``route.path`` (``_prm.py:148``), so
    when upstream registers the route under its own normalization — ``/a/mcp``
    for ``/a/./mcp``, ``/mcp%20path`` for ``/mcp path``, both asserted in the
    parameters above — our target misses it and the wrap silently does not
    happen. ``_prm.py:181-190`` emits a ``RuntimeWarning``, which is the only
    signal. See
    ``test_integration.py::test_upstream_registers_the_route_our_rewrite_targets``
    for the registered paths this is measured against.

    Host case and the explicit ``:443`` genuinely are inert: neither moves the
    path, and our audience stays self-consistent between the verifier and the
    served document.
    """
    provider = _provider_for(base_url, mcp_path, make_verifier=token_verifier_factory)

    assert _derive_resource_url(base_url, mcp_path) == ours
    assert _upstream_resource_url(provider, mcp_path) == upstream
    assert ours != upstream


def test_derive_resource_url_diverges_from_fastmcp_on_an_empty_mount_path(
    token_verifier_factory: TokenVerifierFactory,
) -> None:
    """The single input where the two derivations disagree, pinned deliberately.

    FastMCP short-circuits a falsy path and returns the base URL untouched
    (``if path:``); we always join. The two still agree when the authority has
    no path of its own, because ``AnyHttpUrl`` normalises ``https://host`` to
    ``https://host/`` — so provoking the difference needs both an empty
    ``mcp_path`` and a ``base_url`` that carries a path.

    Documented rather than reconciled: ``mcp_path`` defaults to ``"/mcp"`` and
    an empty string is not a mount path, while matching upstream here would mean
    reimplementing ``AnyHttpUrl`` normalisation — a second copy of an expression
    that agrees only by inspection, which is what this helper exists to avoid.
    """
    base_url = "https://api.example.com/base"
    provider = _provider_for(base_url, "", make_verifier=token_verifier_factory)

    assert _derive_resource_url(base_url, "") == "https://api.example.com/base/"
    assert _upstream_resource_url(provider, "") == "https://api.example.com/base"


@pytest.mark.asyncio
async def test_authplane_auth_as_credentials_passthrough():
    """as_credentials is forwarded to AuthplaneClient.create as auth."""
    from authplane import ASCredentials

    creds = ASCredentials(client_id="client_id", client_secret="secret")
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
            as_credentials=creds,
        )

        client_kwargs = mock_client_cls.create.call_args.kwargs
        assert client_kwargs["auth"] is creds


@pytest.mark.asyncio
async def test_authplane_auth_returns_auth_result():
    """authplane_auth() returns an AuthplaneAuthResult with auth, token_verifier, and client."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with (
        patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls,
        patch("authplane_fastmcp.auth.VerbatimPRMRemoteAuthProvider") as mock_auth_cls,
    ):
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        result = await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )

        assert isinstance(result, AuthplaneAuthResult)
        assert result.auth is mock_auth_cls.return_value
        assert result.token_verifier is not None
        assert result.client is mock_client

        # Pin the verbatim keywords the factory forwards to the provider. The
        # resource is base_url + mcp_path ("/mcp" by default), NOT base_url —
        # asserting the exact value guards against a regression that passes
        # base_url (or any wrong kwarg) as the verbatim resource/issuer.
        provider_kwargs = mock_auth_cls.call_args.kwargs
        assert provider_kwargs["verbatim_issuer"] == "https://auth.example.com"
        assert provider_kwargs["verbatim_resource"] == "https://api.example.com/mcp"


def test_authplane_auth_result_keys():
    """AuthplaneAuthResult.keys() returns only 'auth'."""
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=MagicMock())
    assert result.keys() == ["auth"]


def test_authplane_auth_result_getitem_auth():
    """AuthplaneAuthResult['auth'] returns the auth provider."""
    mock_auth = AsyncMock()
    result = AuthplaneAuthResult(auth=mock_auth, token_verifier=AsyncMock(), client=MagicMock())
    assert result["auth"] is mock_auth


def test_authplane_auth_result_getitem_unknown_raises():
    """AuthplaneAuthResult[unknown_key] raises KeyError."""
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=MagicMock())
    with pytest.raises(KeyError):
        _ = result["unknown"]


def test_authplane_auth_result_iter():
    """Iterating AuthplaneAuthResult yields only 'auth'."""
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=MagicMock())
    assert list(result) == ["auth"]


def test_authplane_auth_result_unpack():
    """AuthplaneAuthResult supports ** unpacking with only the 'auth' key."""
    mock_auth = AsyncMock()
    result = AuthplaneAuthResult(auth=mock_auth, token_verifier=AsyncMock(), client=MagicMock())
    unpacked = {**result}
    assert unpacked == {"auth": mock_auth}


# ---------------------------------------------------------------------------
# aclose lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_auth_result_aclose_delegates_to_client():
    """aclose() calls client.aclose() to release resources."""
    mock_client = AsyncMock()
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=mock_client)
    await result.aclose()
    mock_client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_authplane_auth_result_aclose_idempotent():
    """aclose() can be called multiple times without error."""
    mock_client = AsyncMock()
    result = AuthplaneAuthResult(auth=AsyncMock(), token_verifier=AsyncMock(), client=mock_client)
    await result.aclose()
    await result.aclose()
    assert mock_client.aclose.await_count == 2


# ---------------------------------------------------------------------------
# Resource URL alignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authplane_auth_resource_matches_default_mcp_path():
    """Resource passed to verifier must equal base_url + default mcp_path (/mcp)."""
    mock_client = MagicMock()
    _mock_resource = MagicMock()
    _mock_resource.resource = "https://api.example.com/mcp"
    mock_client.resource = MagicMock(return_value=_mock_resource)

    with patch("authplane_fastmcp.auth.AuthplaneClient") as mock_client_cls:
        mock_client_cls.create = AsyncMock(return_value=mock_client)
        await authplane_auth(
            issuer="https://auth.example.com",
            base_url="https://api.example.com",
        )
        resource = mock_client.resource.call_args.kwargs["resource"]
        assert resource == "https://api.example.com/mcp"


# ---------------------------------------------------------------------------
# Non-AuthplaneError propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_token_non_authplane_error_propagates():
    """Unexpected exceptions from AuthplaneResource.verify() propagate (HTTP 500)."""

    mock_verifier = AsyncMock()
    mock_verifier.resource = "https://api.example.com/mcp"
    mock_verifier.verify.side_effect = RuntimeError("unexpected")

    tv = AuthplaneTokenVerifier(mock_verifier)
    with pytest.raises(RuntimeError, match="unexpected"):
        await tv.verify_token("some_token")


def test_public_names_are_importable_from_the_package_root() -> None:
    # Both were made public in this change so a user who hand-rolls a
    # RemoteAuthProvider does not silently lose the verbatim PRM. Nothing else
    # imports them from the root — conftest reaches into .auth — so without this
    # the __all__ entries could rot without a test noticing.
    import authplane_fastmcp

    assert "VerbatimPRMRemoteAuthProvider" in authplane_fastmcp.__all__
    assert "rewrite_prm_routes_verbatim" in authplane_fastmcp.__all__
    assert authplane_fastmcp.VerbatimPRMRemoteAuthProvider is not None
    assert authplane_fastmcp.rewrite_prm_routes_verbatim is not None
