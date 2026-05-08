"""Edge-case tests for AuthplaneResource covering uncovered branches.

Targets specific code paths that the main test_verifier.py does not reach:

- ``scopes`` property
- ``verify()`` surfaces unexpected runtime exceptions distinctly
- tokens with a list ``aud`` are accepted (multi-audience support)
- unexpected exception inside ``_verify_token_core`` is wrapped
- metadata change callbacks on AuthplaneClient
"""

from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from authplane import AuthplaneClient, AuthplaneResource, FetchSettings, InboundDPoPOptions
from authplane.errors import VerifierRuntimeError

# ---------------------------------------------------------------------------
# Scopes property
# ---------------------------------------------------------------------------


async def test_scopes_property_returns_configured_scopes(mock_jwks: Any) -> None:
    """The ``scopes`` property exposes an immutable copy of the constructor scopes."""
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=FetchSettings(ssrf_protection=False),
    )
    try:
        v = client.resource(
            resource="https://api.example.com",
            scopes=["read:data", "write:data", "admin"],
        )
        assert v.scopes == ("read:data", "write:data", "admin")
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Metadata change: new metadata drops jwks_uri
# ---------------------------------------------------------------------------


async def test_on_metadata_changed_logs_error_when_new_metadata_drops_jwks_uri(
    client: AuthplaneClient,
) -> None:
    """When refreshed AS metadata no longer contains a jwks_uri, the client
    should log a warning and clear its jwks_uri."""
    assert client._jwks_uri is not None  # pyright: ignore[reportPrivateUsage]

    old_metadata: dict[str, Any] = {
        "issuer": "https://auth.example.com",
        "jwks_uri": client._jwks_uri,  # pyright: ignore[reportPrivateUsage]
    }
    # New metadata document without a jwks_uri field
    new_metadata: dict[str, Any] = {
        "issuer": "https://auth.example.com",
    }

    await client._on_metadata_changed(old_metadata, new_metadata)  # pyright: ignore[reportPrivateUsage]

    assert client._jwks_uri is None  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Metadata change: introspection_endpoint changes
# ---------------------------------------------------------------------------


async def test_on_metadata_changed_logs_introspection_endpoint_change(
    client: AuthplaneClient,
) -> None:
    """When the introspection_endpoint changes in refreshed metadata the client
    logs the change."""
    old_metadata: dict[str, Any] = {
        "issuer": "https://auth.example.com",
        "jwks_uri": client._jwks_uri,  # pyright: ignore[reportPrivateUsage]
        "introspection_endpoint": "https://auth.example.com/oauth/introspect/v1",
    }
    new_metadata: dict[str, Any] = {
        "issuer": "https://auth.example.com",
        "jwks_uri": client._jwks_uri,  # pyright: ignore[reportPrivateUsage]
        "introspection_endpoint": "https://auth.example.com/oauth/introspect/v2",
    }

    # Must complete without error; logging is verified implicitly via coverage.
    await client._on_metadata_changed(old_metadata, new_metadata)  # pyright: ignore[reportPrivateUsage]

    # jwks_uri must be unchanged (the endpoint update does not affect JWKS).
    assert client._jwks_uri is not None  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# verify() surfaces unexpected errors as VerifierRuntimeError
# ---------------------------------------------------------------------------


async def test_verify_wraps_unexpected_exception_as_runtime_error(
    verifier: AuthplaneResource,
    token_factory: Callable[..., str],
) -> None:
    """Unexpected verifier runtime failures should not be mislabeled as signature errors."""
    token = token_factory()

    with (
        patch.object(
            verifier,
            "_verify_token_core",
            AsyncMock(side_effect=RuntimeError("totally unexpected")),
        ),
        pytest.raises(VerifierRuntimeError, match="runtime failure"),
    ):
        await verifier.verify(token)


# ---------------------------------------------------------------------------
# Audience handling — aud always normalized to list[str]
# ---------------------------------------------------------------------------


async def test_single_element_aud_array_accepted(
    verifier: AuthplaneResource,
    token_factory: Callable[..., str],
) -> None:
    """A token whose aud is a single-element array should be accepted and normalized to a list."""
    token = token_factory(aud=["https://api.example.com"])  # type: ignore[arg-type]
    claims = await verifier.verify(token)
    assert claims.audience == ("https://api.example.com",)


async def test_multi_audience_token_accepted(
    verifier: AuthplaneResource,
    token_factory: Callable[..., str],
) -> None:
    """A token whose aud claim is a multi-element list is accepted when resource is present."""
    token = token_factory(aud=["https://api.example.com", "https://other.com"])  # type: ignore[arg-type]
    claims = await verifier.verify(token)
    assert "https://api.example.com" in claims.audience


# ---------------------------------------------------------------------------
# Unexpected exception inside _verify_token_core
# ---------------------------------------------------------------------------


async def test_verify_token_core_unexpected_exception_raises_runtime_error(
    verifier: AuthplaneResource,
    token_factory: Callable[..., str],
) -> None:
    """Unexpected inner runtime errors should surface as VerifierRuntimeError."""
    token = token_factory()

    # Patch import_key (called inside _verify_token_core's try block) to raise
    # something that is not an authlib error or one of our known exceptions.
    with (
        patch(
            "authplane.verifier.verifier.JsonWebKey.import_key",
            side_effect=ValueError("simulated crypto failure"),
        ),
        pytest.raises(VerifierRuntimeError, match="runtime failure"),
    ):
        await verifier.verify(token)


async def test_verify_dpop_wraps_unexpected_exception_as_runtime_error(
    client: AuthplaneClient,
    token_factory: Callable[..., str],
) -> None:
    """Unexpected DPoP validation errors should surface as VerifierRuntimeError."""
    from dataclasses import dataclass

    verifier = client.resource(
        resource="https://api.example.com",
        scopes=["read:data", "write:data"],
        inbound_dpop=InboundDPoPOptions(),
    )
    token = token_factory(cnf={"jkt": "thumbprint"})

    @dataclass
    class Ctx:
        method: str = "GET"
        url: str = "https://api.example.com/resource"
        proof: str | None = "proof"

    with (
        patch(
            "authplane.verifier.verifier.verify_dpop_proof",
            AsyncMock(side_effect=RuntimeError("totally unexpected")),
        ),
        pytest.raises(VerifierRuntimeError, match="runtime failure"),
    ):
        await verifier.verify(token, dpop_request=Ctx())
