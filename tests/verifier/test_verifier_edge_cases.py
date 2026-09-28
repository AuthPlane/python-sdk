"""Edge-case tests for AuthplaneResource covering uncovered branches.

Targets specific code paths that the main test_verifier.py does not reach:

- ``scopes`` property
- ``verify()`` surfaces unexpected runtime exceptions distinctly
- tokens with a list ``aud`` are accepted (multi-audience support)
- unexpected exception inside ``_verify_token_core`` is wrapped
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
