"""Tests for URL elicitation translation in the MCP adapter.

Covers two surfaces:

* the :func:`to_url_elicitation_required_error` primitive (pure function);
* the client-wrapping integration (``authplane_mcp_auth`` returns a client
  whose ``exchange()`` auto-translates ``ConsentRequiredError`` into MCP
  ``-32042`` before user tool code sees it).
"""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from authplane.errors import AuthError, ConsentRequiredError
from authplane.oauth import TokenExchangeOptions
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp.types import URL_ELICITATION_REQUIRED, ElicitRequestURLParams
from pydantic import BaseModel

import authplane_mcp.url_elicitation as url_elicitation
from authplane_mcp.auth import _wrap_client_for_elicitation  # pyright: ignore[reportPrivateUsage]

_OPTIONS = TokenExchangeOptions(subject_token="test")

# ---------------------------------------------------------------------------
# Wire contract
# ---------------------------------------------------------------------------


def test_elicitation_id_wire_key_is_camelcase_under_installed_mcp() -> None:
    # README-pinned contract: the mcp 1.x line serializes the elicitation-id
    # field as camelCase ``elicitationId``. If a future 1.x release renames it,
    # this fails with a real diff instead of masking the drift at collection
    # time (as a dynamic probe would).
    params = ElicitRequestURLParams(
        mode="url", url="https://example.test", elicitationId="probe", message="m"
    )
    assert "elicitationId" in params.model_dump(by_alias=True)


# ---------------------------------------------------------------------------
# Primitive: to_url_elicitation_required_error
# ---------------------------------------------------------------------------


def test_returns_url_elicitation_for_consent_with_url() -> None:
    error = ConsentRequiredError(
        "user must grant access",
        service_id="calendar",
        cause_detail="missing_user_consent",
        consent_url="https://as.example.com/consent?service=calendar",
        code="consent_required",
        status_code=400,
    )

    mapped = url_elicitation.to_url_elicitation_required_error(error)

    assert isinstance(mapped, UrlElicitationRequiredError)
    assert mapped.error.code == URL_ELICITATION_REQUIRED
    assert mapped.error.message == "user must grant access"
    assert mapped.error.data is not None
    elicitations = mapped.error.data["elicitations"]
    assert elicitations[0]["url"] == "https://as.example.com/consent?service=calendar"
    assert elicitations[0]["mode"] == "url"
    # describe() output is the canonical elicitation message — pin the format.
    assert elicitations[0]["message"] == "user must grant access (calendar: missing_user_consent)"
    # The adapter must populate a fresh UUID under the camelCase
    # ``elicitationId`` wire field the pinned mcp 1.x line uses.
    UUID(elicitations[0]["elicitationId"])
    # ...and the dict must round-trip back into a schema-valid model, proving the
    # consent-driven path yields a genuine ``ElicitRequestURLParams``.
    rebuilt = ElicitRequestURLParams.model_validate(elicitations[0])
    assert rebuilt.url == "https://as.example.com/consent?service=calendar"
    assert rebuilt.mode == "url"


def test_returns_none_for_non_consent_error() -> None:
    assert (
        url_elicitation.to_url_elicitation_required_error(
            AuthError("bad request", code="invalid_request", status_code=400)
        )
        is None
    )


def test_returns_none_for_consent_without_url() -> None:
    error = ConsentRequiredError(
        "consent required",
        service_id="calendar",
        cause_detail="missing_user_consent",
        consent_url=None,
    )
    assert url_elicitation.to_url_elicitation_required_error(error) is None


# ---------------------------------------------------------------------------
# Field-rename resilience (the argument for the `<2` ceiling)
# ---------------------------------------------------------------------------


class _StubRenamedElicit(BaseModel):
    """Stand-in for a hypothetical mcp release that renamed the elicitation-id
    field to snake_case ``elicitation_id`` (as mcp 2.0 does)."""

    mode: str
    url: str
    message: str
    elicitation_id: str  # required, snake_case


def test_schema_lookup_picks_snake_case_after_rename() -> None:
    # The positive schema lookup resolves the constructor kwarg from the model
    # itself, so a rename to ``elicitation_id`` is picked up rather than the
    # camelCase kwarg silently landing in ``__pydantic_extra__``.
    assert (
        url_elicitation._resolve_elicitation_id_kwarg(  # pyright: ignore[reportPrivateUsage]
            _StubRenamedElicit
        )
        == "elicitation_id"
    )


class _NoElicitId(BaseModel):
    """A model exposing neither known elicitation-id spelling."""

    mode: str
    url: str
    message: str


def test_resolver_raises_when_no_known_spelling() -> None:
    # With ``extra="allow"``, returning a default kwarg for a model that declares
    # neither spelling would land it silently in ``__pydantic_extra__`` (a -32042
    # with no id). The resolver must instead raise, naming the unrecognized model.
    with pytest.raises(ImportError, match="cannot resolve the elicitation-id field"):
        url_elicitation._resolve_elicitation_id_kwarg(  # pyright: ignore[reportPrivateUsage]
            _NoElicitId
        )


def test_import_raises_when_model_lacks_known_spelling(monkeypatch: pytest.MonkeyPatch) -> None:
    # The import-time resolution is the fail-fast: if the installed mcp exposes
    # neither spelling, importing the module must raise (not defer a silent
    # -32042). Patch the source model on ``mcp.types`` and reload the module.
    import importlib

    import mcp.types

    monkeypatch.setattr(mcp.types, "ElicitRequestURLParams", _NoElicitId)
    try:
        with pytest.raises(ImportError, match="cannot resolve the elicitation-id field"):
            importlib.reload(url_elicitation)
    finally:
        # Restore the real model and reload so the module (and its functools.cache) is
        # left in a good state for the remaining tests. ``importlib.reload`` re-executes
        # into the *same* module ``__dict__``, so this rebinds the module-level state
        # left stale by the failed reload and the integration tests below resolve correctly.
        monkeypatch.undo()
        importlib.reload(url_elicitation)


def test_rename_path_still_yields_minus_32042_with_id(monkeypatch: pytest.MonkeyPatch) -> None:
    # With the elicitation model renamed, the consent path must still produce a
    # -32042 whose elicitation carries a populated id under the new field name —
    # not a silent failure with a missing id. Patch ONLY the model: resolution is
    # lazy, so `_build_url_elicitation_params` re-resolves the kwarg from the
    # patched model. This exercises the resolve→build wiring end to end, rather
    # than short-circuiting it by patching the resolved module state.
    monkeypatch.setattr(url_elicitation, "ElicitRequestURLParams", _StubRenamedElicit)

    error = ConsentRequiredError(
        "user must grant access",
        service_id="calendar",
        cause_detail="missing_user_consent",
        consent_url="https://as.example.com/consent?service=calendar",
        code="consent_required",
        status_code=400,
    )

    mapped = url_elicitation.to_url_elicitation_required_error(error)

    assert isinstance(mapped, UrlElicitationRequiredError)
    assert mapped.error.code == URL_ELICITATION_REQUIRED
    assert mapped.error.data is not None
    elicitation = mapped.error.data["elicitations"][0]
    # The id is populated under the renamed snake_case field, not dropped.
    UUID(elicitation["elicitation_id"])


# ---------------------------------------------------------------------------
# Client-wrapping integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wrapped_client_translates_consent_to_url_elicitation() -> None:
    consent = ConsentRequiredError(
        "user interaction required",
        service_id="profile",
        cause_detail="interaction_required",
        consent_url="https://as.example.com/consent?service=profile",
        code="interaction_required",
        status_code=400,
    )

    client = AsyncMock()
    client.exchange = AsyncMock(side_effect=consent)

    wrapped = _wrap_client_for_elicitation(client)

    with pytest.raises(UrlElicitationRequiredError) as exc:
        await wrapped.exchange(_OPTIONS)
    assert exc.value.error.code == URL_ELICITATION_REQUIRED


@pytest.mark.asyncio
async def test_wrapped_client_passes_through_non_consent_errors() -> None:
    non_consent = AuthError("bad grant", code="invalid_grant", status_code=400)

    client = AsyncMock()
    client.exchange = AsyncMock(side_effect=non_consent)

    wrapped = _wrap_client_for_elicitation(client)

    with pytest.raises(AuthError, match="bad grant"):
        await wrapped.exchange(_OPTIONS)


@pytest.mark.asyncio
async def test_wrapped_client_passes_through_consent_without_url() -> None:
    # Consent errors without a consent_url cannot be turned into an
    # elicitation request, so they flow through unchanged.
    consent_no_url = ConsentRequiredError(
        "consent required",
        service_id="profile",
        cause_detail="interaction_required",
        consent_url=None,
    )

    client = AsyncMock()
    client.exchange = AsyncMock(side_effect=consent_no_url)

    wrapped = _wrap_client_for_elicitation(client)

    with pytest.raises(ConsentRequiredError, match="consent required"):
        await wrapped.exchange(_OPTIONS)


@pytest.mark.asyncio
async def test_wrapped_client_returns_value_unchanged_on_success() -> None:
    client = AsyncMock()
    client.exchange = AsyncMock(return_value="ok")

    wrapped = _wrap_client_for_elicitation(client)

    assert await wrapped.exchange(_OPTIONS) == "ok"
