"""Tests for URL elicitation translation in the FastMCP adapter.

Covers two surfaces:

* the :func:`to_url_elicitation_required_error` primitive (pure function);
* the client-wrapping integration (``authplane_auth`` returns a client whose
  ``exchange()`` auto-translates ``ConsentRequiredError`` into MCP ``-32042``
  before user tool code sees it).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from authplane.errors import AuthError, ConsentRequiredError
from authplane.oauth import TokenExchangeOptions
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp.types import URL_ELICITATION_REQUIRED

from authplane_fastmcp.auth import (
    _wrap_client_for_elicitation,  # pyright: ignore[reportPrivateUsage]
)
from authplane_fastmcp.url_elicitation import to_url_elicitation_required_error

_OPTIONS = TokenExchangeOptions(subject_token="test")

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

    mapped = to_url_elicitation_required_error(error)

    assert isinstance(mapped, UrlElicitationRequiredError)
    assert mapped.error.code == URL_ELICITATION_REQUIRED
    assert mapped.error.message == "user must grant access"
    assert mapped.error.data is not None
    elicitations = mapped.error.data["elicitations"]
    assert elicitations[0]["url"] == "https://as.example.com/consent?service=calendar"
    assert elicitations[0]["mode"] == "url"
    # describe() output is the canonical elicitation message — pin the format.
    assert elicitations[0]["message"] == "user must grant access (calendar: missing_user_consent)"


def test_returns_none_for_non_consent_error() -> None:
    assert (
        to_url_elicitation_required_error(
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
    assert to_url_elicitation_required_error(error) is None


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
