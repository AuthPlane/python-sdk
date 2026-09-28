"""Tests for ASCredentials construction."""

import pytest

from authplane import ASCredentials


def test_credentials_accept_non_empty_fields() -> None:
    creds = ASCredentials(client_id="rs", client_secret="s3cret")
    assert creds.client_id == "rs"
    assert creds.client_secret == "s3cret"


def test_credentials_reject_empty_client_id() -> None:
    with pytest.raises(ValueError, match="client_id must not be empty"):
        ASCredentials(client_id="", client_secret="s3cret")


def test_credentials_reject_empty_client_secret() -> None:
    """An empty secret is a public client, which cannot introspect at all.

    Caught at construction rather than surfacing per request as a fail-open
    warning or, under fail_closed=True, as every token rejected.
    """
    with pytest.raises(ValueError, match="client_secret must not be empty"):
        ASCredentials(client_id="rs", client_secret="")
