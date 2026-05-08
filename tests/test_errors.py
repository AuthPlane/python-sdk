"""Tests for Authplane error hierarchy guarantees."""

import pytest

from authplane.errors import (
    AuthError,
    AuthplaneError,
    CircuitOpenError,
    ConsentRequiredError,
    DPoPBindingMismatchError,
    DPoPError,
    DPoPProofMissingError,
    DPoPReplayDetectedError,
    InsufficientScopeError,
    InvalidClientError,
    InvalidDPoPProofError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    ServerError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)


@pytest.mark.parametrize(
    ("error_type", "is_auth_error"),
    [
        (AuthError, True),
        (InvalidClientError, True),
        (UnauthorizedClientError, True),
        (InvalidScopeError, True),
        (InvalidGrantError, True),
        (UnsupportedGrantTypeError, True),
        (InvalidRequestError, True),
        (ServerError, True),
        (CircuitOpenError, True),
        (ConsentRequiredError, True),
        (InsufficientScopeError, False),
        (DPoPError, False),
        (DPoPProofMissingError, False),
        (InvalidDPoPProofError, False),
        (DPoPReplayDetectedError, False),
        (DPoPBindingMismatchError, False),
    ],
)
def test_error_hierarchy_contract(error_type: type[Exception], is_auth_error: bool) -> None:
    error = error_type("message")
    assert isinstance(error, AuthplaneError)
    assert issubclass(error_type, AuthplaneError)
    assert isinstance(error, AuthError) is is_auth_error


def test_auth_error_preserves_message_code_and_status() -> None:
    error = InvalidClientError("bad credentials", code="invalid_client", status_code=401)
    assert str(error) == "bad credentials"
    assert error.code == "invalid_client"
    assert error.status_code == 401


def test_consent_required_error_preserves_metadata() -> None:
    error = ConsentRequiredError(
        "consent required",
        service_id="calendar",
        cause_detail="missing_user_consent",
        consent_url="https://as.example.com/consent?service=calendar",
        code="consent_required",
        status_code=400,
    )
    assert str(error) == "consent required"
    assert error.code == "consent_required"
    assert error.status_code == 400
    assert error.service_id == "calendar"
    assert error.cause_detail == "missing_user_consent"
    assert error.consent_url == "https://as.example.com/consent?service=calendar"


def test_consent_required_error_describe_full() -> None:
    error = ConsentRequiredError(
        "consent required",
        service_id="calendar",
        cause_detail="missing_user_consent",
    )
    assert error.describe() == "consent required (calendar: missing_user_consent)"


def test_consent_required_error_describe_defaults_service_id() -> None:
    # An explicitly-empty service_id falls back to "unknown_service".
    error = ConsentRequiredError(
        "consent required",
        service_id="",
        cause_detail="missing_user_consent",
    )
    assert error.describe() == "consent required (unknown_service: missing_user_consent)"


def test_consent_required_error_describe_defaults_cause_detail_to_message() -> None:
    # cause_detail falls back to message when not provided. The constructor
    # already coerces empty cause_detail to message, so describe() repeats
    # the message as the cause.
    error = ConsentRequiredError("consent required", service_id="calendar")
    assert error.describe() == "consent required (calendar: consent required)"


def test_insufficient_scope_is_not_an_auth_error() -> None:
    error = InsufficientScopeError("scope missing")
    assert isinstance(error, AuthplaneError)
    assert not isinstance(error, AuthError)
    assert str(error) == "scope missing"
