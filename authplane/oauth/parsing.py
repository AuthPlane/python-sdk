"""Shared parsing helpers for OAuth protocol responses."""

from typing import Any, cast

from ..errors import ProtocolError
from .types import TOKEN_TYPE_ACCESS_TOKEN, TokenResponse


def _required_string(data: dict[str, Any], key: str) -> str:
    value = str(data.get(key, "")).strip()
    if not value:
        raise ProtocolError(f"authplane: token response missing required field {key!r}")
    return value


def _optional_int(data: dict[str, Any], key: str, *, default: int | None = 0) -> int | None:
    """Parse an optional integer field. ``default`` is returned for absent
    or empty-string values; ``None`` is a valid default so callers can
    distinguish "field omitted on the wire" from "field present and zero".
    """
    sentinel = object()
    value = data.get(key, sentinel)
    if value is sentinel or value in ("", None):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ProtocolError(
            f"authplane: token response field {key!r} must be an integer, got {value!r}"
        ) from exc
    if parsed < 0:
        raise ProtocolError(f"authplane: token response field {key!r} must be non-negative")
    return parsed


def parse_token_response(
    data: dict[str, Any],
    *,
    allow_issued_token_type: bool,
    expect_dpop: bool = False,
) -> TokenResponse:
    """Parse and validate a successful OAuth token endpoint response."""
    access_token = _required_string(data, "access_token")
    token_type = _required_string(data, "token_type")
    if token_type.lower() not in {"bearer", "dpop"}:
        raise ProtocolError(
            f"authplane: unsupported token_type {token_type!r}; only Bearer and DPoP are supported"
        )

    # RFC 9449 §5: when a DPoP proof was sent, the response token_type MUST
    # be "DPoP".  A "Bearer" response means the AS ignored the proof and the
    # token is NOT sender-constrained — accepting it would be a confused deputy.
    if expect_dpop and token_type.lower() != "dpop":
        raise ProtocolError(
            f"authplane: DPoP proof was sent but token_type is {token_type!r}, "
            "not 'DPoP'; the authorization server may have ignored the DPoP proof "
            "(RFC 9449 §5)"
        )

    issued_token_type = str(data.get("issued_token_type", "")).strip()
    if allow_issued_token_type:
        if not issued_token_type:
            raise ProtocolError(
                "authplane: token exchange response missing required 'issued_token_type' "
                "(RFC 8693 §2.2.1)"
            )
        if issued_token_type != TOKEN_TYPE_ACCESS_TOKEN:
            raise ProtocolError(
                "authplane: unsupported issued_token_type "
                f"{issued_token_type!r}; only access_token is supported"
            )

    cnf = data.get("cnf")
    cnf_jkt = ""
    if isinstance(cnf, dict):
        typed_cnf = cast("dict[str, Any]", cnf)
        cnf_jkt = str(typed_cnf.get("jkt", "")).strip()

    return TokenResponse(
        access_token=access_token,
        token_type=token_type,
        expires_in=_optional_int(data, "expires_in", default=None),
        scope=str(data.get("scope", "")),
        refresh_token=str(data.get("refresh_token", "")),
        issued_token_type=issued_token_type,
        cnf_jkt=cnf_jkt,
    )
