"""Tests for the shared _dpop_adapter helpers.

These pin the cross-adapter contracts (cardinality enforcement, raw-path
reading) without requiring either adapter package's full plumbing — the
helpers duck-type against a structural Protocol so tests can drive them
with a small fake Headers/Request shape.
"""

from __future__ import annotations

import pytest

from authplane._dpop_adapter import read_dpop_header
from authplane.errors import DPoPMultipleProofsError


class _FakeHeaders:
    """Minimal stand-in for ``starlette.datastructures.Headers``.

    Returns the configured multi-value list from ``getlist``; ``get``
    is implemented for protocol conformance but is intentionally not
    exercised here — :func:`read_dpop_header` reads via ``getlist``.
    """

    def __init__(self, values: list[str]) -> None:
        self._values = values

    def get(self, key: str, default: str | None = None) -> str | None:
        _ = key
        return self._values[0] if self._values else default

    def getlist(self, key: str) -> list[str]:
        _ = key
        return list(self._values)


class _FakeRequest:
    def __init__(self, dpop_values: list[str]) -> None:
        self._headers = _FakeHeaders(dpop_values)

    @property
    def headers(self) -> _FakeHeaders:
        return self._headers

    @property
    def scope(self) -> dict[str, object]:
        return {}

    @property
    def state(self) -> object:  # pragma: no cover - unused here
        return object()

    @property
    def url(self) -> object:  # pragma: no cover - unused here
        return object()


def test_no_dpop_header_returns_none() -> None:
    assert read_dpop_header(_FakeRequest([])) is None  # pyright: ignore[reportArgumentType]


def test_single_dpop_header_returns_proof() -> None:
    assert read_dpop_header(_FakeRequest(["a.b.c"])) == "a.b.c"  # pyright: ignore[reportArgumentType]


def test_whitespace_only_header_is_treated_as_absent() -> None:
    """``DPoP: `` (whitespace only) must not be miscounted as one value."""
    assert read_dpop_header(_FakeRequest(["   "])) is None  # pyright: ignore[reportArgumentType]


def test_two_dpop_headers_reject() -> None:
    """Duplicate ``DPoP`` headers on the request fail §4.3 #1."""
    with pytest.raises(DPoPMultipleProofsError, match="2 DPoP proofs"):
        read_dpop_header(_FakeRequest(["a.b.c", "x.y.z"]))  # pyright: ignore[reportArgumentType]


def test_comma_joined_proxy_shape_reject() -> None:
    """RFC 9110 §5.3 lets proxies join repeated headers with `,`.

    JWS compact serialization never carries a literal `,`, so a comma in
    a single ``DPoP`` value is unambiguously the proxy-joined shape and
    must trip the same cardinality guard as two separate headers.
    """
    with pytest.raises(DPoPMultipleProofsError, match="2 DPoP proofs"):
        read_dpop_header(_FakeRequest(["a.b.c, x.y.z"]))  # pyright: ignore[reportArgumentType]


def test_three_values_across_shapes_reject() -> None:
    """Mixed multi-header + comma-joined still trips the guard."""
    with pytest.raises(DPoPMultipleProofsError, match=r"3 DPoP proofs"):
        read_dpop_header(_FakeRequest(["a.b.c", "x.y.z, p.q.r"]))  # pyright: ignore[reportArgumentType]


def test_single_value_is_trimmed() -> None:
    """Leading/trailing whitespace around a sole proof is stripped."""
    assert (
        read_dpop_header(_FakeRequest(["  a.b.c  "]))  # pyright: ignore[reportArgumentType]
        == "a.b.c"
    )


def test_all_blank_pieces_treated_as_absent() -> None:
    """``", ,"`` carries no real proof — return ``None``, do not reject."""
    assert read_dpop_header(_FakeRequest([" , , "])) is None  # pyright: ignore[reportArgumentType]
