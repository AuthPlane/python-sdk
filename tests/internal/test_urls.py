"""Tests for URL utilities (RFC 8414 metadata URL construction)."""

import pytest

from authplane.errors import InvalidIssuerError, InvalidResourceError
from authplane.internal.urls import (
    build_metadata_url,
    build_prm_url,
    validate_resource_indicator,
)


class TestBuildMetadataUrl:
    """Tests for build_metadata_url per RFC 8414 Section 3."""

    def test_issuer_without_path(self) -> None:
        """Issuer with no path appends .well-known suffix directly."""
        result = build_metadata_url("https://auth.example.com")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server"

    def test_issuer_with_single_path_segment(self) -> None:
        """Issuer with path inserts .well-known after authority."""
        result = build_metadata_url("https://auth.example.com/tenant1")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"

    def test_issuer_with_multi_segment_path(self) -> None:
        """Issuer with multiple path segments inserts .well-known after authority."""
        result = build_metadata_url("https://auth.example.com/org/tenant1")
        assert (
            result == "https://auth.example.com/.well-known/oauth-authorization-server/org/tenant1"
        )

    def test_issuer_with_trailing_slash(self) -> None:
        """Trailing slash on issuer is normalized away."""
        result = build_metadata_url("https://auth.example.com/")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server"

    def test_issuer_with_path_and_trailing_slash(self) -> None:
        """Trailing slash on path issuer is normalized."""
        result = build_metadata_url("https://auth.example.com/tenant1/")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"

    def test_issuer_with_port(self) -> None:
        """Issuer with explicit port is preserved."""
        result = build_metadata_url("https://auth.example.com:8443")
        assert result == "https://auth.example.com:8443/.well-known/oauth-authorization-server"

    def test_issuer_with_port_and_path(self) -> None:
        """Issuer with port and path handles both correctly."""
        result = build_metadata_url("https://auth.example.com:8443/tenant1")
        assert (
            result == "https://auth.example.com:8443/.well-known/oauth-authorization-server/tenant1"
        )

    def test_http_issuer(self) -> None:
        """HTTP scheme is preserved (for dev mode)."""
        result = build_metadata_url("http://localhost:3000")
        assert result == "http://localhost:3000/.well-known/oauth-authorization-server"

    def test_http_issuer_with_path(self) -> None:
        """HTTP issuer with path inserts .well-known correctly."""
        result = build_metadata_url("http://localhost:3000/tenant1")
        assert result == "http://localhost:3000/.well-known/oauth-authorization-server/tenant1"


class TestResourceIndicatorValidation:
    """RFC 8707 §2 — a resource indicator MUST NOT carry a fragment."""

    def test_validate_rejects_fragment(self) -> None:
        with pytest.raises(ValueError, match="must not contain a fragment"):
            validate_resource_indicator("https://api.example.com/mcp#frag")

    def test_validate_accepts_query(self) -> None:
        # A query is legal and is preserved by the derivation (RFC 9728 §3.1);
        # only the fragment is forbidden. The two are treated asymmetrically.
        validate_resource_indicator("https://api.example.com/mcp?tenant=a")

    def test_validate_does_not_echo_credentials(self) -> None:
        with pytest.raises(ValueError) as exc:
            validate_resource_indicator("https://svc:s3cr3t@api.example.com/mcp#frag")
        message = str(exc.value)
        assert "s3cr3t" not in message
        # Compare the echoed identifier whole rather than asking whether the host
        # appears somewhere in the message. A containment check cannot tell "the
        # host is the identifier" from "the host occurs inside a longer one", so
        # it would also pass on a message naming the wrong resource -- and it is
        # the shape static analysis flags as incomplete URL sanitization.
        assert message.rsplit(": ", 1)[-1] == repr("https://api.example.com/mcp")

    def test_malformed_port_does_not_mask_the_rfc_error(self) -> None:
        # ParseResult.port raises ValueError on a non-integer port. Building the
        # redacted authority for the error message must not surface urllib's
        # "Port could not be cast to integer value" in place of the RFC citation.
        with pytest.raises(ValueError) as exc:
            validate_resource_indicator("https://h:abc/mcp#frag")
        assert "must not contain a fragment" in str(exc.value)
        assert "cast to integer" not in str(exc.value)


def test_unparseable_authority_does_not_mask_the_rfc_error() -> None:
    # urlparse raises ValueError("Invalid IPv6 URL") on an unclosed bracket —
    # before the fragment is ever split off. Both guards must still report the
    # RFC violation they were written for, not urllib's parse failure.
    with pytest.raises(ValueError) as exc:
        validate_resource_indicator("https://[::1#frag")
    assert "must not contain a fragment" in str(exc.value)
    assert "IPv6" not in str(exc.value)

    with pytest.raises(ValueError) as exc:
        build_metadata_url("https://[::1?x=1")
    assert "must not contain a query or fragment" in str(exc.value)
    assert "IPv6" not in str(exc.value)


def test_build_prm_url_also_reports_the_rfc_error_not_urllib_s() -> None:
    # The third guard kept the original shape after the first two were fixed:
    # build_prm_url parsed before calling validate_resource_indicator, so an
    # unclosed IPv6 bracket surfaced "Invalid IPv6 URL" instead of the citation.
    with pytest.raises(ValueError) as exc:
        build_prm_url("https://[::1#frag")
    assert "must not contain a fragment" in str(exc.value)
    assert "IPv6" not in str(exc.value)


class TestLeadingSlashPreservation:
    """A doubled leading slash is a distinct identifier, not a normalization."""

    def test_prm_double_leading_slash_does_not_collapse(self) -> None:
        assert build_prm_url("https://api.example.com//mcp") != build_prm_url(
            "https://api.example.com/mcp"
        )

    def test_metadata_double_leading_slash_does_not_collapse(self) -> None:
        assert build_metadata_url("https://auth.example.com//t") != build_metadata_url(
            "https://auth.example.com/t"
        )

    def test_terminating_slash_still_stripped(self) -> None:
        assert build_prm_url("https://api.example.com/mcp/") == build_prm_url(
            "https://api.example.com/mcp"
        )


def test_issuer_error_is_matchable_and_still_a_value_error() -> None:
    # Additive: the guards raised a bare ValueError before, and that is a public
    # contract — but it was indistinguishable from any other ValueError the SDK
    # raises (e.g. "jwks_refresh_seconds must be positive").
    with pytest.raises(InvalidIssuerError):
        build_metadata_url("https://auth.example.com/?x=1")
    with pytest.raises(ValueError):
        build_metadata_url("https://auth.example.com/?x=1")


def test_scheme_less_identifier_keeps_the_path_separator() -> None:
    # Nothing upstream requires the identifier to be absolute — create() gates
    # only on ?/# and resource() only on #. For a scheme-less input urlparse
    # puts the whole authority in `path` with no leading slash, so concatenating
    # it directly mashed the segment onto the well-known suffix
    # ("...oauth-authorization-serverapi.example.com/mcp").
    assert build_metadata_url("api.example.com/mcp").startswith(
        "/.well-known/oauth-authorization-server/"
    )
    assert build_prm_url("api.example.com/mcp").startswith("/.well-known/oauth-protected-resource/")


class TestParamsSegmentIsNotCollapsed:
    """An RFC 3986 ";params" segment is part of the path, not a separate slot.

    ``urlparse`` peels it off the last path segment into ``ParseResult.params``;
    ``urlunparse`` then needs it passed back or the segment is silently dropped.
    Both builders passed "", so "/mcp;v=1" and "/mcp" derived the same document —
    two distinct identifiers collapsing onto one, which is the whole class of bug
    the sibling tests above cover for the leading and terminating slash.
    """

    def test_prm_params_segment_does_not_collapse(self) -> None:
        assert build_prm_url("https://api.example.com/mcp;v=1") != build_prm_url(
            "https://api.example.com/mcp"
        )

    def test_metadata_params_segment_does_not_collapse(self) -> None:
        assert build_metadata_url("https://auth.example.com/t;jsessionid=1") != (
            build_metadata_url("https://auth.example.com/t")
        )

    def test_prm_params_segment_is_kept_verbatim(self) -> None:
        # Not just "different" — the segment has to survive into the derived URL.
        assert build_prm_url("https://api.example.com/mcp;v=1").endswith(
            "/.well-known/oauth-protected-resource/mcp;v=1"
        )


def test_resource_error_is_matchable_and_still_a_value_error() -> None:
    # The counterpart of test_issuer_error_is_matchable_and_still_a_value_error.
    # Both guards raised a bare ValueError before, and that stays a public
    # contract; what the class adds is telling an identifier misconfiguration
    # apart from any other ValueError the SDK raises.
    with pytest.raises(InvalidResourceError):
        validate_resource_indicator("https://api.example.com/mcp#frag")
    with pytest.raises(ValueError):
        validate_resource_indicator("https://api.example.com/mcp#frag")
    with pytest.raises(InvalidResourceError):
        build_prm_url("https://api.example.com/mcp#frag")


def test_identifier_errors_are_exported_from_the_package_root() -> None:
    # Both classes exist to be caught by name, which only works if they are
    # importable from the root. Nothing else in the suite imports them from
    # there — the tests above reach into authplane.errors — so without this the
    # __all__ entries could rot without anything noticing.
    import authplane

    assert "InvalidIssuerError" in authplane.__all__
    assert "InvalidResourceError" in authplane.__all__
    assert authplane.InvalidIssuerError is InvalidIssuerError
    assert authplane.InvalidResourceError is InvalidResourceError
