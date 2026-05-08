"""Tests for URL utilities (RFC 8414 metadata URL construction)."""

from authplane.internal.urls import build_metadata_url


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
