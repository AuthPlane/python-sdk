"""Tests for SSRF protection utilities."""

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from authplane.net.ssrf import (
    SSRFError,
    ValidatedURL,
    format_ip_for_url,
    is_ip_allowed,
    resolve_hostname,
    ssrf_safe_get,
    validate_url,
)


class TestFormatIPForURL:
    """Test IP address formatting for URLs."""

    def test_ipv4_no_brackets(self) -> None:
        """IPv4 addresses should not be bracketed."""
        assert format_ip_for_url("1.2.3.4") == "1.2.3.4"

    def test_ipv6_with_brackets(self) -> None:
        """IPv6 addresses should be bracketed."""
        assert format_ip_for_url("2001:db8::1") == "[2001:db8::1]"
        assert format_ip_for_url("::1") == "[::1]"

    def test_invalid_ip_passthrough(self) -> None:
        """Invalid IP strings should be passed through unchanged."""
        assert format_ip_for_url("not-an-ip") == "not-an-ip"


class TestIsIPAllowed:
    """Test IP address validation."""

    def test_public_ipv4_allowed(self) -> None:
        """Public IPv4 addresses should be allowed."""
        assert is_ip_allowed("8.8.8.8")
        assert is_ip_allowed("1.1.1.1")

    def test_private_ipv4_blocked(self) -> None:
        """Private IPv4 addresses should be blocked."""
        assert not is_ip_allowed("10.0.0.1")
        assert not is_ip_allowed("172.16.0.1")
        assert not is_ip_allowed("192.168.1.1")

    def test_loopback_ipv4_blocked(self) -> None:
        """Loopback IPv4 addresses should be blocked."""
        assert not is_ip_allowed("127.0.0.1")
        assert not is_ip_allowed("127.1.2.3")

    def test_link_local_ipv4_blocked(self) -> None:
        """Link-local IPv4 addresses (AWS metadata) should be blocked."""
        assert not is_ip_allowed("169.254.169.254")
        assert not is_ip_allowed("169.254.0.1")

    def test_carrier_grade_nat_blocked(self) -> None:
        """RFC6598 Carrier-Grade NAT addresses should be blocked."""
        assert not is_ip_allowed("100.64.0.1")
        assert not is_ip_allowed("100.127.255.254")

    def test_multicast_ipv4_blocked(self) -> None:
        """Multicast IPv4 addresses should be blocked."""
        assert not is_ip_allowed("224.0.0.1")
        assert not is_ip_allowed("239.255.255.255")

    def test_public_ipv6_allowed(self) -> None:
        """Public IPv6 addresses should be allowed."""
        assert is_ip_allowed("2001:4860:4860::8888")  # Google DNS

    def test_loopback_ipv6_blocked(self) -> None:
        """Loopback IPv6 addresses should be blocked."""
        assert not is_ip_allowed("::1")

    def test_link_local_ipv6_blocked(self) -> None:
        """Link-local IPv6 addresses should be blocked."""
        assert not is_ip_allowed("fe80::1")

    def test_ipv6_embedded_ipv4_blocked(self) -> None:
        """IPv6 addresses with embedded private IPv4 should be blocked."""
        # IPv4-mapped IPv6 (::ffff:192.168.1.1)
        assert not is_ip_allowed("::ffff:192.168.1.1")
        # 6to4 addresses embedding private IPs
        assert not is_ip_allowed("2002:c000:0201::1")  # 192.0.2.1 embedded

    def test_invalid_ip_rejected(self) -> None:
        """Invalid IP strings should be rejected."""
        assert not is_ip_allowed("not-an-ip")
        assert not is_ip_allowed("999.999.999.999")


@pytest.mark.asyncio
class TestResolveHostname:
    """Test DNS resolution."""

    @patch("socket.getaddrinfo")
    async def test_resolve_success(self, mock_getaddrinfo: MagicMock) -> None:
        """Should resolve hostnames to IP addresses."""
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ("1.2.3.4", 443)),
            (None, None, None, None, ("5.6.7.8", 443)),
        ]

        ips = await resolve_hostname("example.com", 443)
        assert set(ips) == {"1.2.3.4", "5.6.7.8"}

    @patch("socket.getaddrinfo")
    async def test_resolve_failure(self, mock_getaddrinfo: MagicMock) -> None:
        """Should raise SSRFError on DNS failure."""
        import socket

        mock_getaddrinfo.side_effect = socket.gaierror("DNS lookup failed")

        with pytest.raises(SSRFError, match="DNS resolution failed"):
            await resolve_hostname("nonexistent.invalid", 443)

    @patch("socket.getaddrinfo")
    async def test_resolve_no_results(self, mock_getaddrinfo: MagicMock) -> None:
        """Should raise SSRFError when no addresses returned."""
        mock_getaddrinfo.return_value = []

        with pytest.raises(SSRFError, match="no addresses"):
            await resolve_hostname("example.com", 443)


@pytest.mark.asyncio
class TestValidateURL:
    """Test URL validation."""

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_https_url_with_public_ip(self, mock_resolve: AsyncMock) -> None:
        """HTTPS URL resolving to public IP should be allowed."""
        mock_resolve.return_value = ["8.8.8.8"]

        validated = await validate_url("https://example.com/path?query=1")
        assert validated.original_url == "https://example.com/path?query=1"
        assert validated.hostname == "example.com"
        assert validated.port == 443
        assert validated.path == "/path?query=1"
        assert validated.resolved_ips == ["8.8.8.8"]

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_http_url_rejected_by_default(self, mock_resolve: AsyncMock) -> None:
        """HTTP URL should be rejected by default."""
        with pytest.raises(SSRFError, match="must use HTTPS"):
            await validate_url("http://example.com/")

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_http_url_allowed_with_flag(self, mock_resolve: AsyncMock) -> None:
        """HTTP URL should be allowed with allow_http=True."""
        mock_resolve.return_value = ["8.8.8.8"]

        validated = await validate_url("http://example.com/", allow_http=True)
        assert validated.hostname == "example.com"
        assert validated.port == 80

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_file_protocol_rejected(self, mock_resolve: AsyncMock) -> None:
        """file:// URLs should be rejected."""
        with pytest.raises(SSRFError, match="must use HTTPS"):
            await validate_url("file:///etc/passwd")

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_private_ip_blocked(self, mock_resolve: AsyncMock) -> None:
        """URLs resolving to private IPs should be blocked."""
        mock_resolve.return_value = ["192.168.1.1"]

        with pytest.raises(SSRFError, match="blocked IP"):
            await validate_url("https://internal.example.com/")

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_cloud_metadata_blocked(self, mock_resolve: AsyncMock) -> None:
        """URLs resolving to cloud metadata endpoint should be blocked."""
        mock_resolve.return_value = ["169.254.169.254"]

        with pytest.raises(SSRFError, match="blocked IP"):
            await validate_url("https://metadata.example.com/")

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_localhost_blocked(self, mock_resolve: AsyncMock) -> None:
        """URLs resolving to localhost should be blocked."""
        mock_resolve.return_value = ["127.0.0.1"]

        with pytest.raises(SSRFError, match="blocked IP"):
            await validate_url("https://localhost/")

    @patch("authplane.net.ssrf.resolve_hostname")
    async def test_mixed_public_private_blocked(self, mock_resolve: AsyncMock) -> None:
        """If any resolved IP is blocked, validation should fail."""
        mock_resolve.return_value = ["8.8.8.8", "192.168.1.1"]

        with pytest.raises(SSRFError, match="blocked IP"):
            await validate_url("https://mixed.example.com/")

    async def test_url_without_host_rejected(self) -> None:
        """URL without host should be rejected."""
        with pytest.raises(SSRFError, match="must have a host"):
            await validate_url("https:///path")

    async def test_invalid_url_rejected(self) -> None:
        """Invalid URL should be rejected (missing scheme)."""
        with pytest.raises(SSRFError, match="must use HTTPS"):
            await validate_url("not a url")


@pytest.mark.asyncio
class TestSSRFSafeFetch:
    """Test SSRF-safe HTTP fetching."""

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_successful_fetch(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Should fetch JSON successfully with SSRF protections."""
        # Setup validation
        mock_validate.return_value = ValidatedURL(
            original_url="https://example.com/.well-known/jwks.json",
            hostname="example.com",
            port=443,
            path="/.well-known/jwks.json",
            resolved_ips=["1.2.3.4"],
        )

        # Setup HTTP client mock
        mock_response = MagicMock()
        mock_response.headers = {"content-length": "100"}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b'{"keys": []}'

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        result = await ssrf_safe_get("https://example.com/.well-known/jwks.json")
        assert result.body == {"keys": []}

        # Verify SSRF protections were applied
        mock_validate.assert_called_once_with(
            "https://example.com/.well-known/jwks.json",
            allow_http=False,
            allow_localhost=False,
            allow_private_networks=False,
        )

        # Verify DNS pinning (connect to IP, not hostname)
        mock_client.stream.assert_called_once()
        call_args = mock_client.stream.call_args
        assert call_args[0][0] == "GET"
        assert call_args[0][1] == "https://1.2.3.4:443/.well-known/jwks.json"
        assert call_args[1]["headers"]["Host"] == "example.com"

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_host_header_includes_non_default_port(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Non-default port must appear in the Host header (RFC 7230 §5.4)."""
        mock_validate.return_value = ValidatedURL(
            original_url="http://localhost:9000/foo",
            hostname="localhost",
            port=9000,
            path="/foo",
            resolved_ips=["127.0.0.1"],
        )

        mock_response = MagicMock()
        mock_response.headers = {"content-length": "2"}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b"{}"

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        await ssrf_safe_get("http://localhost:9000/foo", allow_http=True, allow_localhost=True)

        assert mock_client.stream.call_args[1]["headers"]["Host"] == "localhost:9000"

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_host_header_strips_default_http_port(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Default HTTP port 80 must be omitted from the Host header."""
        mock_validate.return_value = ValidatedURL(
            original_url="http://example.com/path",
            hostname="example.com",
            port=80,
            path="/path",
            resolved_ips=["1.2.3.4"],
        )

        mock_response = MagicMock()
        mock_response.headers = {"content-length": "2"}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b"{}"

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        await ssrf_safe_get("http://example.com/path", allow_http=True)

        assert mock_client.stream.call_args[1]["headers"]["Host"] == "example.com"

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_host_header_brackets_ipv6_literal(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """IPv6 hostnames must be bracketed in the Host header (RFC 3986 §3.2.2)."""
        mock_validate.return_value = ValidatedURL(
            original_url="http://[::1]:9000/foo",
            hostname="::1",
            port=9000,
            path="/foo",
            resolved_ips=["::1"],
        )

        mock_response = MagicMock()
        mock_response.headers = {"content-length": "2"}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b"{}"

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        await ssrf_safe_get("http://[::1]:9000/foo", allow_http=True, allow_localhost=True)

        assert mock_client.stream.call_args[1]["headers"]["Host"] == "[::1]:9000"

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_response_too_large_content_length(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Should reject response if Content-Length exceeds max_size."""
        mock_validate.return_value = ValidatedURL(
            original_url="https://example.com/large",
            hostname="example.com",
            port=443,
            path="/large",
            resolved_ips=["1.2.3.4"],
        )

        mock_response = MagicMock()
        mock_response.headers = {"content-length": "100000"}  # > 64KB default
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        with pytest.raises(SSRFError, match="Response too large"):
            await ssrf_safe_get("https://example.com/large")

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_response_too_large_actual_content(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Should reject response if actual content exceeds max_size."""
        mock_validate.return_value = ValidatedURL(
            original_url="https://example.com/large",
            hostname="example.com",
            port=443,
            path="/large",
            resolved_ips=["1.2.3.4"],
        )

        mock_response = MagicMock()
        mock_response.headers = {}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b"x" * 100000  # > 64KB default

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        with pytest.raises(SSRFError, match="Response too large"):
            await ssrf_safe_get("https://example.com/large")

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_redirects_disabled(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Should disable redirects to prevent bypass."""
        mock_validate.return_value = ValidatedURL(
            original_url="https://example.com/",
            hostname="example.com",
            port=443,
            path="/",
            resolved_ips=["1.2.3.4"],
        )

        mock_response = MagicMock()
        mock_response.headers = {}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b"{}"

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        await ssrf_safe_get("https://example.com/")

        # Verify client was created with follow_redirects=False
        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args[1]
        assert call_kwargs["follow_redirects"] is False

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_timeout_configured(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Should configure timeout for all operations."""
        mock_validate.return_value = ValidatedURL(
            original_url="https://example.com/",
            hostname="example.com",
            port=443,
            path="/",
            resolved_ips=["1.2.3.4"],
        )

        mock_response = MagicMock()
        mock_response.headers = {}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b"{}"

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm = AsyncMock()
        mock_stream_cm.__aenter__.return_value = mock_response
        mock_stream_cm.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_stream_cm)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        await ssrf_safe_get("https://example.com/", timeout=5.0)

        # Verify timeout was configured
        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args[1]
        assert call_kwargs["timeout"].connect == 5.0

    @patch("authplane.net.ssrf.validate_url")
    async def test_validation_error_propagated(self, mock_validate: AsyncMock) -> None:
        """Should propagate SSRFError from validation."""
        mock_validate.side_effect = SSRFError("blocked IP")

        with pytest.raises(SSRFError, match="blocked IP"):
            await ssrf_safe_get("https://malicious.com/")

    @patch("authplane.net.ssrf.validate_url")
    @patch("httpx.AsyncClient")
    async def test_fallback_to_next_ip_on_timeout(
        self, mock_client_class: MagicMock, mock_validate: AsyncMock
    ) -> None:
        """Should try next IP if first times out."""
        mock_validate.return_value = ValidatedURL(
            original_url="https://example.com/",
            hostname="example.com",
            port=443,
            path="/",
            resolved_ips=["1.2.3.4", "5.6.7.8"],  # Two IPs
        )

        # First IP times out, second succeeds
        mock_response = MagicMock()
        mock_response.headers = {}

        async def mock_aiter_bytes() -> AsyncGenerator[bytes, None]:
            yield b'{"ok": true}'

        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.status_code = 200

        mock_stream_cm_success = AsyncMock()
        mock_stream_cm_success.__aenter__.return_value = mock_response
        mock_stream_cm_success.__aexit__.return_value = None

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(
            side_effect=[
                httpx.TimeoutException("timeout"),  # First IP fails
                mock_stream_cm_success,  # Second IP succeeds
            ]
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client

        result = await ssrf_safe_get("https://example.com/")
        assert result.body == {"ok": True}
        assert mock_client.stream.call_count == 2
