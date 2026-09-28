"""Tests for generic document fetcher with SSRF protection."""

import logging
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from authplane.internal.document_fetcher import DocumentFetcher
from authplane.internal.fetch_result import FetchResult
from authplane.net.fetch_settings import FetchSettings
from authplane.net.ssrf import HttpResponse, SSRFError


@pytest.mark.asyncio
class TestDocumentFetcherWithoutSSRF:
    """Test document fetcher with SSRF protection disabled."""

    async def test_successful_fetch(self) -> None:
        """Should fetch document successfully without SSRF protection."""
        jwks_data: dict[str, list[dict[str, str]]] = {"keys": [{"kid": "test-key", "kty": "RSA"}]}

        with respx.mock:
            respx.get("https://auth.example.com/.well-known/jwks.json").mock(
                return_value=respx.MockResponse(status_code=200, json=jwks_data)
            )

            fetcher = DocumentFetcher(
                "https://auth.example.com/.well-known/jwks.json",
                settings=FetchSettings(ssrf_protection=False),
            )
            result = await fetcher.fetch()
            assert isinstance(result, FetchResult)
            assert result.document == jwks_data

    async def test_http_error_propagated(self) -> None:
        """Should propagate HTTP errors."""
        with respx.mock:
            respx.get("https://auth.example.com/.well-known/jwks.json").mock(
                return_value=respx.MockResponse(status_code=500)
            )

            fetcher = DocumentFetcher(
                "https://auth.example.com/.well-known/jwks.json",
                settings=FetchSettings(ssrf_protection=False),
            )

            with pytest.raises(httpx.HTTPStatusError):
                await fetcher.fetch()


@pytest.mark.asyncio
class TestDocumentFetcherWithSSRF:
    """Test document fetcher with SSRF protection enabled."""

    @patch("authplane.internal.document_fetcher.ssrf_safe_get")
    async def test_uses_ssrf_safe_get(self, mock_ssrf_fetch: AsyncMock) -> None:
        """Should use ssrf_safe_get when protection is enabled."""
        jwks_data: dict[str, list[dict[str, str]]] = {"keys": [{"kid": "test-key", "kty": "RSA"}]}
        mock_ssrf_fetch.return_value = HttpResponse(body=jwks_data, headers={}, status_code=200)

        fetcher = DocumentFetcher(
            "https://auth.example.com/.well-known/jwks.json",
        )

        result = await fetcher.fetch()
        assert isinstance(result, FetchResult)
        assert result.document == jwks_data

        # Verify ssrf_safe_get was called with correct parameters
        mock_ssrf_fetch.assert_called_once_with(
            "https://auth.example.com/.well-known/jwks.json",
            allow_http=False,
            allow_localhost=False,
            allow_private_networks=False,
            max_size=65536,
            timeout=10.0,
        )

    @patch("authplane.internal.document_fetcher.ssrf_safe_get")
    async def test_allow_http_passed_to_ssrf_fetch(self, mock_ssrf_fetch: AsyncMock) -> None:
        """Should pass allow_http to ssrf_safe_get."""
        mock_ssrf_fetch.return_value = HttpResponse(body={"keys": []}, headers={}, status_code=200)

        fetcher = DocumentFetcher(
            "http://localhost:8000/.well-known/jwks.json", settings=FetchSettings(allow_http=True)
        )

        await fetcher.fetch()

        mock_ssrf_fetch.assert_called_once_with(
            "http://localhost:8000/.well-known/jwks.json",
            allow_http=True,
            allow_localhost=False,
            allow_private_networks=False,
            max_size=65536,
            timeout=10.0,
        )

    @patch("authplane.internal.document_fetcher.ssrf_safe_get")
    async def test_ssrf_error_propagated(self, mock_ssrf_fetch: AsyncMock) -> None:
        """Should propagate SSRFError from ssrf_safe_get."""
        mock_ssrf_fetch.side_effect = SSRFError("blocked IP")

        fetcher = DocumentFetcher(
            "https://malicious.com/.well-known/jwks.json",
        )

        with pytest.raises(SSRFError, match="blocked IP"):
            await fetcher.fetch()


class TestDocumentFetcherConfiguration:
    """Test document fetcher configuration options."""

    def test_default_ssrf_protection_enabled(self) -> None:
        """SSRF protection should be enabled by default."""
        fetcher = DocumentFetcher("https://auth.example.com/.well-known/jwks.json")

        assert fetcher.ssrf_protection is True

    def test_default_http_not_allowed(self) -> None:
        """HTTP should not be allowed by default."""
        fetcher = DocumentFetcher("https://auth.example.com/.well-known/jwks.json")

        assert fetcher.allow_http is False


@pytest.mark.asyncio
class TestDocumentFetcherEdgeCases:
    """Test edge cases and error handling."""

    @patch("authplane.internal.document_fetcher.ssrf_safe_get")
    async def test_logs_ssrf_errors(
        self, mock_ssrf_fetch: AsyncMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Should log SSRF errors before raising."""
        caplog.set_level(logging.ERROR)

        mock_ssrf_fetch.side_effect = SSRFError("DNS resolution failed")

        fetcher = DocumentFetcher(
            "https://malicious.com/.well-known/jwks.json",
        )

        with pytest.raises(SSRFError):
            await fetcher.fetch()

        # Verify error was logged
        assert "SSRF protection blocked" in caplog.text
        assert "malicious.com" in caplog.text

    async def test_multiple_fetches(self) -> None:
        """Should handle multiple fetch calls."""
        jwks_data: dict[str, list[dict[str, str]]] = {"keys": [{"kid": "test-key"}]}

        with respx.mock:
            route = respx.get("https://auth.example.com/.well-known/jwks.json").mock(
                return_value=respx.MockResponse(status_code=200, json=jwks_data)
            )

            fetcher = DocumentFetcher(
                "https://auth.example.com/.well-known/jwks.json",
                settings=FetchSettings(ssrf_protection=False),
            )

            result1 = await fetcher.fetch()
            assert result1.document == jwks_data

            result2 = await fetcher.fetch()
            assert result2.document == jwks_data

            assert route.call_count == 2

    async def test_fetch_extracts_cache_control_max_age(self) -> None:
        """Should extract Cache-Control max-age from response headers."""
        jwks_data: dict[str, list[dict[str, str]]] = {"keys": [{"kid": "test-key", "kty": "RSA"}]}

        with respx.mock:
            respx.get("https://auth.example.com/.well-known/jwks.json").mock(
                return_value=respx.MockResponse(
                    status_code=200,
                    json=jwks_data,
                    headers={"Cache-Control": "max-age=120"},
                )
            )

            fetcher = DocumentFetcher(
                "https://auth.example.com/.well-known/jwks.json",
                settings=FetchSettings(ssrf_protection=False),
            )

            before = time.time()
            result = await fetcher.fetch()
            after = time.time()

            assert result.document == jwks_data
            assert result.expires_at is not None
            assert before + 120 <= result.expires_at <= after + 120

    async def test_fetch_no_cache_headers_returns_none_expires_at(self) -> None:
        """Should return None expires_at when no cache headers present."""
        jwks_data: dict[str, list[dict[str, str]]] = {"keys": [{"kid": "test-key", "kty": "RSA"}]}

        with respx.mock:
            respx.get("https://auth.example.com/.well-known/jwks.json").mock(
                return_value=respx.MockResponse(
                    status_code=200,
                    json=jwks_data,
                )
            )

            fetcher = DocumentFetcher(
                "https://auth.example.com/.well-known/jwks.json",
                settings=FetchSettings(ssrf_protection=False),
            )

            result = await fetcher.fetch()
            assert result.document == jwks_data
            assert result.expires_at is None
