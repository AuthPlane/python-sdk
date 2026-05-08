"""Tests for development mode and granular SSRF controls."""

import os
from typing import Any
from unittest.mock import patch

import pytest

from authplane import AuthplaneClient, AuthplaneError, FetchSettings
from authplane.net.ssrf import HttpResponse, is_ip_allowed


class TestIsIPAllowedGranular:
    """Test granular IP allow controls."""

    def test_localhost_blocked_by_default(self) -> None:
        """Localhost should be blocked in production mode."""
        assert not is_ip_allowed("127.0.0.1")
        assert not is_ip_allowed("::1")

    def test_localhost_allowed_with_flag(self) -> None:
        """Localhost should be allowed with allow_localhost=True."""
        assert is_ip_allowed("127.0.0.1", allow_localhost=True)
        assert is_ip_allowed("127.1.2.3", allow_localhost=True)
        assert is_ip_allowed("::1", allow_localhost=True)

    def test_private_networks_blocked_by_default(self) -> None:
        """Private networks should be blocked in production mode."""
        assert not is_ip_allowed("10.0.0.1")
        assert not is_ip_allowed("172.16.0.1")
        assert not is_ip_allowed("192.168.1.1")

    def test_private_networks_allowed_with_flag(self) -> None:
        """Private networks should be allowed with allow_private_networks=True."""
        assert is_ip_allowed("10.0.0.1", allow_private_networks=True)
        assert is_ip_allowed("172.16.0.1", allow_private_networks=True)
        assert is_ip_allowed("192.168.1.1", allow_private_networks=True)

    def test_cloud_metadata_always_blocked(self) -> None:
        """Cloud metadata endpoints should ALWAYS be blocked."""
        # Even with all flags enabled
        assert not is_ip_allowed(
            "169.254.169.254",
            allow_localhost=True,
            allow_private_networks=True,
        )
        assert not is_ip_allowed(
            "169.254.0.1",
            allow_localhost=True,
            allow_private_networks=True,
        )

    def test_public_ips_always_allowed(self) -> None:
        """Public IPs should be allowed regardless of flags."""
        assert is_ip_allowed("8.8.8.8")
        assert is_ip_allowed("8.8.8.8", allow_localhost=False)
        assert is_ip_allowed("8.8.8.8", allow_private_networks=False)


@pytest.mark.asyncio
class TestDevModeClient:
    """Test AuthplaneClient dev_mode functionality."""

    async def test_dev_mode_allows_localhost_http(self) -> None:
        """dev_mode=True should allow HTTP localhost without disabling SSRF."""

        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "http://localhost:8000",
                        "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="http://localhost:8000",
                dev_mode=True,
            )

            try:
                assert client.fetch_settings.ssrf_protection is True  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_http is True  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_localhost is True  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_private_networks is True  # pyright: ignore[reportPrivateUsage]
            finally:
                await client.aclose()

    async def test_production_mode_strict_by_default(self) -> None:
        """Production mode (default) should be strict."""

        # SSRF is enabled by default, so we need to mock at ssrf_safe_get level
        # since that's the code path for SSRF-enabled fetch
        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "https://auth.prod.com",
                        "jwks_uri": "https://auth.prod.com/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="https://auth.prod.com",
            )

            try:
                assert client.fetch_settings.ssrf_protection is True  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_http is False  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_localhost is False  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_private_networks is False  # pyright: ignore[reportPrivateUsage]
            finally:
                await client.aclose()

    async def test_granular_override_dev_mode(self) -> None:
        """Explicit parameters should override dev_mode."""

        # dev_mode=True sets relaxed defaults, but explicit fetch settings still
        # override individual behavior for a given fetch type.
        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "https://localhost:8443",
                        "jwks_uri": "https://localhost:8443/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="https://localhost:8443",
                dev_mode=True,
                fetch_settings=FetchSettings(
                    allow_http=False, allow_localhost=True, allow_private_networks=True
                ),
            )

        try:
            assert client.fetch_settings.ssrf_protection is True
            assert client.fetch_settings.allow_http is False
            assert client.fetch_settings.allow_localhost is True
        finally:
            await client.aclose()

    async def test_allow_localhost_without_dev_mode(self) -> None:
        """Can enable localhost without full dev_mode."""

        # allow_localhost=True but ssrf_protection=True by default,
        # so ssrf_safe_get is used. Need to mock it.
        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "https://localhost:8443",
                        "jwks_uri": "https://localhost:8443/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        _settings = FetchSettings(allow_localhost=True)
        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="https://localhost:8443",
                fetch_settings=_settings,
            )

            try:
                assert client.fetch_settings.allow_http is False
                assert client.fetch_settings.allow_localhost is True
                assert client.fetch_settings.allow_private_networks is False
            finally:
                await client.aclose()

    async def test_allow_private_networks_corporate(self) -> None:
        """Corporate deployment with internal Authplane."""

        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "https://auth.internal.corp",
                        "jwks_uri": "https://auth.internal.corp/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        _settings = FetchSettings(allow_private_networks=True)
        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="https://auth.internal.corp",
                fetch_settings=_settings,
            )

            try:
                assert client.fetch_settings.allow_http is False
                assert client.fetch_settings.allow_localhost is False
                assert client.fetch_settings.allow_private_networks is True
            finally:
                await client.aclose()

    @patch.dict(os.environ, {"AUTHPLANE_DEV_MODE": "true"})
    async def test_dev_mode_from_environment(self) -> None:
        """dev_mode should be detected from AUTHPLANE_DEV_MODE env var."""

        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "http://localhost:8000",
                        "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="http://localhost:8000",
            )

            try:
                assert client.fetch_settings.ssrf_protection is True  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_http is True  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_localhost is True  # pyright: ignore[reportPrivateUsage]
            finally:
                await client.aclose()

    @patch.dict(os.environ, {"AUTHPLANE_DEV_MODE": "false"})
    async def test_dev_mode_env_false_ignored(self) -> None:
        """AUTHPLANE_DEV_MODE=false should not enable dev mode."""

        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "https://auth.prod.com",
                        "jwks_uri": "https://auth.prod.com/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="https://auth.prod.com",
            )

            try:
                assert client.fetch_settings.allow_http is False  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_localhost is False  # pyright: ignore[reportPrivateUsage]
            finally:
                await client.aclose()

    async def test_explicit_dev_mode_overrides_env(self) -> None:
        """Explicit dev_mode parameter should override environment."""

        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "https://auth.prod.com",
                        "jwks_uri": "https://auth.prod.com/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with (
            patch.dict(os.environ, {"AUTHPLANE_DEV_MODE": "true"}),
            patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get),
        ):
            client = await AuthplaneClient.create(
                issuer="https://auth.prod.com",
                dev_mode=False,  # Explicit production mode
            )

            try:
                assert client.fetch_settings.allow_http is False  # pyright: ignore[reportPrivateUsage]
                assert client.fetch_settings.allow_localhost is False  # pyright: ignore[reportPrivateUsage]
            finally:
                await client.aclose()


@pytest.mark.asyncio
class TestDevModeIntegration:
    """Integration tests with actual SSRF validation."""

    async def test_localhost_http_blocked_in_production(self) -> None:
        """HTTP localhost metadata discovery should be blocked in production mode."""
        # Discovery must fail because SSRF blocks HTTP localhost
        with pytest.raises(AuthplaneError):
            await AuthplaneClient.create(
                issuer="http://localhost:8000",
            )

    async def test_localhost_http_allowed_in_dev_mode(self) -> None:
        """HTTP localhost metadata discovery should work with SSRF still enabled."""

        async def mock_ssrf_get(url: str, **kwargs: Any) -> HttpResponse:
            if "oauth-authorization-server" in url:
                return HttpResponse(
                    body={
                        "issuer": "http://localhost:8000",
                        "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
                    },
                    headers={},
                    status_code=200,
                )
            return HttpResponse(body={"keys": []}, headers={}, status_code=200)

        with patch("authplane.internal.document_fetcher.ssrf_safe_get", side_effect=mock_ssrf_get):
            client = await AuthplaneClient.create(
                issuer="http://localhost:8000",
                dev_mode=True,
            )

            try:
                jwks = await client.jwks_cache.get()  # pyright: ignore[reportOptionalMemberAccess]
                assert client.fetch_settings.ssrf_protection is True  # pyright: ignore[reportPrivateUsage]
                assert jwks == {"keys": []}
            finally:
                await client.aclose()

    async def test_cloud_metadata_blocked_even_in_dev_mode(self) -> None:
        """Cloud metadata IP should be blocked even with dev_mode=True."""
        # Discovery must fail because 169.254.x is always blocked
        with pytest.raises(AuthplaneError):
            await AuthplaneClient.create(
                issuer="http://169.254.169.254",  # AWS metadata endpoint
                dev_mode=True,
            )
