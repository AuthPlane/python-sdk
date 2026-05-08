"""Tests for FetchSettings and from_dev_mode factory."""

from authplane.net import FetchSettings


class TestFetchSettingsDefaults:
    """Test default FetchSettings values."""

    def test_defaults_are_strict(self) -> None:
        """Default settings should enforce strict production rules."""
        settings = FetchSettings()
        assert settings.ssrf_protection is True
        assert settings.allow_http is False
        assert settings.allow_localhost is False
        assert settings.allow_private_networks is False
        assert settings.timeout == 10.0


class TestFromDevMode:
    """Test FetchSettings.from_dev_mode factory method."""

    def test_dev_mode_true_keeps_ssrf_protection_enabled(self) -> None:
        """Dev mode should keep SSRF protection enabled and only relax allow-rules."""
        settings = FetchSettings.from_dev_mode(True)
        assert settings.ssrf_protection is True

    def test_dev_mode_true_allows_http(self) -> None:
        """Dev mode should allow HTTP (not just HTTPS)."""
        settings = FetchSettings.from_dev_mode(True)
        assert settings.allow_http is True

    def test_dev_mode_true_allows_localhost(self) -> None:
        """Dev mode should allow localhost addresses."""
        settings = FetchSettings.from_dev_mode(True)
        assert settings.allow_localhost is True

    def test_dev_mode_true_allows_private_networks(self) -> None:
        """Dev mode should allow private network addresses."""
        settings = FetchSettings.from_dev_mode(True)
        assert settings.allow_private_networks is True

    def test_dev_mode_false_enables_ssrf_protection(self) -> None:
        """Production mode should enable SSRF protection."""
        settings = FetchSettings.from_dev_mode(False)
        assert settings.ssrf_protection is True

    def test_dev_mode_false_blocks_http(self) -> None:
        """Production mode should require HTTPS."""
        settings = FetchSettings.from_dev_mode(False)
        assert settings.allow_http is False

    def test_dev_mode_false_blocks_localhost(self) -> None:
        """Production mode should block localhost."""
        settings = FetchSettings.from_dev_mode(False)
        assert settings.allow_localhost is False

    def test_dev_mode_false_blocks_private_networks(self) -> None:
        """Production mode should block private networks."""
        settings = FetchSettings.from_dev_mode(False)
        assert settings.allow_private_networks is False

    def test_timeout_same_for_both_modes(self) -> None:
        """Timeout should be the same regardless of mode."""
        dev = FetchSettings.from_dev_mode(True)
        prod = FetchSettings.from_dev_mode(False)
        assert dev.timeout == 10.0
        assert prod.timeout == 10.0

    def test_dev_mode_is_frozen(self) -> None:
        """Settings returned by from_dev_mode should be immutable."""
        settings = FetchSettings.from_dev_mode(True)
        import pytest

        with pytest.raises(AttributeError):
            settings.allow_http = False  # type: ignore[misc]
