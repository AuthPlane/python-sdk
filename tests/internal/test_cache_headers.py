"""Tests for HTTP cache header parsing (RFC 7234)."""

import time

import pytest

from authplane.internal.cache_headers import parse_expires_at
from authplane.internal.fetch_result import FetchResult


class TestParseExpiresAt:
    """Tests for parse_expires_at per RFC 7234 Section 4.2.2."""

    def test_max_age_parsed_correctly(self) -> None:
        """Cache-Control max-age returns absolute timestamp."""
        before = time.time()
        result = parse_expires_at({"cache-control": "max-age=300"})
        after = time.time()

        assert result is not None
        assert before + 300 <= result <= after + 300

    def test_max_age_zero(self) -> None:
        """Cache-Control max-age=0 returns a timestamp roughly equal to now."""
        before = time.time()
        result = parse_expires_at({"cache-control": "max-age=0"})
        after = time.time()

        assert result is not None
        assert before <= result <= after

    def test_no_store_returns_zero(self) -> None:
        """Cache-Control no-store returns 0.0 (already expired)."""
        result = parse_expires_at({"cache-control": "no-store"})
        assert result == 0.0

    def test_no_cache_returns_zero(self) -> None:
        """Cache-Control no-cache returns 0.0 (already expired)."""
        result = parse_expires_at({"cache-control": "no-cache"})
        assert result == 0.0

    def test_max_age_with_other_directives(self) -> None:
        """max-age is extracted even alongside other directives."""
        before = time.time()
        result = parse_expires_at({"cache-control": "public, max-age=600, must-revalidate"})
        after = time.time()

        assert result is not None
        assert before + 600 <= result <= after + 600

    def test_no_store_takes_precedence_over_max_age(self) -> None:
        """no-store is checked before max-age."""
        result = parse_expires_at({"cache-control": "no-store, max-age=300"})
        assert result == 0.0

    def test_expires_header_parsed(self) -> None:
        """Expires header is parsed to absolute timestamp."""
        # Use a date far in the future
        result = parse_expires_at({"expires": "Thu, 01 Jan 2099 00:00:00 GMT"})

        assert result is not None
        assert result > time.time()

    def test_expires_in_past_returns_past_timestamp(self) -> None:
        """Expires in the past returns a timestamp before now."""
        result = parse_expires_at({"expires": "Thu, 01 Jan 2020 00:00:00 GMT"})

        assert result is not None
        assert result < time.time()

    def test_max_age_takes_precedence_over_expires(self) -> None:
        """Cache-Control max-age takes precedence over Expires (RFC 7234 §4.2.2)."""
        before = time.time()
        result = parse_expires_at(
            {
                "cache-control": "max-age=60",
                "expires": "Thu, 01 Jan 2099 00:00:00 GMT",
            }
        )
        after = time.time()

        # Should use max-age=60, not the far-future Expires
        assert result is not None
        assert before + 60 <= result <= after + 60

    def test_no_cache_headers_returns_none(self) -> None:
        """No cache headers returns None."""
        result = parse_expires_at({})
        assert result is None

    def test_unrelated_headers_returns_none(self) -> None:
        """Headers without cache info returns None."""
        result = parse_expires_at({"content-type": "application/json"})
        assert result is None

    def test_malformed_max_age_falls_through_to_expires(self) -> None:
        """Bad max-age falls through to Expires."""
        result = parse_expires_at(
            {
                "cache-control": "max-age=notanumber",
                "expires": "Thu, 01 Jan 2099 00:00:00 GMT",
            }
        )

        assert result is not None
        assert result > time.time()

    def test_malformed_expires_returns_none(self) -> None:
        """Malformed Expires with no Cache-Control returns None."""
        result = parse_expires_at({"expires": "not-a-date"})
        assert result is None

    def test_empty_cache_control_falls_through(self) -> None:
        """Empty Cache-Control value falls through to Expires."""
        result = parse_expires_at(
            {
                "cache-control": "",
                "expires": "Thu, 01 Jan 2099 00:00:00 GMT",
            }
        )

        assert result is not None
        assert result > time.time()


class TestFetchResult:
    """Tests for FetchResult dataclass."""

    def test_defaults(self) -> None:
        """expires_at defaults to None."""
        result = FetchResult(document={"key": "value"})
        assert result.document == {"key": "value"}
        assert result.expires_at is None

    def test_with_expires_at(self) -> None:
        """expires_at is stored when provided."""
        result = FetchResult(document={"key": "value"}, expires_at=12345.0)
        assert result.expires_at == 12345.0

    def test_frozen(self) -> None:
        """FetchResult is immutable."""
        result = FetchResult(document={"key": "value"})
        with pytest.raises(AttributeError):
            result.expires_at = 999.0  # type: ignore[misc]
