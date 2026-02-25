"""Tests for rate limiter."""

import time
from unittest.mock import patch

from netwatcher.alerts.rate_limiter import RateLimiter


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter(window_seconds=300, max_count=3)
        assert rl.allow("key1") is True
        assert rl.allow("key1") is True
        assert rl.allow("key1") is True

    def test_blocks_over_limit(self):
        rl = RateLimiter(window_seconds=300, max_count=2)
        assert rl.allow("key1") is True
        assert rl.allow("key1") is True
        assert rl.allow("key1") is False

    def test_different_keys_independent(self):
        rl = RateLimiter(window_seconds=300, max_count=1)
        assert rl.allow("key1") is True
        assert rl.allow("key2") is True
        assert rl.allow("key1") is False
        assert rl.allow("key2") is False

    def test_window_expiry(self):
        rl = RateLimiter(window_seconds=1, max_count=1)
        assert rl.allow("key1") is True
        assert rl.allow("key1") is False

        # Simulate time passing
        with patch("netwatcher.alerts.rate_limiter.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            assert rl.allow("key1") is True

    def test_reset(self):
        rl = RateLimiter(window_seconds=300, max_count=1)
        assert rl.allow("key1") is True
        assert rl.allow("key1") is False
        rl.reset("key1")
        assert rl.allow("key1") is True
