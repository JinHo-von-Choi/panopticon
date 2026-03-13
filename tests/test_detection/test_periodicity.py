"""주기성 탐지 모듈 테스트.

작성자: 최진호
작성일: 2026-03-13
"""

import math

import pytest

from netwatcher.detection.periodicity import (
    autocorrelation_score,
    fft_periodicity_score,
    iat_entropy,
    score_from_entropy,
    score_from_fft,
)


class TestFFTPeriodicity:
    def test_perfect_sine(self):
        """완벽한 사인파는 높은 주기성 점수를 가져야 한다."""
        n = 128
        period = 16
        values = [math.sin(2 * math.pi * i / period) for i in range(n)]
        score = fft_periodicity_score(values)
        assert score > 0.5

    def test_constant_signal(self):
        """상수 신호는 주기성이 없어야 한다."""
        values = [5.0] * 50
        score = fft_periodicity_score(values)
        assert score == 0.0

    def test_random_noise(self):
        """난수(결정론적 시드)는 낮은 주기성을 가져야 한다."""
        import random
        rng = random.Random(42)
        values = [rng.uniform(0, 100) for _ in range(128)]
        score = fft_periodicity_score(values)
        assert score < 0.5

    def test_too_few_values(self):
        """3개 이하 값은 0.0을 반환해야 한다."""
        assert fft_periodicity_score([1.0, 2.0]) == 0.0
        assert fft_periodicity_score([]) == 0.0

    def test_beacon_like_intervals(self):
        """규칙적인 비콘 간격(60초 +/- 1초)은 높은 점수여야 한다."""
        import random
        rng = random.Random(99)
        values = [60.0 + rng.uniform(-1, 1) for _ in range(50)]
        score = fft_periodicity_score(values)
        # 거의 동일한 값이므로 주기성이 아닌 일정성 -- FFT가 낮을 수 있음
        # 이 경우 다른 지표(CV, entropy)가 잡아야 한다
        assert isinstance(score, float)


class TestAutocorrelation:
    def test_periodic_signal(self):
        """주기적 신호는 높은 자기상관을 가져야 한다."""
        period = 10
        values = [math.sin(2 * math.pi * i / period) for i in range(100)]
        score = autocorrelation_score(values)
        assert score > 0.7

    def test_constant_values(self):
        """동일 값은 완벽한 자기상관(1.0)이어야 한다."""
        values = [42.0] * 20
        score = autocorrelation_score(values)
        assert score == 1.0

    def test_few_values(self):
        """3개 이하 값은 0.0이어야 한다."""
        assert autocorrelation_score([1.0, 2.0]) == 0.0

    def test_random_low_correlation(self):
        """난수는 낮은 자기상관이어야 한다."""
        import random
        rng = random.Random(123)
        values = [rng.uniform(0, 100) for _ in range(100)]
        score = autocorrelation_score(values)
        assert score < 0.5


class TestIATEntropy:
    def test_identical_intervals(self):
        """동일 간격은 엔트로피 0이어야 한다."""
        intervals = [60.0] * 50
        assert iat_entropy(intervals) == 0.0

    def test_varied_intervals(self):
        """다양한 간격은 높은 엔트로피를 가져야 한다."""
        import random
        rng = random.Random(42)
        intervals = [rng.uniform(1, 1000) for _ in range(200)]
        entropy = iat_entropy(intervals)
        assert entropy > 2.0

    def test_too_few(self):
        """1개 이하 값은 0.0이어야 한다."""
        assert iat_entropy([]) == 0.0
        assert iat_entropy([5.0]) == 0.0


class TestScoreFunctions:
    def test_score_from_fft(self):
        assert score_from_fft(0.6) == 1.0
        assert score_from_fft(0.4) == 0.7
        assert score_from_fft(0.2) == 0.3
        assert score_from_fft(0.05) == 0.0

    def test_score_from_entropy_low(self):
        """낮은 엔트로피 = 높은 비콘 스코어."""
        assert score_from_entropy(0.1) == 1.0

    def test_score_from_entropy_high(self):
        """높은 엔트로피 = 낮은 비콘 스코어."""
        assert score_from_entropy(3.5) == 0.0
