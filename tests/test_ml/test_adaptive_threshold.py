"""AdaptiveThreshold 단위 테스트.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import pytest

from netwatcher.ml.adaptive_threshold import AdaptiveThreshold


class TestAdaptiveThreshold:
    """AdaptiveThreshold 핵심 동작 검증."""

    def test_initial_value(self):
        """초기값이 올바르게 설정된다."""
        t = AdaptiveThreshold(initial=0.7)
        assert t.current == 0.7

    def test_false_positive_increases_threshold(self):
        """오탐 피드백이 임계값을 상향한다."""
        t = AdaptiveThreshold(initial=0.5, step=0.1)
        t.adjust(is_false_positive=True)
        assert t.current == pytest.approx(0.6)

    def test_true_positive_decreases_threshold(self):
        """정탐 피드백이 임계값을 하향한다."""
        t = AdaptiveThreshold(initial=0.5, step=0.1)
        t.adjust(is_false_positive=False)
        assert t.current == pytest.approx(0.4)

    def test_does_not_exceed_max(self):
        """임계값이 max_val을 초과하지 않는다."""
        t = AdaptiveThreshold(initial=0.9, max_val=0.95, step=0.1)
        t.adjust(is_false_positive=True)
        assert t.current == 0.95

    def test_does_not_go_below_min(self):
        """임계값이 min_val 미만으로 내려가지 않는다."""
        t = AdaptiveThreshold(initial=0.35, min_val=0.3, step=0.1)
        t.adjust(is_false_positive=False)
        assert t.current == 0.3

    def test_multiple_adjustments(self):
        """연속 조정이 누적된다."""
        t = AdaptiveThreshold(initial=0.5, step=0.05, min_val=0.0, max_val=1.0)
        for _ in range(3):
            t.adjust(is_false_positive=True)
        assert t.current == pytest.approx(0.65)

    def test_mixed_feedback(self):
        """오탐/정탐 혼합 피드백이 올바르게 동작한다."""
        t = AdaptiveThreshold(initial=0.5, step=0.1, min_val=0.0, max_val=1.0)
        t.adjust(is_false_positive=True)   # 0.6
        t.adjust(is_false_positive=True)   # 0.7
        t.adjust(is_false_positive=False)  # 0.6
        assert t.current == pytest.approx(0.6)

    def test_custom_parameters(self):
        """사용자 정의 파라미터가 올바르게 적용된다."""
        t = AdaptiveThreshold(initial=0.8, min_val=0.5, max_val=0.9, step=0.03)
        assert t.current == 0.8
        t.adjust(is_false_positive=True)
        assert t.current == pytest.approx(0.83)
