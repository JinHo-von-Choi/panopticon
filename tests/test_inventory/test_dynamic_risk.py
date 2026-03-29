"""DynamicRiskScorer 테스트: 알림 기록, 위험 점수 계산."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatcher.inventory.dynamic_risk import DynamicRiskScorer


# ---------------------------------------------------------------------------
# 기본 동작
# ---------------------------------------------------------------------------

class TestBasicBehavior:
    def test_no_alerts_returns_static_only(self):
        """알림 이력이 없으면 정적 점수만 반영."""
        scorer = DynamicRiskScorer()
        # static_score=50 → 정규화: 50/20 = 2.5
        score = scorer.calculate_risk("10.0.0.1", static_score=50.0)
        assert score == pytest.approx(2.5, abs=0.01)

    def test_zero_static_zero_alerts(self):
        scorer = DynamicRiskScorer()
        score  = scorer.calculate_risk("10.0.0.1", static_score=0.0)
        assert score == 0.0

    def test_static_score_clamped_at_5(self):
        """정적 점수 100은 5.0으로 정규화."""
        scorer = DynamicRiskScorer()
        score  = scorer.calculate_risk("10.0.0.1", static_score=100.0)
        assert score == pytest.approx(5.0, abs=0.01)


# ---------------------------------------------------------------------------
# 알림 기록 및 동적 점수
# ---------------------------------------------------------------------------

class TestAlertRecording:
    def test_single_alert_increases_score(self):
        scorer = DynamicRiskScorer()
        scorer.record_alert("10.0.0.1", "high", "port_scan")
        score = scorer.calculate_risk("10.0.0.1", static_score=0.0)
        assert score > 0.0

    def test_multiple_alerts_higher_score(self):
        scorer = DynamicRiskScorer()
        scorer.record_alert("10.0.0.1", "high", "port_scan")
        score1 = scorer.calculate_risk("10.0.0.1")

        scorer.record_alert("10.0.0.1", "critical", "c2_beaconing")
        score2 = scorer.calculate_risk("10.0.0.1")
        assert score2 > score1

    def test_critical_higher_than_low(self):
        """critical 알림은 low 알림보다 높은 점수를 부여."""
        scorer_crit = DynamicRiskScorer()
        scorer_crit.record_alert("10.0.0.1", "critical", "engine_a")
        score_crit = scorer_crit.calculate_risk("10.0.0.1")

        scorer_low = DynamicRiskScorer()
        scorer_low.record_alert("10.0.0.1", "low", "engine_a")
        score_low = scorer_low.calculate_risk("10.0.0.1")

        assert score_crit > score_low


# ---------------------------------------------------------------------------
# 시간 감쇠
# ---------------------------------------------------------------------------

class TestTimeDecay:
    def test_older_alerts_contribute_less(self):
        """오래된 알림은 감쇠되어 점수 기여가 줄어든다."""
        now = time.time()

        # 1시간 전 알림 기록 후, 현재 시각에서 점수 계산
        scorer_old = DynamicRiskScorer(decay_half_life=3600.0)
        with patch("netwatcher.inventory.dynamic_risk.time") as mock_time:
            mock_time.time.return_value = now - 3600.0
            scorer_old.record_alert("10.0.0.1", "high", "engine_a")
        with patch("netwatcher.inventory.dynamic_risk.time") as mock_time:
            mock_time.time.return_value = now
            score_old = scorer_old.calculate_risk("10.0.0.1")

        # 방금 알림 기록 후, 같은 현재 시각에서 점수 계산
        scorer_new = DynamicRiskScorer(decay_half_life=3600.0)
        with patch("netwatcher.inventory.dynamic_risk.time") as mock_time:
            mock_time.time.return_value = now
            scorer_new.record_alert("10.0.0.1", "high", "engine_a")
        with patch("netwatcher.inventory.dynamic_risk.time") as mock_time:
            mock_time.time.return_value = now
            score_new = scorer_new.calculate_risk("10.0.0.1")

        assert score_new > score_old


# ---------------------------------------------------------------------------
# 엔진 다양성 보너스
# ---------------------------------------------------------------------------

class TestDiversityBonus:
    def test_multi_engine_higher_score(self):
        """여러 엔진에서 알림이 오면 다양성 보너스로 점수 상승."""
        scorer_single = DynamicRiskScorer()
        scorer_single.record_alert("10.0.0.1", "medium", "engine_a")
        scorer_single.record_alert("10.0.0.1", "medium", "engine_a")
        score_single = scorer_single.calculate_risk("10.0.0.1")

        scorer_multi = DynamicRiskScorer()
        scorer_multi.record_alert("10.0.0.1", "medium", "engine_a")
        scorer_multi.record_alert("10.0.0.1", "medium", "engine_b")
        score_multi = scorer_multi.calculate_risk("10.0.0.1")

        assert score_multi > score_single


# ---------------------------------------------------------------------------
# 점수 범위
# ---------------------------------------------------------------------------

class TestScoreRange:
    def test_score_never_exceeds_10(self):
        scorer = DynamicRiskScorer()
        for i in range(100):
            scorer.record_alert("10.0.0.1", "critical", f"engine_{i}")
        score = scorer.calculate_risk("10.0.0.1", static_score=100.0)
        assert score <= 10.0

    def test_score_never_negative(self):
        scorer = DynamicRiskScorer()
        score  = scorer.calculate_risk("10.0.0.1", static_score=-10.0)
        assert score >= 0.0


# ---------------------------------------------------------------------------
# get_high_risk
# ---------------------------------------------------------------------------

class TestGetHighRisk:
    def test_empty_when_no_alerts(self):
        scorer = DynamicRiskScorer()
        assert scorer.get_high_risk() == []

    def test_returns_high_risk_hosts(self):
        scorer = DynamicRiskScorer()
        # 높은 위험 호스트
        for _ in range(20):
            scorer.record_alert("10.0.0.1", "critical", "engine_a")
        # 낮은 위험 호스트
        scorer.record_alert("10.0.0.2", "info", "engine_b")

        high = scorer.get_high_risk(threshold=5.0)
        ips  = [d["ip"] for d in high]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" not in ips

    def test_result_sorted_by_score_desc(self):
        scorer = DynamicRiskScorer()
        for _ in range(20):
            scorer.record_alert("10.0.0.1", "critical", "engine_a")
        for _ in range(10):
            scorer.record_alert("10.0.0.2", "critical", "engine_b")

        high = scorer.get_high_risk(threshold=1.0)
        if len(high) >= 2:
            assert high[0]["risk_score"] >= high[1]["risk_score"]

    def test_result_dict_structure(self):
        scorer = DynamicRiskScorer()
        for _ in range(20):
            scorer.record_alert("10.0.0.1", "critical", "engine_a")
        high = scorer.get_high_risk(threshold=1.0)
        if high:
            item = high[0]
            assert "ip" in item
            assert "risk_score" in item
            assert "alert_count" in item


# ---------------------------------------------------------------------------
# get_risk_summary
# ---------------------------------------------------------------------------

class TestGetRiskSummary:
    def test_summary_no_alerts(self):
        scorer  = DynamicRiskScorer()
        summary = scorer.get_risk_summary("10.0.0.1")
        assert summary["risk_score"] == 0.0
        assert summary["alert_count"] == 0
        assert summary["engines"] == []

    def test_summary_with_alerts(self):
        scorer = DynamicRiskScorer()
        scorer.record_alert("10.0.0.1", "high", "port_scan")
        scorer.record_alert("10.0.0.1", "medium", "dns_anomaly")
        summary = scorer.get_risk_summary("10.0.0.1")
        assert summary["alert_count"] == 2
        assert set(summary["engines"]) == {"port_scan", "dns_anomaly"}
        assert summary["risk_score"] > 0.0
