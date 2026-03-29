"""엔진 메트릭 수집기 테스트."""

from __future__ import annotations

import pytest

from netwatcher.observability.engine_metrics import EngineMetricsCollector


class TestEngineMetricsCollector:
    """EngineMetricsCollector 테스트 스위트."""

    @pytest.fixture
    def collector(self) -> EngineMetricsCollector:
        return EngineMetricsCollector()

    def test_record_packet(self, collector: EngineMetricsCollector) -> None:
        """패킷 기록이 정상적으로 카운트되는지 검증한다."""
        collector.record_packet("arp_spoof")
        collector.record_packet("arp_spoof")
        collector.record_packet("port_scan")

        m = collector.get_metrics("arp_spoof")
        assert m["packet_count"] == 2
        assert m["alert_count"] == 0

        m2 = collector.get_metrics("port_scan")
        assert m2["packet_count"] == 1

    def test_record_alert(self, collector: EngineMetricsCollector) -> None:
        """알림 기록과 yield rate 계산을 검증한다."""
        for _ in range(1000):
            collector.record_packet("dns_anomaly")
        for _ in range(5):
            collector.record_alert("dns_anomaly")

        m = collector.get_metrics("dns_anomaly")
        assert m["packet_count"] == 1000
        assert m["alert_count"] == 5
        assert m["alert_yield_rate"] == 5.0  # 5 alerts / 1000 packets * 1000

    def test_alert_yield_rate_zero_packets(self, collector: EngineMetricsCollector) -> None:
        """패킷 0건일 때 yield rate가 0인지 검증한다."""
        collector.record_alert("empty_engine")
        m = collector.get_metrics("empty_engine")
        assert m["alert_yield_rate"] == 0.0

    def test_record_feedback_true_positive(self, collector: EngineMetricsCollector) -> None:
        """정탐 피드백 기록을 검증한다."""
        collector.record_feedback("arp_spoof", is_true_positive=True)
        collector.record_feedback("arp_spoof", is_true_positive=True)
        collector.record_feedback("arp_spoof", is_true_positive=False)

        m = collector.get_metrics("arp_spoof")
        assert m["tp_count"] == 2
        assert m["fp_count"] == 1
        assert m["tp_rate"] == pytest.approx(2 / 3, abs=0.001)
        assert m["fp_rate"] == pytest.approx(1 / 3, abs=0.001)

    def test_record_feedback_no_feedback(self, collector: EngineMetricsCollector) -> None:
        """피드백이 없을 때 rate가 None인지 검증한다."""
        collector.record_packet("no_feedback")
        m = collector.get_metrics("no_feedback")
        assert m["fp_rate"] is None
        assert m["tp_rate"] is None

    def test_update_memory_estimate(self, collector: EngineMetricsCollector) -> None:
        """메모리 추정이 양수를 반환하는지 검증한다."""

        class FakeEngine:
            def __init__(self) -> None:
                self.data = [1, 2, 3]
                self.name = "fake"

        engine = FakeEngine()
        collector.update_memory_estimate("fake_engine", engine)
        m = collector.get_metrics("fake_engine")
        assert m["memory_bytes"] > 0

    def test_get_metrics_unknown_engine(self, collector: EngineMetricsCollector) -> None:
        """존재하지 않는 엔진의 메트릭이 빈 dict인지 검증한다."""
        assert collector.get_metrics("nonexistent") == {}

    def test_get_all_metrics(self, collector: EngineMetricsCollector) -> None:
        """모든 엔진 메트릭이 반환되는지 검증한다."""
        collector.record_packet("engine_a")
        collector.record_packet("engine_b")
        collector.record_alert("engine_b")

        all_m = collector.get_all_metrics()
        assert "engine_a" in all_m
        assert "engine_b" in all_m
        assert all_m["engine_b"]["alert_count"] == 1
