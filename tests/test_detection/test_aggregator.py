"""알림 집약 파이프라인 테스트.

작성자: 최진호
작성일: 2026-03-13
"""

import time

import pytest

from netwatcher.detection.aggregator import AlertAggregator, MetaAlert
from netwatcher.detection.models import Alert, Severity


def _make_alert(
    engine: str = "port_scan",
    source_ip: str = "10.0.0.1",
    dest_ip: str = "192.168.1.1",
    title: str = "Port Scan Detected",
    severity: Severity = Severity.WARNING,
) -> Alert:
    return Alert(
        engine=engine,
        severity=severity,
        title=title,
        source_ip=source_ip,
        dest_ip=dest_ip,
        confidence=0.8,
    )


class TestDeduplication:
    def test_first_alert_passes(self):
        """첫 번째 알림은 그대로 전달되어야 한다."""
        agg = AlertAggregator()
        alert = _make_alert()
        result = agg.submit(alert)
        assert isinstance(result, Alert)
        assert result.engine == "port_scan"

    def test_duplicate_suppressed(self):
        """동일한 (engine, source, dest, title) 알림은 억제되어야 한다."""
        agg = AlertAggregator()
        alert1 = _make_alert()
        alert2 = _make_alert()
        agg.submit(alert1)
        result = agg.submit(alert2)
        assert result is None

    def test_different_dest_not_suppressed(self):
        """다른 목적지의 알림은 억제되지 않아야 한다."""
        agg = AlertAggregator()
        agg.submit(_make_alert(dest_ip="192.168.1.1"))
        result = agg.submit(_make_alert(dest_ip="192.168.1.2"))
        assert result is not None


class TestAggregation:
    def test_multiple_targets_create_meta_alert(self):
        """같은 소스에서 다른 대상으로의 알림은 MetaAlert로 집약되어야 한다."""
        agg = AlertAggregator()
        agg.submit(_make_alert(dest_ip="192.168.1.1"))
        result = agg.submit(_make_alert(dest_ip="192.168.1.2"))
        assert isinstance(result, MetaAlert)
        assert result.unique_targets == 2
        assert "10.0.0.1" in result.title

    def test_severity_escalation(self):
        """그룹 내 최고 severity가 메타알림에 반영되어야 한다."""
        agg = AlertAggregator()
        agg.submit(_make_alert(dest_ip="1.1.1.1", severity=Severity.WARNING))
        result = agg.submit(_make_alert(dest_ip="2.2.2.2", severity=Severity.CRITICAL))
        assert isinstance(result, MetaAlert)
        assert result.severity == Severity.CRITICAL

    def test_max_samples(self):
        """sample_alerts는 max_samples 이하로 제한되어야 한다."""
        agg = AlertAggregator(max_samples=2)
        for i in range(5):
            agg.submit(_make_alert(dest_ip=f"10.0.0.{i}"))
        result = agg.submit(_make_alert(dest_ip="10.0.0.100"))
        assert isinstance(result, MetaAlert)
        assert len(result.sample_alerts) <= 2


class TestFlush:
    def test_flush_returns_all_groups(self):
        """flush()는 모든 활성 그룹의 MetaAlert를 반환해야 한다."""
        agg = AlertAggregator()
        agg.submit(_make_alert(source_ip="10.0.0.1", dest_ip="1.1.1.1"))
        agg.submit(_make_alert(source_ip="10.0.0.1", dest_ip="2.2.2.2"))
        agg.submit(_make_alert(source_ip="10.0.0.2", dest_ip="3.3.3.3"))

        results = agg.flush()
        assert len(results) == 2
        sources = {r.source_ip for r in results}
        assert sources == {"10.0.0.1", "10.0.0.2"}

    def test_flush_clears_state(self):
        """flush() 후 상태가 초기화되어야 한다."""
        agg = AlertAggregator()
        agg.submit(_make_alert())
        agg.flush()
        result = agg.submit(_make_alert())
        assert isinstance(result, Alert)  # 새로운 첫 알림으로 처리


class TestMetaAlertSerialization:
    def test_to_dict(self):
        """MetaAlert.to_dict()가 올바른 형식을 반환해야 한다."""
        meta = MetaAlert(
            engine="port_scan",
            severity=Severity.WARNING,
            title="test",
            source_ip="10.0.0.1",
            count=5,
            unique_targets=5,
            first_seen=1000.0,
            last_seen=1060.0,
        )
        d = meta.to_dict()
        assert d["engine"] == "port_scan"
        assert d["severity"] == "WARNING"
        assert d["count"] == 5
