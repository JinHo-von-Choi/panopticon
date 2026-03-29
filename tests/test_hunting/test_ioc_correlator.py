"""IOCCorrelator 테스트."""

from __future__ import annotations

import pytest
import pytest_asyncio

from netwatcher.hunting.ioc_correlator import IOCCorrelator, IOCReport, _max_severity
from netwatcher.storage.repositories import EventRepository


class TestMaxSeverity:
    def test_critical_wins(self):
        assert _max_severity("INFO", "CRITICAL") == "CRITICAL"
        assert _max_severity("CRITICAL", "INFO") == "CRITICAL"

    def test_warning_over_info(self):
        assert _max_severity("INFO", "WARNING") == "WARNING"

    def test_same_severity(self):
        assert _max_severity("WARNING", "WARNING") == "WARNING"


class TestIOCReport:
    def test_empty_report_serializes(self):
        report = IOCReport(ioc_type="ip", ioc_value="10.0.0.1")
        d = report.to_dict()
        assert d["ioc_type"] == "ip"
        assert d["ioc_value"] == "10.0.0.1"
        assert d["event_count"] == 0
        assert d["first_seen"] is None
        assert d["severity_max"] == "INFO"

    def test_report_with_timestamps(self):
        from datetime import datetime, timezone
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        report = IOCReport(
            ioc_type="domain",
            ioc_value="evil.com",
            first_seen=ts,
            last_seen=ts,
            event_count=3,
            severity_max="CRITICAL",
        )
        d = report.to_dict()
        assert d["event_count"] == 3
        assert d["first_seen"] is not None
        assert d["severity_max"] == "CRITICAL"


@pytest.mark.asyncio
class TestIOCCorrelatorWithDB:
    """DB fixture를 사용하는 통합 테스트."""

    async def test_correlate_ip_no_events(self, event_repo: EventRepository):
        correlator = IOCCorrelator(event_repo)
        report = await correlator.correlate_ip("192.168.99.99")
        assert report.event_count == 0
        assert report.related_ips == []

    async def test_correlate_ip_with_events(self, event_repo: EventRepository):
        await event_repo.insert(
            engine="port_scan",
            severity="WARNING",
            title="Port scan detected",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.10",
            mitre_attack_id="T1046",
        )
        await event_repo.insert(
            engine="threat_intel",
            severity="CRITICAL",
            title="Known malicious IP",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.20",
        )

        correlator = IOCCorrelator(event_repo)
        report = await correlator.correlate_ip("10.0.0.5")

        assert report.event_count == 2
        assert report.severity_max == "CRITICAL"
        assert "port_scan" in report.engines_triggered
        assert "threat_intel" in report.engines_triggered
        assert len(report.timeline) == 2

    async def test_correlate_domain_with_events(self, event_repo: EventRepository):
        await event_repo.insert(
            engine="dns_anomaly",
            severity="WARNING",
            title="Suspicious DNS: evil.example.com",
            description="High entropy domain",
            source_ip="10.0.0.1",
        )

        correlator = IOCCorrelator(event_repo)
        report = await correlator.correlate_domain("evil.example.com")

        assert report.event_count == 1
        assert "dns_anomaly" in report.engines_triggered

    async def test_find_related_ip(self, event_repo: EventRepository):
        await event_repo.insert(
            engine="port_scan",
            severity="INFO",
            title="Scan",
            source_ip="10.0.0.1",
        )

        correlator = IOCCorrelator(event_repo)
        results = await correlator.find_related("ip", "10.0.0.1")
        assert len(results) == 1

    async def test_find_related_unknown_type(self, event_repo: EventRepository):
        correlator = IOCCorrelator(event_repo)
        results = await correlator.find_related("ja3", "abc123")
        assert isinstance(results, list)
