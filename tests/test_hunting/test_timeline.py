"""ThreatTimeline 테스트."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from netwatcher.hunting.timeline import ThreatTimeline, TimelineEntry
from netwatcher.storage.repositories import EventRepository


class TestTimelineEntry:
    def test_to_dict(self):
        ts = datetime(2026, 3, 29, 12, 0, 0, tzinfo=timezone.utc)
        entry = TimelineEntry(
            timestamp=ts,
            event_type="Port scan detected",
            engine="port_scan",
            severity="WARNING",
            description="Scan from 10.0.0.5",
            metadata={"source_ip": "10.0.0.5"},
        )
        d = entry.to_dict()
        assert d["engine"] == "port_scan"
        assert d["severity"] == "WARNING"
        assert "2026-03-29" in d["timestamp"]


@pytest.mark.asyncio
class TestThreatTimelineWithDB:
    async def test_build_empty(self, event_repo: EventRepository):
        timeline = ThreatTimeline(event_repo)
        entries = await timeline.build("ip", "192.168.99.99", hours=24)
        assert entries == []

    async def test_build_ip_timeline(self, event_repo: EventRepository):
        await event_repo.insert(
            engine="port_scan",
            severity="WARNING",
            title="Port scan detected",
            description="Multiple ports scanned",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.10",
            mitre_attack_id="T1046",
        )
        await event_repo.insert(
            engine="threat_intel",
            severity="CRITICAL",
            title="Known malicious IP",
            source_ip="10.0.0.5",
        )
        # 관계없는 이벤트
        await event_repo.insert(
            engine="dns_anomaly",
            severity="INFO",
            title="Normal DNS",
            source_ip="10.0.0.99",
        )

        timeline = ThreatTimeline(event_repo)
        entries = await timeline.build("ip", "10.0.0.5", hours=1)

        assert len(entries) == 2
        assert entries[0].engine == "port_scan"
        assert entries[1].engine == "threat_intel"
        # 시간순 정렬 확인
        assert entries[0].timestamp <= entries[1].timestamp

    async def test_build_domain_timeline(self, event_repo: EventRepository):
        await event_repo.insert(
            engine="dns_anomaly",
            severity="WARNING",
            title="Suspicious DNS query: evil.example.com",
            description="High entropy",
            source_ip="10.0.0.1",
        )

        timeline = ThreatTimeline(event_repo)
        entries = await timeline.build("domain", "evil.example.com", hours=1)

        assert len(entries) == 1
        assert entries[0].engine == "dns_anomaly"

    async def test_build_unsupported_type(self, event_repo: EventRepository):
        timeline = ThreatTimeline(event_repo)
        entries = await timeline.build("mac", "aa:bb:cc:dd:ee:ff", hours=1)
        assert entries == []

    async def test_timeline_entry_metadata(self, event_repo: EventRepository):
        await event_repo.insert(
            engine="port_scan",
            severity="WARNING",
            title="Port scan",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            mitre_attack_id="T1046",
        )

        timeline = ThreatTimeline(event_repo)
        entries = await timeline.build("ip", "10.0.0.1", hours=1)

        assert len(entries) == 1
        meta = entries[0].metadata
        assert meta["source_ip"] == "10.0.0.1"
        assert meta["dest_ip"] == "10.0.0.2"
        assert meta["mitre_attack_id"] == "T1046"
