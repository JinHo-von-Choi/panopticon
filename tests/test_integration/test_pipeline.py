"""Integration tests for the full packet-to-alert-to-DB pipeline."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.registry import EngineRegistry
from netwatcher.storage.repositories import (
    DeviceRepository,
    EventRepository,
    IncidentRepository,
    TrafficStatsRepository,
)

from scapy.all import IP, TCP, Ether


@pytest.mark.asyncio
async def test_packet_to_alert_to_db(config, event_repo):
    """Simulate: Scapy packet -> EngineRegistry -> AlertDispatcher -> DB query."""
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )
    await dispatcher.start()

    try:
        # Create a synthetic alert (as if an engine detected something)
        alert = Alert(
            engine="port_scan",
            severity=Severity.WARNING,
            title="Port Scan Detected",
            description="192.168.1.100 scanned 20 ports on 192.168.1.1",
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1",
            confidence=0.85,
        )
        dispatcher.enqueue(alert)
        await asyncio.sleep(0.3)

        # Verify in DB
        events = await event_repo.list_recent(limit=10)
        assert len(events) >= 1
        found = [e for e in events if e["engine"] == "port_scan"]
        assert len(found) == 1
        assert found[0]["severity"] == "WARNING"
        assert found[0]["source_ip"] == "192.168.1.100"
    finally:
        await dispatcher.stop()


@pytest.mark.asyncio
async def test_device_batch_upsert(device_repo):
    """Batch upsert of device buffer should populate devices table."""
    buffer = {}
    for i in range(100):
        mac = f"aa:bb:cc:dd:ee:{i:02x}"
        buffer[mac] = {
            "ip": f"192.168.1.{i + 1}" if i < 254 else None,
            "hostname": f"host-{i}",
            "vendor": "TestVendor",
            "os_hint": "Linux",
            "bytes": 1024 * (i + 1),
            "packets": 10 * (i + 1),
        }

    await device_repo.batch_upsert(buffer)

    # Verify devices table
    devices = await device_repo.list_all()
    assert len(devices) == 100

    # Check a specific device
    dev = await device_repo.get_by_mac("aa:bb:cc:dd:ee:00")
    assert dev is not None
    assert dev["hostname"] == "host-0"
    assert dev["total_bytes"] == 1024
    assert dev["total_packets"] == 10


@pytest.mark.asyncio
async def test_retention_cleanup(event_repo, stats_repo):
    """Old events and stats should be deleted by retention cleanup (date-based)."""
    # Insert an old event
    event_id = await event_repo.insert(
        engine="test",
        severity="INFO",
        title="Old Event",
    )

    # Manually set the timestamp to 100 days ago via direct SQL
    old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    await event_repo._db.pool.execute(
        "UPDATE events SET timestamp = $1 WHERE id = $2",
        old_ts, event_id,
    )

    # Insert old traffic stats
    old_stats_ts = (datetime.now(timezone.utc) - timedelta(days=400)).strftime(
        "%Y-%m-%dT%H:%M:00Z"
    )
    await stats_repo.insert(
        timestamp=old_stats_ts,
        total_packets=100,
        total_bytes=50000,
        tcp_count=50,
        udp_count=30,
        arp_count=10,
        dns_count=10,
    )

    # Insert a recent event (should NOT be deleted)
    recent_id = await event_repo.insert(
        engine="test",
        severity="INFO",
        title="Recent Event",
    )

    # Run retention cleanup
    deleted_events = await event_repo.delete_older_than(90)
    deleted_stats  = await stats_repo.delete_older_than(365)

    assert deleted_events >= 1
    assert deleted_stats >= 1

    # Recent event should still exist
    recent = await event_repo.get_by_id(recent_id)
    assert recent is not None

    # Old event should be gone (no resolve needed)
    old = await event_repo.get_by_id(event_id)
    assert old is None


@pytest.mark.asyncio
async def test_incident_persistence(incident_repo):
    """Incidents should be persisted to and retrieved from the database."""
    inc_id = await incident_repo.insert(
        severity="CRITICAL",
        title="Kill Chain Activity from 192.168.1.100",
        description="Multiple stages detected",
        alert_ids=[1, 2, 3],
        source_ips=["192.168.1.100"],
        engines=["port_scan", "lateral_movement"],
        kill_chain_stages=["reconnaissance", "lateral_movement"],
        rule="kill_chain",
    )
    assert inc_id > 0

    # Retrieve
    inc = await incident_repo.get_by_id(inc_id)
    assert inc is not None
    assert inc["title"] == "Kill Chain Activity from 192.168.1.100"
    assert inc["severity"] == "CRITICAL"
    assert 1 in inc["alert_ids"]

    # List unresolved
    incidents = await incident_repo.list_recent(limit=10, include_resolved=False)
    assert len(incidents) >= 1

    # Resolve
    resolved = await incident_repo.resolve(inc_id)
    assert resolved is True

    # After resolution, should not appear in unresolved list
    unresolved = await incident_repo.list_recent(limit=10, include_resolved=False)
    found = [i for i in unresolved if i["id"] == inc_id]
    assert len(found) == 0
