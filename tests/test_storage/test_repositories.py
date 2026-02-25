"""Tests for storage repositories."""

import pytest


@pytest.mark.asyncio
async def test_event_insert_and_list(event_repo):
    event_id = await event_repo.insert(
        engine="test_engine",
        severity="WARNING",
        title="Test Alert",
        description="Test description",
        source_ip="192.168.1.10",
        packet_info={"layers": ["IP", "TCP"], "src_port": 12345, "dst_port": 80},
    )
    assert event_id is not None

    events = await event_repo.list_recent(limit=10)
    assert len(events) == 1
    assert events[0]["title"] == "Test Alert"
    assert events[0]["severity"] == "WARNING"
    assert events[0]["packet_info"]["src_port"] == 12345


@pytest.mark.asyncio
async def test_event_get_by_id(event_repo):
    eid = await event_repo.insert(
        engine="test", severity="CRITICAL", title="Detail Test",
        metadata={"key": "value"},
        packet_info={"layers": ["ARP"], "arp_op": "reply"},
    )
    ev = await event_repo.get_by_id(eid)
    assert ev is not None
    assert ev["metadata"]["key"] == "value"
    assert ev["packet_info"]["arp_op"] == "reply"


@pytest.mark.asyncio
async def test_event_count(event_repo):
    await event_repo.insert(engine="e1", severity="CRITICAL", title="t1")
    await event_repo.insert(engine="e2", severity="WARNING", title="t2")
    await event_repo.insert(engine="e3", severity="CRITICAL", title="t3")

    total = await event_repo.count()
    assert total == 3

    critical = await event_repo.count(severity="CRITICAL")
    assert critical == 2


@pytest.mark.asyncio
async def test_event_resolve(event_repo):
    eid = await event_repo.insert(engine="e1", severity="INFO", title="t1")
    await event_repo.resolve(eid)
    events = await event_repo.list_recent()
    assert events[0]["resolved"] == 1


@pytest.mark.asyncio
async def test_device_upsert_with_vendor(device_repo):
    await device_repo.upsert(
        "aa:bb:cc:dd:ee:01", "192.168.1.10",
        vendor="Apple", hostname="macbook.local",
        packet_bytes=100, os_hint="macOS/iOS",
    )
    await device_repo.upsert("aa:bb:cc:dd:ee:01", "192.168.1.10", packet_bytes=200)

    device = await device_repo.get_by_mac("aa:bb:cc:dd:ee:01")
    assert device is not None
    assert device["total_packets"] == 2
    assert device["total_bytes"] == 300
    assert device["vendor"] == "Apple"
    assert device["hostname"] == "macbook.local"
    assert device["os_hint"] == "macOS/iOS"


@pytest.mark.asyncio
async def test_device_list_all(device_repo):
    await device_repo.upsert("aa:bb:cc:dd:ee:01", "192.168.1.1")
    await device_repo.upsert("aa:bb:cc:dd:ee:02", "192.168.1.2")

    devices = await device_repo.list_all()
    assert len(devices) == 2


@pytest.mark.asyncio
async def test_device_open_ports(device_repo):
    await device_repo.upsert("aa:bb:cc:dd:ee:01", "192.168.1.1")
    await device_repo.update_open_ports("aa:bb:cc:dd:ee:01", [80, 443, 22])

    device = await device_repo.get_by_mac("aa:bb:cc:dd:ee:01")
    assert device["open_ports"] == [22, 80, 443]


@pytest.mark.asyncio
async def test_traffic_stats(stats_repo):
    await stats_repo.insert(
        timestamp="2024-01-01T00:00:00Z",
        total_packets=100,
        total_bytes=50000,
        tcp_count=60,
        udp_count=30,
        arp_count=5,
        dns_count=5,
    )

    recent = await stats_repo.recent(minutes=60)
    assert len(recent) == 1

    summary = await stats_repo.summary()
    assert summary["total_packets"] == 100
    assert summary["tcp_count"] == 60
