"""Tests for web API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.storage.repositories import (
    DeviceRepository,
    EventRepository,
    TrafficStatsRepository,
)
from netwatcher.web.server import create_app


@pytest.fixture
def app(config, event_repo, device_repo, stats_repo):
    dispatcher = AlertDispatcher.__new__(AlertDispatcher)
    dispatcher._config = config
    dispatcher._event_repo = event_repo
    dispatcher._queue = None
    dispatcher._task = None
    dispatcher._rate_limiter = None
    dispatcher._channels = []
    dispatcher._ws_subscribers = set()

    return create_app(
        config=config,
        event_repo=event_repo,
        device_repo=device_repo,
        stats_repo=stats_repo,
        dispatcher=dispatcher,
    )


@pytest.mark.asyncio
async def test_get_events(app, event_repo):
    await event_repo.insert(engine="test", severity="INFO", title="Test Event")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/events")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["events"]) == 1


@pytest.mark.asyncio
async def test_get_devices(app, device_repo):
    await device_repo.upsert("aa:bb:cc:dd:ee:01", "192.168.1.1")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["devices"]) == 1


@pytest.mark.asyncio
async def test_get_event_detail(app, event_repo):
    """Verify GET /api/events/{id} returns full event detail."""
    event_id = await event_repo.insert(
        engine="test", severity="WARNING", title="Detail Test",
        description="test description",
        packet_info={"layers": ["Ethernet", "IP", "TCP"], "length": 128},
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/events/{event_id}")
        assert resp.status_code == 200
        data = resp.json()
        ev = data["event"]
        assert ev["id"] == event_id
        assert ev["engine"] == "test"
        assert ev["severity"] == "WARNING"
        assert ev["packet_info"]["layers"] == ["Ethernet", "IP", "TCP"]

        # Non-existent event should 404
        resp2 = await client.get("/api/events/999999")
        assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_get_events_filtered(app, event_repo):
    """Verify engine filter works for both list and count."""
    await event_repo.insert(engine="arp_spoof", severity="CRITICAL", title="ARP")
    await event_repo.insert(engine="dns_anomaly", severity="WARNING", title="DNS")
    await event_repo.insert(engine="arp_spoof", severity="WARNING", title="ARP2")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/events?engine=arp_spoof")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["events"]) == 2
        for ev in data["events"]:
            assert ev["engine"] == "arp_spoof"


@pytest.mark.asyncio
async def test_get_stats(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "traffic" in data
        assert "events" in data
