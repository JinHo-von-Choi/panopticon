"""Tests for blocklist and device registration API endpoints."""

import pytest
from unittest.mock import MagicMock
from httpx import ASGITransport, AsyncClient

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.storage.repositories import (
    BlocklistRepository,
    DeviceRepository,
    EventRepository,
    TrafficStatsRepository,
)
from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.web.server import create_app


@pytest.fixture
def feed_manager(config):
    fm = FeedManager.__new__(FeedManager)
    fm._config = config
    fm._sources = []
    fm._blocked_ips = set()
    fm._blocked_domains = set()
    fm._custom_ips = set()
    fm._custom_domains = set()
    fm._ip_to_feed = {}
    fm._domain_to_feed = {}
    return fm


@pytest.fixture
def app(config, event_repo, device_repo, stats_repo, blocklist_repo, feed_manager):
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
        blocklist_repo=blocklist_repo,
        feed_manager=feed_manager,
    )


@pytest.mark.asyncio
async def test_add_and_list_blocklist_ip(app, feed_manager):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Add IP
        resp = await client.post("/api/blocklist/ip", json={"ip": "10.0.0.1", "notes": "test"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify in feed manager
        assert "10.0.0.1" in feed_manager._blocked_ips
        assert "10.0.0.1" in feed_manager._custom_ips

        # List
        resp = await client.get("/api/blocklist?entry_type=ip")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1


@pytest.mark.asyncio
async def test_add_invalid_ip(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/blocklist/ip", json={"ip": "not-an-ip"})
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_add_and_remove_domain(app, feed_manager):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Add domain
        resp = await client.post("/api/blocklist/domain", json={"domain": "evil.example.com"})
        assert resp.status_code == 200
        assert "evil.example.com" in feed_manager._blocked_domains

        # Remove domain
        resp = await client.request("DELETE", "/api/blocklist/domain", json={"domain": "evil.example.com"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert "evil.example.com" not in feed_manager._blocked_domains


@pytest.mark.asyncio
async def test_blocklist_stats(app, feed_manager):
    feed_manager._blocked_ips.add("1.2.3.4")
    feed_manager._custom_ips.add("1.2.3.4")
    feed_manager._ip_to_feed["1.2.3.4"] = "Custom"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/blocklist/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_ips"] >= 1
        assert data["custom_ips"] >= 1


@pytest.mark.asyncio
async def test_register_device(app, device_repo):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/devices/register", json={
            "mac_address": "aa:bb:cc:dd:ee:01",
            "nickname": "Test PC",
            "ip_address": "192.168.1.10",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["device"]["nickname"] == "Test PC"
        assert data["device"]["is_known"] == 1


@pytest.mark.asyncio
async def test_register_device_invalid_mac(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/devices/register", json={
            "mac_address": "invalid",
            "nickname": "Test",
        })
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_update_device(app, device_repo):
    await device_repo.register(mac_address="aa:bb:cc:dd:ee:01", nickname="Old Name")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.put("/api/devices/aa:bb:cc:dd:ee:01", json={
            "nickname": "New Name",
            "notes": "Updated",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["device"]["nickname"] == "New Name"
        assert data["device"]["notes"] == "Updated"


@pytest.mark.asyncio
async def test_update_device_not_found(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.put("/api/devices/ff:ff:ff:ff:ff:ff", json={
            "nickname": "Ghost",
        })
        assert resp.status_code == 404
