"""Tests for IP block management API endpoints.

작성자: 최진호
작성일: 2026-02-20
"""

import pytest
from httpx import ASGITransport, AsyncClient

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.response.blocker import BlockManager
from netwatcher.storage.repositories import (
    DeviceRepository,
    EventRepository,
    TrafficStatsRepository,
)
from netwatcher.web.server import create_app


@pytest.fixture
def block_manager():
    """BlockManager with mock backend for testing."""
    return BlockManager(
        enabled=True,
        backend="mock",
        chain_name="TEST_BLOCK",
        whitelist=["10.0.0.1"],
        max_blocks=100,
        default_duration=3600,
    )


@pytest.fixture
def app(config, event_repo, device_repo, stats_repo, block_manager):
    dispatcher = AlertDispatcher.__new__(AlertDispatcher)
    dispatcher._config           = config
    dispatcher._event_repo       = event_repo
    dispatcher._queue            = None
    dispatcher._task             = None
    dispatcher._rate_limiter     = None
    dispatcher._channels         = []
    dispatcher._ws_subscribers   = set()
    dispatcher._block_manager    = None
    dispatcher._auto_block_engines = set()

    return create_app(
        config=config,
        event_repo=event_repo,
        device_repo=device_repo,
        stats_repo=stats_repo,
        dispatcher=dispatcher,
        block_manager=block_manager,
    )


@pytest.mark.asyncio
async def test_list_blocks_empty(app):
    """빈 상태에서 블록 목록 조회 시 빈 리스트 반환."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/blocks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocks"] == []
        assert data["total"] == 0


@pytest.mark.asyncio
async def test_add_and_list_block(app):
    """IP 차단 추가 후 목록에 표시 확인."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Add block
        resp = await client.post("/api/blocks", json={
            "ip": "192.168.1.100",
            "reason": "Suspicious activity",
            "duration": 7200,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["ip"] == "192.168.1.100"

        # Verify in list
        resp = await client.get("/api/blocks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["blocks"][0]["ip"] == "192.168.1.100"
        assert data["blocks"][0]["reason"] == "Suspicious activity"
        assert data["blocks"][0]["duration"] == 7200


@pytest.mark.asyncio
async def test_add_block_invalid_ip(app):
    """잘못된 IP 형식에 대해 400 반환."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/blocks", json={
            "ip": "not-an-ip",
            "reason": "test",
        })
        assert resp.status_code == 400
        assert "Invalid IP" in resp.json()["error"]


@pytest.mark.asyncio
async def test_add_block_whitelisted_ip(app):
    """화이트리스트 IP 차단 시 400 반환."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/blocks", json={
            "ip": "10.0.0.1",
            "reason": "test whitelist",
        })
        assert resp.status_code == 400
        assert "Failed to block" in resp.json()["error"]


@pytest.mark.asyncio
async def test_unblock(app):
    """IP 차단 추가 후 해제 확인."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First add a block
        resp = await client.post("/api/blocks", json={
            "ip": "192.168.1.200",
            "reason": "To be removed",
        })
        assert resp.status_code == 200

        # Unblock
        resp = await client.delete("/api/blocks/192.168.1.200")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["ip"] == "192.168.1.200"

        # Verify removed from list
        resp = await client.get("/api/blocks")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


@pytest.mark.asyncio
async def test_unblock_not_found(app):
    """존재하지 않는 IP 해제 시 404 반환."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.delete("/api/blocks/172.16.0.1")
        assert resp.status_code == 404
        assert "No active block" in resp.json()["error"]


@pytest.mark.asyncio
async def test_unblock_invalid_ip(app):
    """잘못된 IP 형식으로 해제 시 400 반환."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.delete("/api/blocks/invalid-ip")
        assert resp.status_code == 400
        assert "Invalid IP" in resp.json()["error"]


@pytest.mark.asyncio
async def test_duplicate_block(app):
    """이미 차단된 IP 재차단 시 400 반환."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Block first time
        resp = await client.post("/api/blocks", json={
            "ip": "192.168.1.50",
            "reason": "First block",
        })
        assert resp.status_code == 200

        # Block same IP again
        resp = await client.post("/api/blocks", json={
            "ip": "192.168.1.50",
            "reason": "Duplicate block",
        })
        assert resp.status_code == 400
        assert "Failed to block" in resp.json()["error"]
