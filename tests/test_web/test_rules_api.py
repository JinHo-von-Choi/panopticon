"""Tests for signature rule management API."""

import os

import pytest
from httpx import ASGITransport, AsyncClient

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.engines.signature import SignatureEngine
from netwatcher.web.server import create_app


@pytest.fixture
def rules_dir(tmp_path):
    """Create a temporary rules directory with test rules."""
    rd = tmp_path / "rules"
    rd.mkdir()
    rule_file = rd / "test.yaml"
    rule_file.write_text("""
rules:
  - id: "API-001"
    name: "Test SSH Rule"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: 22
    flags: "SYN"
    threshold:
      count: 10
      seconds: 60
      by: "src_ip"

  - id: "API-002"
    name: "Test HTTP Rule"
    severity: "WARNING"
    protocol: "tcp"
    dst_port: [80, 443]
    content:
      - "malicious"
    content_nocase: true

  - id: "API-003"
    name: "Disabled Rule"
    severity: "INFO"
    enabled: false
""")
    return rd


@pytest.fixture
def signature_engine(rules_dir):
    """Create a SignatureEngine with test rules."""
    return SignatureEngine({
        "enabled": True,
        "rules_dir": str(rules_dir),
        "hot_reload": False,
    })


@pytest.fixture
def app(config, event_repo, device_repo, stats_repo, signature_engine):
    """Create FastAPI app with rules router."""
    dispatcher = AlertDispatcher.__new__(AlertDispatcher)
    dispatcher._config         = config
    dispatcher._event_repo     = event_repo
    dispatcher._queue          = None
    dispatcher._task           = None
    dispatcher._rate_limiter   = None
    dispatcher._channels       = []
    dispatcher._ws_subscribers = set()

    return create_app(
        config=config,
        event_repo=event_repo,
        device_repo=device_repo,
        stats_repo=stats_repo,
        dispatcher=dispatcher,
        signature_engine=signature_engine,
    )


@pytest.mark.asyncio
async def test_list_rules(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["rules"]) == 3

        # Verify rule fields
        ids = {r["id"] for r in data["rules"]}
        assert "API-001" in ids
        assert "API-002" in ids
        assert "API-003" in ids


@pytest.mark.asyncio
async def test_get_rule_detail(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/rules/API-001")
        assert resp.status_code == 200
        data = resp.json()
        rule = data["rule"]
        assert rule["id"] == "API-001"
        assert rule["name"] == "Test SSH Rule"
        assert rule["severity"] == "CRITICAL"
        assert rule["protocol"] == "tcp"
        assert rule["dst_port"] == 22
        assert rule["flags"] == "SYN"
        assert rule["threshold"] is not None
        assert rule["threshold"]["count"] == 10
        assert rule["enabled"] is True


@pytest.mark.asyncio
async def test_get_rule_detail_content(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/rules/API-002")
        assert resp.status_code == 200
        data = resp.json()
        rule = data["rule"]
        assert rule["has_content"] is True
        assert rule["content_count"] == 1
        assert rule["content_nocase"] is True


@pytest.mark.asyncio
async def test_get_rule_not_found(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/rules/NONEXISTENT")
        assert resp.status_code == 404
        assert "not found" in resp.json()["error"].lower()


@pytest.mark.asyncio
async def test_toggle_rule(app, signature_engine):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # API-001 starts enabled
        rules_map = signature_engine.rules_by_id
        assert rules_map["API-001"].enabled is True

        # Toggle off
        resp = await client.put("/api/rules/API-001/toggle")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["enabled"] is False

        # Verify engine state changed
        assert signature_engine.rules_by_id["API-001"].enabled is False

        # Toggle back on
        resp2 = await client.put("/api/rules/API-001/toggle")
        assert resp2.status_code == 200
        assert resp2.json()["enabled"] is True
        assert signature_engine.rules_by_id["API-001"].enabled is True


@pytest.mark.asyncio
async def test_toggle_rule_not_found(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.put("/api/rules/NONEXISTENT/toggle")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reload_rules(app, signature_engine, rules_dir):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Initial count
        assert len(signature_engine.rules) == 3

        # Add a new rule file
        new_file = rules_dir / "extra.yaml"
        new_file.write_text("""
rules:
  - id: "NEW-001"
    name: "New Rule"
    severity: "INFO"
""")

        # Trigger reload via API
        resp = await client.post("/api/rules/reload")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["rules_loaded"] == 4

        # Verify new rule is loaded
        assert "NEW-001" in signature_engine.rules_by_id


@pytest.mark.asyncio
async def test_list_rules_shows_disabled(app):
    """Disabled rules should appear in the list with enabled=false."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/rules")
        data = resp.json()
        disabled = [r for r in data["rules"] if r["id"] == "API-003"]
        assert len(disabled) == 1
        assert disabled[0]["enabled"] is False


@pytest.mark.asyncio
async def test_no_signature_engine(config, event_repo, device_repo, stats_repo):
    """When signature_engine is None, rules routes should not be registered."""
    dispatcher = AlertDispatcher.__new__(AlertDispatcher)
    dispatcher._config         = config
    dispatcher._event_repo     = event_repo
    dispatcher._queue          = None
    dispatcher._task           = None
    dispatcher._rate_limiter   = None
    dispatcher._channels       = []
    dispatcher._ws_subscribers = set()

    app = create_app(
        config=config,
        event_repo=event_repo,
        device_repo=device_repo,
        stats_repo=stats_repo,
        dispatcher=dispatcher,
        signature_engine=None,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/rules")
        # 404 because the route is not registered (StaticFiles may serve 404)
        assert resp.status_code in (404, 405)
