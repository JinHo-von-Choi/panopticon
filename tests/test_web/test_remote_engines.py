"""실제 관리 계정 로그인과 센서 Unix 소켓을 연결한 엔진 API."""

import os
import secrets
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio

from netwatcher.alerts.stream import EventStream
from netwatcher.services.remote_sensor_control import RemoteSensorControl
from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.auth import AuthManager
from netwatcher.web.server import create_app
from tests.test_services.test_sensor_control import control


@pytest_asyncio.fixture
async def engine_api(db, config, control, monkeypatch):
    service, registry, editor, request, send, stopped, accounts, server = control
    monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "true")
    secret = secrets.token_hex(32)
    monkeypatch.setenv("NETWATCHER_JWT_SECRET", secret)
    config.raw["input"] = {"mode": "native"}
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secret})
    manager = AuthManager(config, users=accounts)
    await manager.initialize()
    remote = RemoteSensorControl(db, "office", server.path, expected_uid=os.getuid())
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
                     auth_manager=manager, audit_logger=AuditLogger(db.pool), audit_required=True, sensor_control=remote)
    from scripts.gates import missing_admin_guards
    assert missing_admin_guards(app.routes) == []
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        login = await client.post("/api/auth/login", json={"username": "control-admin", "password": "a-strong-test-password-123"})
        assert login.status_code == 200, login.text
        header = {"Authorization": "Bearer " + login.json()["token"]}
        yield client, header, service, registry, editor, accounts, server, stopped


@pytest.mark.asyncio
async def test_http_catalog_and_configuration_use_sensor_and_store_audit(db, engine_api):
    client, header, service, registry, editor, *_ = engine_api
    result = await client.get("/api/engines", headers=header)
    assert result.status_code == 200, result.text
    engines = result.json()["engines"]
    assert len(engines) == len(registry.get_all_engine_info())
    scan = next(engine for engine in engines if engine["name"] == "port_scan")
    assert scan["configuration_available"] and len(scan["base_version"]) == 64
    absent = next(engine for engine in engines if not engine["configuration_available"])
    assert absent["schema"]
    body = {"request_id": str(uuid4()), "base_version": scan["base_version"], "config": {"threshold": 5}}
    first = await client.put("/api/engines/port_scan/config", headers=header, json=body)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "applied"
    instance = registry._find_active("port_scan")
    duplicate = await client.put("/api/engines/port_scan/config", headers=header, json=body)
    assert duplicate.status_code == 200 and duplicate.json() == first.json()
    assert registry._find_active("port_scan") is instance
    assert editor.get_engine_config("port_scan")["threshold"] == 5
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 1
    audit = await client.get("/api/audit/changes/" + body["request_id"], headers=header)
    assert audit.status_code == 200, audit.text
    assert audit.json()["outcome"] == "applied" and audit.json()["requires_reconciliation"] is False
    stale = await client.patch("/api/engines/port_scan/toggle", headers=header,
        json={"request_id": str(uuid4()), "base_version": scan["base_version"], "enabled": False})
    assert stale.status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_http_viewer_and_analyst_read_but_cannot_change(db, engine_api, role):
    client, header, service, registry, editor, accounts, *_ = engine_api
    await accounts.create(role, "a-strong-test-password-123", role, "test")
    login = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + login.json()["token"]}
    detail = await client.get("/api/engines/port_scan", headers=reader)
    assert detail.status_code == 200
    base = detail.json()["base_version"]
    assert (await client.patch("/api/engines/port_scan/toggle", headers=reader,
        json={"request_id": str(uuid4()), "base_version": base, "enabled": False})).status_code == 403
    assert (await client.put("/api/engines/port_scan/config", headers=reader,
        json={"request_id": str(uuid4()), "base_version": base, "config": {"threshold": 5}})).status_code == 403
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_http_reply_loss_is_unknown_and_manual_same_request_returns_receipt(db, engine_api):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    before = (await client.get("/api/engines/port_scan", headers=header)).json()
    body = {"request_id": str(uuid4()), "base_version": before["base_version"], "enabled": False}
    async def lose_reply(command):
        result = await service(command)
        if command.operation == "engine.toggle":
            raise ConnectionError("injected reply loss")
        return result
    server.handler = lose_reply
    first = await client.patch("/api/engines/port_scan/toggle", headers=header, json=body)
    assert first.status_code == 503
    assert first.json()["detail"]["code"] == "sensor_result_unknown"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 1
    server.handler = service
    second = await client.patch("/api/engines/port_scan/toggle", headers=header, json=body)
    assert second.status_code == 200 and second.json()["engine"]["enabled"] is False
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 1


@pytest.mark.asyncio
async def test_http_sensor_disconnection_and_expired_lease_do_not_fall_back(db, engine_api):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    await server.close()
    assert (await client.get("/api/engines", headers=header)).status_code == 503
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
    assert (await client.get("/api/engines/port_scan", headers=header)).status_code == 503
    assert not stopped and editor.get_engine_config("port_scan")["threshold"] == 15
