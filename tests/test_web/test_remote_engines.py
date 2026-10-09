"""실제 관리 계정 로그인과 센서 Unix 소켓을 연결한 엔진 API."""

import os
import secrets
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio

from netwatcher.alerts.stream import EventStream
from netwatcher.services import sensor_control
from netwatcher.services.remote_sensor_control import RemoteSensorControl
from netwatcher.services.sensor_control import SensorControlError
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


@pytest.mark.asyncio
async def test_engine_list_uses_one_sensor_round_trip(db, engine_api):
    """엔진 목록 조회가 센서 왕복 1회로 끝나야 한다.

    이전 구현은 카탈로그 1회 뒤 엔진마다 engine.read를 순차 전송해
    카탈로그 1 + 엔진 N 회를 왕복했다. 인증 쿼리와 설정 파일 파싱도 같은
    횟수로 반복되므로 이 계약을 그대로 지킨다.
    """
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    engine_count = len(registry.get_all_engine_info())
    assert engine_count > 1, "검증할 다중 엔진 구성이어야 한다"

    operations = []
    original = service.__call__

    async def counting(command):
        operations.append(command.operation)
        return await original(command)

    server.handler = counting
    result = await client.get("/api/engines", headers=header)
    assert result.status_code == 200, result.text
    assert len(result.json()["engines"]) == engine_count
    assert operations == ["engine.states"], f"단일 일괄 왕복이어야 한다: {operations}"


@pytest.mark.asyncio
async def test_engine_states_match_single_engine_reads(db, engine_api):
    """일괄 응답이 단건 조회와 엔진별 상태·버전에서 동일해야 한다."""
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    bulk = (await client.get("/api/engines", headers=header)).json()["engines"]
    assert bulk
    for entry in bulk:
        name = entry["name"]
        base = entry["base_version"]
        state = {key: value for key, value in entry.items() if key != "base_version"}
        single = await client.get(f"/api/engines/{name}", headers=header)
        assert single.status_code == 200, single.text
        detail = single.json()
        assert detail["engine"] == state, name
        assert detail["base_version"] == base, name


@pytest.mark.asyncio
async def test_engine_states_fall_back_when_response_would_exceed_limit(db, engine_api, monkeypatch):
    """일괄 응답이 한계를 넘으면 단건 경로로 되돌아가야 한다."""
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    operations = []
    original = service.__call__

    async def counting(command):
        operations.append(command.operation)
        return await original(command)

    server.handler = counting
    monkeypatch.setattr(sensor_control, "MAX_ENGINE_STATES_BYTES", 256)
    result = await client.get("/api/engines", headers=header)
    assert result.status_code == 200, result.text
    assert len(result.json()["engines"]) == len(registry.get_all_engine_info())
    # 실제로 단건 경로(catalog 1회 + read N회)로 내려갔는지 확인한다.
    assert operations[0] == "engine.states" and operations[1] == "engine.catalog"
    assert operations.count("engine.read") == len(registry.get_all_engine_info())


@pytest.mark.asyncio
async def test_engine_list_does_not_swallow_permission_failure(db, engine_api, monkeypatch):
    """폴백이 권한 실패까지 삼키면 안 된다 — 단건 경로도 같은 거부를 낸다."""
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    original = service.__call__

    async def refuse(command):
        raise SensorControlError("sensor_control_forbidden", 403)

    server.handler = refuse
    result = await client.get("/api/engines", headers=header)
    assert result.status_code == 403, result.text
    assert result.json()["detail"]["code"] == "sensor_control_forbidden"


@pytest.mark.asyncio
async def test_engine_states_load_configuration_once(db, engine_api, monkeypatch):
    """일괄 조회는 설정 파일을 엔진마다 다시 파싱하지 않아야 한다."""
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    engine_count = len(registry.get_all_engine_info())
    loads = []
    original = editor._load
    monkeypatch.setattr(editor, "_load", lambda: (loads.append(1), original())[1])
    assert (await client.get("/api/engines", headers=header)).status_code == 200
    assert len(loads) == 1, f"YAML 파싱이 {len(loads)}회 — 엔진당 1회면 회귀다 ({engine_count}개 엔진)"


@pytest.mark.asyncio
async def test_engine_states_include_every_registered_engine_once(db, engine_api):
    """모든 등록 엔진이 정확히 한 번씩 와야 한다 (누락·중복 금지)."""
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    names = [info["name"] for info in registry.get_all_engine_info()]
    engines = (await client.get("/api/engines", headers=header)).json()["engines"]
    seen = [engine["name"] for engine in engines]
    assert sorted(seen) == sorted(names)
    assert len(seen) == len(set(seen)), "같은 엔진이 두 번 들어왔다"
    for engine in engines:
        assert isinstance(engine["enabled"], bool) and isinstance(engine["config"], dict)


@pytest.mark.asyncio
async def test_engine_states_tolerate_empty_registry(db, engine_api, monkeypatch):
    """엔진이 하나도 없을 때도 폴백 없이 정상 응답해야 한다."""
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    monkeypatch.setattr(registry, "get_all_engine_info", lambda: [])
    result = await client.get("/api/engines", headers=header)
    assert result.status_code == 200, result.text
    assert result.json()["engines"] == []


@pytest.mark.asyncio
async def test_engine_states_reject_disabled_account_and_stale_lease(db, control):
    """일괄 경로도 센서 측 권한·세대 검사를 그대로 받아야 한다.

    HTTP로 접근하면 콘솔 계층이 먼저 계정을 막으므로(401), 전송 계층을
    직접 써서 센서가 스스로 거부하는지 확인한다.
    """
    service, registry, editor, request, send, stopped, accounts, server = control
    admin = await accounts.authenticate("control-admin", "a-strong-test-password-123")
    assert admin is not None
    assert (await send(request("engine.states", engine="states", actor=admin)))["engines"]

    await accounts.create("standby-admin", "a-strong-test-password-123", "admin", "test")
    await accounts.update(admin["id"], admin["version"], role="admin", enabled=False, actor="test")
    with pytest.raises(SensorControlError) as forbidden:
        await send(request("engine.states", engine="states", actor=admin))
    assert forbidden.value.code == "sensor_control_forbidden" and forbidden.value.status == 403

    live = await accounts.authenticate("standby-admin", "a-strong-test-password-123")
    await db.pool.execute("UPDATE sensor_runtime_state SET stopped=true")
    with pytest.raises(SensorControlError) as stopped_sensor:
        await send(request("engine.states", engine="states", actor=live))
    assert stopped_sensor.value.code == "sensor_generation_changed"
    assert not stopped
