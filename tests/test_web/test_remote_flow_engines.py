"""관리 계정 HTTP 요청이 실제 센서의 NetFlow 엔진을 변경한다."""

from uuid import uuid4

import pytest

from tests.test_services.test_sensor_control import control
from tests.test_services.test_sensor_flow_control import bind_flow
from tests.test_web.test_remote_engines import engine_api


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
async def test_remote_flow_catalog_mutation_and_audit(db, control, engine_api, role):
    processor = bind_flow(control)
    client, headers, service, registry, editor, accounts, *_ = engine_api
    if role != "admin":
        await accounts.create("flow-" + role, "a-strong-test-password-123", role, "test")
        login = await client.post("/api/auth/login", json={"username": "flow-" + role, "password": "a-strong-test-password-123"})
        assert login.status_code == 200
        headers = {"Authorization": "Bearer " + login.json()["token"]}
    catalog = await client.get("/api/engines", headers=headers)
    assert catalog.status_code == 200
    flow = next(engine for engine in catalog.json()["engines"] if engine["name"] == "flow_port_scan")
    assert flow["configuration_available"] and flow["requires_span"] is False
    detail = await client.get("/api/engines/flow_port_scan", headers=headers)
    assert detail.status_code == 200
    body = {"request_id": str(uuid4()), "base_version": detail.json()["base_version"], "config": {"threshold": 5}}
    changed = await client.put("/api/engines/flow_port_scan/config", headers=headers, json=body)
    if role != "admin":
        assert changed.status_code == 403
        assert processor.get_engine_info("flow_port_scan")["config"]["threshold"] == 20
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
        return
    assert changed.status_code == 200, changed.text
    assert changed.json()["status"] == "applied"
    assert processor.get_engine_info("flow_port_scan")["config"]["threshold"] == 5
    assert editor.get_flow_engine_config("flow_port_scan")["threshold"] == 5
    assert editor.get_engine_config("flow_port_scan") == {"threshold": 199}
    old = processor.engines[0]
    duplicate = await client.put("/api/engines/flow_port_scan/config", headers=headers, json=body)
    assert duplicate.status_code == 200 and duplicate.json() == changed.json()
    assert processor.engines[0] is old
    audit = await client.get("/api/audit/changes/" + body["request_id"], headers=headers)
    assert audit.status_code == 200 and audit.json()["outcome"] == "applied"
    assert audit.json()["requires_reconciliation"] is False
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 1
