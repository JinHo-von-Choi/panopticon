"""실제 로그인·센서·DB를 통한 탐지 예외 목록 변경."""

from uuid import uuid4

import pytest

from tests.test_web.test_remote_engines import engine_api
from tests.test_services.test_sensor_control import control


@pytest.mark.asyncio
async def test_whitelist_http_explicit_add_duplicate_remove_and_stale_version(db, engine_api):
    client, header, service, registry, editor, *_ = engine_api
    assert (await client.get("/api/whitelist")).status_code == 401
    read = await client.get("/api/whitelist", headers=header)
    assert read.status_code == 200, read.text
    body = {"request_id": str(uuid4()), "base_version": read.json()["base_version"],
            "type": "ip", "value": "10.1.2.71", "present": True}
    added = await client.put("/api/whitelist/entry", headers=header, json=body)
    assert added.status_code == 200, added.text
    assert registry.whitelist.is_ip_whitelisted(body["value"])
    assert (await client.put("/api/whitelist/entry", headers=header, json=body)).json() == added.json()
    stale = {**body, "request_id": str(uuid4()), "present": False}
    assert (await client.put("/api/whitelist/entry", headers=header, json=stale)).status_code == 409
    removed = await client.put("/api/whitelist/entry", headers=header,
        json={**stale, "base_version": added.json()["base_version"]})
    assert removed.status_code == 200
    assert not registry.whitelist.is_ip_whitelisted(body["value"])
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 2
    history = await client.get("/api/audit/changes/" + body["request_id"], headers=header)
    assert history.status_code == 200, history.text
    assert history.json()["outcome"] == "applied"
    assert history.json()["requires_reconciliation"] is False
    assert [entry["action"] for entry in history.json()["entries"]] == ["sensor_change_prepared", "sensor_change_applied"]


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_whitelist_http_roles_do_not_reach_mutation(db, engine_api, role):
    client, header, service, registry, editor, accounts, *_ = engine_api
    await accounts.create(role, "a-strong-test-password-123", role, "test")
    login = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + login.json()["token"]}
    read = await client.get("/api/whitelist", headers=reader)
    assert read.status_code == 200
    changed = await client.put("/api/whitelist/entry", headers=reader,
        json={"request_id": str(uuid4()), "base_version": read.json()["base_version"],
              "type": "ip", "value": "10.1.2.71", "present": True})
    assert changed.status_code == 403
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_whitelist_http_lost_reply_requires_read_and_never_reexecutes(db, engine_api):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    read = (await client.get("/api/whitelist", headers=header)).json()
    body = {"request_id": str(uuid4()), "base_version": read["base_version"],
            "type": "ip", "value": "10.1.2.71", "present": True}
    calls = []
    async def lost_reply(command):
        result = await service(command)
        if command.operation == "whitelist.set":
            calls.append(command.request_id)
            raise ConnectionError("test reply lost")
        return result
    server.handler = lost_reply
    response = await client.put("/api/whitelist/entry", headers=header, json=body)
    assert response.status_code == 503
    assert calls == [body["request_id"]]
    assert registry.whitelist.is_ip_whitelisted(body["value"])
    assert body["value"] in (await client.get("/api/whitelist", headers=header)).json()["ips"]
    server.handler = service
    receipt = await client.put("/api/whitelist/entry", headers=header, json=body)
    assert receipt.status_code == 200
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 1


@pytest.mark.asyncio
async def test_whitelist_http_disconnected_sensor_is_not_empty_list(engine_api):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    await server.close()
    assert (await client.get("/api/whitelist", headers=header)).status_code == 503


@pytest.mark.asyncio
async def test_sensor_audit_prepared_without_committed_result_requires_reconciliation(db, engine_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    read = (await client.get("/api/whitelist", headers=header)).json()
    original = service._audit
    async def fail_completion(conn, request, action, details):
        if action == "sensor_change_applied":
            raise OSError("test audit storage unavailable")
        await original(conn, request, action, details)
    monkeypatch.setattr(service, "_audit", fail_completion)
    body = {"request_id": str(uuid4()), "base_version": read["base_version"],
            "type": "ip", "value": "10.1.2.71", "present": True}
    assert (await client.put("/api/whitelist/entry", headers=header, json=body)).status_code == 503
    history = await client.get("/api/audit/changes/" + body["request_id"], headers=header)
    assert history.status_code == 200
    assert history.json()["outcome"] == "unknown"
    assert history.json()["requires_reconciliation"] is True
    assert [entry["action"] for entry in history.json()["entries"]] == ["sensor_change_prepared"]
    assert registry.whitelist.is_ip_whitelisted(body["value"])
    assert stopped == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_sensor_audit_uuid_lookup_is_admin_only(db, engine_api, role):
    client, header, service, registry, editor, accounts, *_ = engine_api
    await accounts.create(role, "a-strong-test-password-123", role, "test")
    login = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + login.json()["token"]}
    assert (await client.get("/api/audit/changes/" + str(uuid4()), headers=reader)).status_code == 403


@pytest.mark.asyncio
async def test_sensor_audit_uuid_absent_or_database_failure_is_not_success(db, engine_api):
    client, header, *_ = engine_api
    identifier = str(uuid4())
    assert (await client.get("/api/audit/changes/" + identifier, headers=header)).status_code == 404
    for invalid in (identifier.upper(), "not-a-uuid", identifier + "0"):
        assert (await client.get("/api/audit/changes/" + invalid, headers=header)).status_code == 422
    await db.pool.execute("ALTER TABLE audit_log RENAME TO audit_log_unavailable")
    try:
        assert (await client.get("/api/audit/changes/" + identifier, headers=header)).status_code == 503
    finally:
        await db.pool.execute("ALTER TABLE audit_log_unavailable RENAME TO audit_log")


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, "pending", [], {}])
async def test_invalid_stored_audit_outcome_cannot_confirm_completion(db, engine_api, outcome):
    client, header, *_ = engine_api
    identifier = uuid4().hex
    await db.pool.execute("INSERT INTO audit_log(user_id,action,resource,details) VALUES($1,$2,$3,$4)",
                          "test", "api_mutation", "/test", {"request_id": identifier, "outcome": outcome})
    response = await client.get("/api/audit/changes/" + identifier, headers=header)
    assert response.status_code == 200
    assert response.json()["outcome"] == "unknown"
    assert response.json()["requires_reconciliation"] is True
