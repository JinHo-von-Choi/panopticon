"""관리 계정·실제 사건 저장소·필수 감사로 사건 해결 경계를 확인한다."""

import secrets

import httpx
import pytest
import pytest_asyncio

from netwatcher.alerts.stream import EventStream
from netwatcher.storage.repositories import DeviceRepository, EventRepository, IncidentRepository, TrafficStatsRepository
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.auth import AuthManager
from netwatcher.web.server import create_app
from scripts.gates import missing_admin_guards


@pytest_asyncio.fixture
async def incident_api(db, config, monkeypatch):
    secret = secrets.token_hex(32)
    monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "true")
    monkeypatch.setenv("NETWATCHER_JWT_SECRET", secret)
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secret,
                               "api_rate_limit": {"enabled": False}})
    accounts = UserAccounts(db)
    await accounts.create("incident-admin", "a-strong-test-password-123", "admin", "test")
    manager = AuthManager(config, users=accounts)
    await manager.initialize()
    repository = IncidentRepository(db)
    incident_id = await repository.insert("CRITICAL", "Investigation test", source_ips=["192.0.2.10"])
    audit = AuditLogger(db.pool)
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
        auth_manager=manager, audit_logger=audit, audit_required=True, incident_repository=repository)
    assert missing_admin_guards(app.routes) == []
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/auth/login", json={"username": "incident-admin", "password": "a-strong-test-password-123"})
        assert response.status_code == 200, response.text
        header = {"Authorization": "Bearer " + response.json()["token"]}
        yield client, header, repository, accounts, audit, incident_id, app


@pytest.mark.asyncio
async def test_stored_incidents_work_without_sensor_correlator(db, incident_api):
    client, header, repository, accounts, audit, identifier, app = incident_api
    capabilities = await client.get("/api/capabilities", headers=header)
    assert capabilities.json()["features"]["incidents"] is True
    result = await client.get("/api/incidents", headers=header)
    assert result.status_code == 200
    assert [row["id"] for row in result.json()["incidents"]] == [identifier]
    assert result.json()["source"] == "store"
    summary = await client.get("/api/stats/summary", headers=header)
    assert summary.status_code == 200 and summary.json()["high_risk_count"] == 1
    response = await client.post(f"/api/incidents/{identifier}/resolve", headers=header)
    assert response.status_code == 200, response.text
    assert (await repository.get_by_id(identifier))["resolved"] is True
    history = await client.get("/api/audit/changes/" + response.headers["X-Request-ID"], headers=header)
    assert history.json()["outcome"] == "completed"
    entries = history.json()["entries"]
    assert [entry["action"] for entry in entries] == ["authorized_intent", "change_prepared", "api_mutation"]
    assert entries[-1]["details"]["before"]["resolved"] is False
    assert entries[-1]["details"]["after"]["resolved"] is True
    assert all(entry["user"] == "incident-admin" for entry in entries)
    assert (await client.get("/api/stats/summary", headers=header)).json()["high_risk_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_readers_cannot_resolve(db, incident_api, role):
    client, header, repository, accounts, audit, identifier, app = incident_api
    await accounts.create(role, "a-strong-test-password-123", role, "test")
    response = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + response.json()["token"]}
    assert (await client.get(f"/api/incidents/{identifier}", headers=reader)).status_code == 200
    before = await repository.get_by_id(identifier)
    assert (await client.post(f"/api/incidents/{identifier}/resolve", headers=reader)).status_code == 403
    assert await repository.get_by_id(identifier) == before
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='authorized_intent'") == 0


@pytest.mark.asyncio
async def test_disabled_admin_token_cannot_resolve(incident_api):
    client, header, repository, accounts, audit, identifier, app = incident_api
    account = await accounts.get_by_username("incident-admin")
    await accounts.create("other-admin", "a-strong-test-password-123", "admin", "test")
    login = await client.post("/api/auth/login", json={"username": "other-admin", "password": "a-strong-test-password-123"})
    assert login.status_code == 200
    other = {"Authorization": "Bearer " + login.json()["token"]}
    response = await client.put(f"/api/users/{account['id']}", headers=other,
        json={"enabled": False, "role": "admin", "expected_version": account["version"]})
    assert response.status_code == 200, response.text
    assert (await client.post(f"/api/incidents/{identifier}/resolve", headers=header)).status_code == 401
    assert (await repository.get_by_id(identifier))["resolved"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["authorized_intent", "change_prepared"])
async def test_failed_required_audit_keeps_record_unchanged(incident_api, monkeypatch, failure):
    client, header, repository, accounts, audit, identifier, app = incident_api
    original = audit.log
    async def fail(**entry):
        return False if entry["action"] == failure else await original(**entry)
    monkeypatch.setattr(audit, "log", fail)
    before = await repository.get_by_id(identifier)
    assert (await client.post(f"/api/incidents/{identifier}/resolve", headers=header)).status_code == 503
    assert await repository.get_by_id(identifier) == before


@pytest.mark.asyncio
async def test_applied_change_with_lost_reply_is_unknown_and_readable(db, incident_api, monkeypatch):
    client, header, repository, accounts, audit, identifier, app = incident_api
    original = repository.resolve
    calls = []
    async def lose_reply(incident_id):
        calls.append(incident_id)
        await original(incident_id)
        raise ConnectionError("lost reply with private diagnostic")
    monkeypatch.setattr(repository, "resolve", lose_reply)
    response = await client.post(f"/api/incidents/{identifier}/resolve", headers=header)
    assert response.status_code == 503
    assert "private diagnostic" not in response.text
    assert calls == [identifier]
    detail = await client.get(f"/api/incidents/{identifier}", headers=header)
    assert detail.status_code == 200 and detail.json()["incident"]["resolved"] is True
    history = await client.get("/api/audit/changes/" + response.headers["X-Request-ID"], headers=header)
    assert history.json()["outcome"] == "unknown"
    assert history.json()["requires_reconciliation"] is True


@pytest.mark.asyncio
async def test_result_audit_failure_does_not_repeat_change(incident_api, monkeypatch):
    client, header, repository, accounts, audit, identifier, app = incident_api
    original = audit.log
    async def fail(**entry):
        return False if entry["action"] == "api_mutation" else await original(**entry)
    monkeypatch.setattr(audit, "log", fail)
    response = await client.post(f"/api/incidents/{identifier}/resolve", headers=header)
    assert response.status_code == 503
    assert response.json()["execution_status"] == "unknown"
    assert (await repository.get_by_id(identifier))["resolved"] is True


@pytest.mark.asyncio
async def test_database_failure_is_not_an_empty_or_resolved_list(db, incident_api):
    client, header, repository, accounts, audit, identifier, app = incident_api
    await db.pool.execute("DROP TABLE incidents")
    for path in ("/api/incidents", f"/api/incidents/{identifier}", "/api/stats/summary"):
        response = await client.get(path, headers=header)
        assert response.status_code == 503, response.text
        assert "high_risk_count" not in response.json()
        assert "incidents" not in response.json()
