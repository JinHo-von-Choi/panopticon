"""관리자 변경의 실제 JWT 권한, 감사 실패와 실행 결과를 검증한다."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock

import bcrypt
import jwt
import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.detection.whitelist import Whitelist
from netwatcher.response.blocker import BlockManager
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.server import create_app
from scripts.gates import gate_mutation_permissions, missing_admin_guards

SECRET = "mutation-test-signing-key-at-least-thirty-two-bytes"
CHANGES = [
    ("POST", "/api/incidents/7/resolve", None),
    ("POST", "/api/blocks", {"ip": "192.0.2.10"}),
    ("DELETE", "/api/blocks/192.0.2.10", None),
    ("POST", "/api/blocklist/ip", {"ip": "192.0.2.10"}),
    ("DELETE", "/api/blocklist/ip", {"ip": "192.0.2.10"}),
    ("DELETE", "/api/blocklist/ip/192.0.2.10", None),
    ("POST", "/api/blocklist/domain", {"domain": "bad.example"}),
    ("DELETE", "/api/blocklist/domain", {"domain": "bad.example"}),
    ("DELETE", "/api/blocklist/domain/bad.example", None),
    ("POST", "/api/whitelist/toggle", {"type": "ip", "value": "192.0.2.10"}),
    ("PUT", "/api/rules/test/toggle", None),
    ("POST", "/api/rules/reload", None),
    ("POST", "/api/devices/register", {"mac_address": "02:00:00:00:00:01"}),
    ("POST", "/api/devices/02:00:00:00:00:01", {"nickname": "test"}),
    ("PUT", "/api/devices/02:00:00:00:00:01", {"nickname": "test"}),
    ("PUT", "/api/devices/02:00:00:00:00:01/context", {
        "role": "backup", "ip_address": "192.0.2.10", "expected_version": 0,
        "ownership_confirmed": True, "evidence": "approved asset",
    }),
    ("PATCH", "/api/engines/port_scan/toggle", {"enabled": False}),
    ("PUT", "/api/engines/port_scan/config", {"threshold": 20}),
]


class RecordingAudit:
    def __init__(self, failure=None):
        self.failure = failure
        self.entries = []

    async def log(self, **entry):
        if self.failure == entry["action"]:
            return False
        self.entries.append(entry)
        return True


@pytest.fixture
def secured_app(monkeypatch):
    monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
    config = Config({"auth": {"enabled": True,
        "password": bcrypt.hashpw(b"test-password", bcrypt.gensalt(rounds=4)).decode(),
        "jwt_secret": SECRET, "api_rate_limit": {"enabled": False}}})
    manager = BlockManager(enabled=True, backend="mock", whitelist=[], max_blocks=100)
    audit = RecordingAudit()
    dependencies = [MagicMock() for _ in range(5)]
    devices, blocklist, feed, engine, editor = dependencies
    devices.get_by_mac = AsyncMock(return_value=None)
    blocklist.get_entry = AsyncMock(return_value=None)
    whitelist = Whitelist({})
    app = create_app(config, None, devices, None, None, auth_manager=AuthManager(config),
                     block_manager=manager, blocklist_repo=blocklist, feed_manager=feed,
                     signature_engine=engine, registry=engine, yaml_editor=editor,
                     whitelist=whitelist, audit_logger=audit, audit_required=True,
                     incident_repository=MagicMock())
    for dependency in dependencies:
        dependency.reset_mock()
    return app, manager, whitelist, audit, dependencies


def headers(role):
    if role is None:
        return {}
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": "operator", "role": role, "iat": now,
                        "exp": now + timedelta(minutes=5)}, SECRET, algorithm="HS256")
    return {"Authorization": "Bearer " + token}


@pytest.mark.asyncio
@pytest.mark.parametrize("role,status", [(None, 401), ("viewer", 403), ("analyst", 403)])
async def test_change_history_requires_admin(secured_app, role, status):
    app, _, _, audit, _ = secured_app
    audit.change_history = AsyncMock(return_value=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/audit/changes/" + "a" * 32, headers=headers(role))
    assert response.status_code == status
    audit.change_history.assert_not_awaited()


@pytest.mark.asyncio
async def test_change_history_validates_request_id(secured_app):
    app, _, _, audit, _ = secured_app
    audit.change_history = AsyncMock(return_value=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/audit/changes/invalid", headers=headers("admin"))
    assert response.status_code == 422
    audit.change_history.assert_not_awaited()


def test_state_summary_redacts_secrets_and_bounds_nested_values():
    from netwatcher.web.change_audit import state_summary
    result = state_summary({"password": "private", "api_key": "private",
                            "name": "backup", "count": 2, "values": list(range(100)),
                            "ratio": float("nan")})
    assert result["password"] == result["api_key"] == "[redacted]"
    assert "backup" not in str(result)
    assert result["name"]["length"] == 6
    assert result["count"] == 2
    assert len(result["values"]) == 64
    assert result["ratio"] == {"non_finite": "nan"}


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", CHANGES)
@pytest.mark.parametrize("role,status", [(None, 401), ("viewer", 403), ("analyst", 403)])
async def test_all_admin_changes_reject_other_roles(secured_app, method, path, body, role, status):
    app, manager, whitelist, audit, dependencies = secured_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request(method, path, json=body, headers=headers(role))
    assert response.status_code == status
    assert manager.get_active_blocks() == []
    assert not whitelist.is_ip_whitelisted("192.0.2.10")
    assert all(not dependency.mock_calls for dependency in dependencies)
    assert all(entry["action"] != "authorized_intent" for entry in audit.entries)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", CHANGES)
async def test_failed_intent_prevents_every_change(secured_app, method, path, body):
    app, manager, whitelist, audit, dependencies = secured_app
    audit.failure = "authorized_intent"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request(method, path, json=body, headers=headers("admin"))
    assert response.status_code == 503
    assert manager.get_active_blocks() == []
    assert not whitelist.is_ip_whitelisted("192.0.2.10")
    assert all(not dependency.mock_calls for dependency in dependencies)


@pytest.mark.asyncio
async def test_admin_block_has_linked_intent_result_and_actor(secured_app):
    app, manager, _, audit, _ = secured_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/blocks", headers=headers("admin"),
                                     json={"ip": "192.0.2.10", "password": "do-not-log"})
    assert response.status_code == 200
    assert len(manager.get_active_blocks()) == 1
    intent, prepared, result = audit.entries
    assert [intent["action"], prepared["action"], result["action"]] == ["authorized_intent", "change_prepared", "api_mutation"]
    assert prepared["details"]["before"]["active"] is False
    assert result["details"]["before"]["active"] is False
    assert result["details"]["after"]["active"] is True
    assert intent["user"] == result["user"] == "operator"
    assert intent["details"]["request_id"] == result["details"]["request_id"] == response.headers["X-Request-ID"]
    assert result["details"]["outcome"] == "completed"
    assert "do-not-log" not in str(audit.entries)


@pytest.mark.asyncio
async def test_result_failure_reports_unknown_without_repeating_action(secured_app):
    app, manager, _, audit, _ = secured_app
    audit.failure = "api_mutation"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/blocks", headers=headers("admin"), json={"ip": "192.0.2.10"})
    assert response.status_code == 503
    assert response.json()["execution_status"] == "unknown"
    assert response.json()["request_id"] == audit.entries[0]["details"]["request_id"]
    assert len(manager.get_active_blocks()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", CHANGES)
async def test_failed_change_details_prevents_execution(secured_app, method, path, body):
    app, manager, whitelist, audit, dependencies = secured_app
    audit.failure = "change_prepared"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request(method, path, json=body, headers=headers("admin"))
    assert response.status_code == 503
    assert manager.get_active_blocks() == []
    assert not whitelist.is_ip_whitelisted("192.0.2.10")
    for dependency in dependencies:
        for call in dependency.mock_calls:
            assert call[0].split(".")[0] in {"get_by_mac", "get_entry", "get_engine_config", "rules", "rules_by_id"}


@pytest.mark.asyncio
async def test_concurrent_whitelist_toggles_keep_correct_before_and_after(secured_app):
    import asyncio
    app, _, whitelist, audit, _ = secured_app
    original = audit.log
    async def slow_log(**entry):
        if entry["action"] == "change_prepared":
            await asyncio.sleep(.01)
        return await original(**entry)
    audit.log = slow_log
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await asyncio.gather(*(client.post("/api/whitelist/toggle", headers=headers("admin"),
            json={"type": "ip", "value": "192.0.2.10"}) for _ in range(2)))
    assert all(response.status_code == 200 for response in responses)
    assert not whitelist.is_ip_whitelisted("192.0.2.10")
    results = [entry["details"] for entry in audit.entries if entry["action"] == "api_mutation"]
    assert {(entry["before"]["present"], entry["after"]["present"]) for entry in results} == {(False, True), (True, False)}


@pytest.mark.asyncio
async def test_unexpected_execution_failure_keeps_unknown_audit(secured_app):
    app, manager, _, audit, _ = secured_app
    async def fail(**kwargs):
        raise RuntimeError("backend unavailable")
    manager.block = fail
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post("/api/blocks", headers=headers("admin"), json={"ip": "192.0.2.10"})
    assert response.status_code == 500
    assert audit.entries[-1]["details"]["outcome"] == "unknown"
    assert manager.get_active_blocks() == []
    assert response.json()["execution_status"] == "unknown"
    assert response.headers["X-Request-ID"] == response.json()["request_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", [
    ("PATCH", "/api/engines/port_scan/toggle", {"enabled": True}),
    ("PUT", "/api/engines/port_scan/config", {"threshold": 20}),
])
async def test_engine_internal_error_is_not_returned_to_client(secured_app, method, path, body):
    app, _, _, audit, dependencies = secured_app
    dependencies[-1].ensure_writable.side_effect = RuntimeError("internal-file-and-database-details")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request(method, path, headers=headers("admin"), json=body)
    assert response.status_code == 500
    assert "internal-file-and-database-details" not in response.text
    assert audit.entries[-1]["details"]["outcome"] == "unknown"


@pytest.mark.parametrize("path", ["/api/blocks/new", "/api/incidents/{incident_id}/resolve"])
def test_gate_catches_new_route_without_admin_dependency(path):
    app = FastAPI()
    @app.post(path)
    async def unguarded():
        return {"ok": True}
    @app.delete("/api/blocks/protected", dependencies=[Depends(require_role(Role.ADMIN))])
    async def guarded():
        return {"ok": True}
    assert missing_admin_guards(app.routes) == ["POST " + path]
    assert gate_mutation_permissions().passed


@pytest.mark.asyncio
@pytest.mark.parametrize("role,status", [(None, 401), ("viewer", 200), ("analyst", 200), ("admin", 200)])
async def test_capabilities_require_authenticated_reader(secured_app, role, status):
    app, _, _, audit, _ = secured_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/capabilities", headers=headers(role))
    assert response.status_code == status
    if status == 200:
        features = response.json()["features"]
        assert features["engines"] and features["whitelist"] and features["defense"]
        assert not features["replay"] and not features["ai-analyzer"]
    if status == 401:
        assert [entry["action"] for entry in audit.entries] == ["access_denied"]
    else:
        assert audit.entries == []
