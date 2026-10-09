"""실제 로그인·PostgreSQL·별도 CLI 실행기를 연결한 조치 API 시험."""

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import signal
import sys
from types import SimpleNamespace

import bcrypt
import httpx
import pytest
import pytest_asyncio
import yaml

from netwatcher.alerts.stream import EventStream
from netwatcher.storage.repositories import EventRepository, DeviceRepository, TrafficStatsRepository, ResponseActionRepository, ResponseProposalRepository
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.web.auth import AuthManager
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from netwatcher.storage.execution_claims import ExecutionClaims
from netwatcher.response.lifecycle import LifecycleError
from netwatcher.response.remote import configured_remote_executor
from netwatcher.utils.config import Config
from tests.test_response.test_execution_service import reject_insert

PASSWORD = "RemoteFixturePassword-2026"


@pytest_asyncio.fixture
async def remote_case(db, config, tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
    config.raw["auth"] = {"enabled": True, "multi_user": True, "username": "admin",
        "password": bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode(),
        "jwt_secret": secrets.token_hex(32), "api_rate_limit": {"enabled": False}, "login_attempts_per_minute": 1000}
    path = tmp_path / "executor.sock"
    config.raw["response_execution"] = {
        "remote": {"enabled": True, "socket_path": str(path), "expected_uid": os.getuid()},
        "worker": {"enabled": True, "socket_path": str(path), "allowed_uid": os.getuid()}}
    users = UserAccounts(db)
    manager = AuthManager(config, users=users)
    await manager.initialize()
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
        auth_manager=manager, audit_logger=AuditLogger(db.pool), audit_required=True,
        response_repository=ResponseActionRepository(db), response_proposal_repo=ResponseProposalRepository(db))
    child = None
    log_path = tmp_path / "worker.log"
    log_path.touch(mode=0o600)
    config_path = tmp_path / "worker.yaml"
    config_path.write_text(yaml.safe_dump({"netwatcher": deepcopy(config.raw)}, allow_unicode=True))
    config_path.chmod(0o600)
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(("NETWATCHER_DB_", "NETWATCHER_LOGIN_")) or key == "PYTHONPATH":
            env.pop(key)
    env["NETWATCHER_SKIP_DOTENV"] = "1"
    with log_path.open("ab") as log:
        try:
            child = await asyncio.create_subprocess_exec(sys.executable, "-m", "netwatcher", "--component", "executor",
                "-c", str(config_path), cwd=Path(__file__).resolve().parents[2], env=env, stdout=log, stderr=log)
            async with asyncio.timeout(10):
                while not path.exists():
                    assert child.returncode is None, "executor stopped; inspect private worker.log"
                    await asyncio.sleep(0.02)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                login = await client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
                assert login.status_code == 200
                header = {"Authorization": "Bearer " + login.json()["token"]}
                device = await db.pool.fetchval("""INSERT INTO devices(mac_address,ip_address)
                    VALUES('02:00:00:00:00:01','8.8.8.8') RETURNING id""")
                created = await client.post("/api/response-proposals", headers=header, json={
                    "source_ip": "8.8.8.8", "visibility_state": "observed", "asset_id": "router",
                    "scope_kind": "asset", "scope_asset_id": "router", "confirmed_at": datetime.now(timezone.utc).isoformat()})
                assert created.status_code == 201, created.text
                proposal = created.json()["proposal_id"]
                body = {"target": "8.8.8.8", "direction": "input", "ttl_seconds": 300,
                    "scope": {"asset": "router"}, "base_version": f"device:{device}:0", "device_id": device,
                    "reason": "관리자가 확인한 격리 조치"}
                yield SimpleNamespace(client=client, header=header, body=body, proposal=proposal,
                                      users=users, manager=manager, app=app, child=child, device=device)
        finally:
            if child is not None and child.returncode is None:
                child.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(child.wait(), 5)
                except TimeoutError:
                    child.kill()
                    await child.wait()
            if child is not None:
                assert child.returncode == 0
            assert not path.exists()


async def approve(case, **changes):
    return await case.client.post(f"/api/change-proposals/{case.proposal}/approve", headers=case.header,
                                  json={**case.body, **changes})


def activation(case):
    return {key: value for key, value in case.body.items() if key not in {"device_id", "reason"}}


@pytest.mark.asyncio
async def test_real_http_approval_and_separate_shadow_worker_are_idempotent(remote_case, db):
    case = remote_case
    approved = await approve(case)
    assert approved.status_code == 201, approved.text
    action_id = approved.json()["action_id"]
    detail = (await case.client.get(f"/api/response-actions/{action_id}", headers=case.header)).json()["action"]
    listing = (await case.client.get("/api/response-actions", headers=case.header)).json()["actions"]
    assert detail["binding"] == listing[0]["binding"]
    assert detail["binding"]["scope"] == case.body["scope"]
    assert detail["binding"]["reason"] == case.body["reason"]
    assert detail["binding"]["device_id"] == case.device
    assert detail["binding"]["mapping_version"] == 0
    assert datetime.fromisoformat(detail["binding"]["approval_expires_at"]).tzinfo is not None
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0
    assert await db.pool.fetchval("SELECT approved_by FROM response_actions") == (await case.manager.verify_token_async(case.header["Authorization"][7:]))["uid"]
    url = f"/api/response-actions/{action_id}"
    first = await case.client.post(url + "/activate", headers=case.header, json=activation(case))
    assert first.status_code == 200, first.text
    assert first.json()["state"] == "unknown" and first.json()["result"]["backend"] == "shadow"
    assert first.json()["verified"] is False
    second = await case.client.post(url + "/activate", headers=case.header, json=activation(case))
    assert second.status_code == 200 and second.json()["expire_at"] == first.json()["expire_at"]
    assert await db.pool.fetchval("SELECT attempt_count FROM response_actions") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM response_receipts") == 1
    assert (await case.client.post(url + "/verify", headers=case.header)).status_code == 200
    assert (await case.client.post(url + "/remove", headers=case.header)).status_code == 200
    assert (await case.client.get(url, headers=case.header)).json()["action"]["state"] == "unknown"
    assert (await approve(case)).status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_non_admin_cannot_approve_apply_verify_or_remove(remote_case, db, role):
    case = remote_case
    await case.users.create(role, PASSWORD, role, "admin")
    login = await case.client.post("/api/auth/login", json={"username": role, "password": PASSWORD})
    header = {"Authorization": "Bearer " + login.json()["token"]}
    assert (await case.client.post(f"/api/change-proposals/{case.proposal}/approve", headers=header, json=case.body)).status_code == 403
    for operation in ("activate", "verify", "remove"):
        response = await case.client.post(f"/api/response-actions/1/{operation}", headers=header,
                                         json=activation(case) if operation == "activate" else None)
        assert response.status_code == 403
    assert await db.pool.fetchval("SELECT count(*) FROM response_actions") == 0
    assert (await case.client.get("/api/response-actions", headers=header)).status_code == 200


@pytest.mark.asyncio
async def test_approval_audit_failure_rolls_back_action_binding_and_proposal(remote_case, db):
    case = remote_case
    await reject_insert(db, "audit_log", "NEW.action = 'execution_authorized'")
    assert (await approve(case)).status_code == 503
    assert await db.pool.fetchval("SELECT count(*) FROM response_actions") == 0
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_bindings") == 0
    assert await db.pool.fetchval("SELECT status FROM response_proposals") == "proposed"


@pytest.mark.asyncio
async def test_concurrent_approval_commits_one_action(remote_case, db):
    replies = await asyncio.gather(*(approve(remote_case) for _ in range(3)))
    assert sorted(reply.status_code for reply in replies) == [201, 409, 409]
    assert await db.pool.fetchval("SELECT count(*) FROM response_actions") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_bindings") == 1


@pytest.mark.asyncio
async def test_mutated_activation_and_foreign_key_do_not_reach_worker(remote_case, db):
    case = remote_case
    action_id = (await approve(case)).json()["action_id"]
    url = f"/api/response-actions/{action_id}/activate"
    changed = {**activation(case), "ttl_seconds": 600}
    assert (await case.client.post(url, headers=case.header, json=changed)).status_code == 409
    assert (await case.client.post(url, headers={**case.header, "Idempotency-Key": str(secrets.token_hex(16))}, json=activation(case))).status_code == 409
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0


@pytest.mark.asyncio
async def test_changed_ownership_is_rejected_by_actual_worker(remote_case, db):
    case = remote_case
    action_id = (await approve(case)).json()["action_id"]
    await db.pool.execute("UPDATE devices SET ip_address='8.8.4.4' WHERE id=$1", case.device)
    reply = await case.client.post(f"/api/response-actions/{action_id}/activate", headers=case.header, json=activation(case))
    assert reply.status_code == 409, reply.text
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0


@pytest.mark.asyncio
async def test_worker_unavailable_keeps_approval_unexecuted(remote_case, db):
    case = remote_case
    action_id = (await approve(case)).json()["action_id"]
    case.child.send_signal(signal.SIGTERM)
    await asyncio.wait_for(case.child.wait(), 5)
    reply = await case.client.post(f"/api/response-actions/{action_id}/activate", headers=case.header, json=activation(case))
    assert reply.status_code == 503
    assert await db.pool.fetchval("SELECT state FROM response_actions") == "requested"
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0


@pytest.mark.asyncio
async def test_role_change_after_gateway_validation_blocks_approval(remote_case, db, monkeypatch):
    case = remote_case
    await case.users.create("other-admin", PASSWORD, "admin", "admin")
    admin = await case.users.get_by_username("admin")
    original = ExecutionClaims.approve

    async def race(self, *args, **kwargs):
        await case.users.update(admin["id"], admin["version"], role="viewer", enabled=True, actor="other-admin")
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(ExecutionClaims, "approve", race)
    assert (await approve(case)).status_code == 409
    assert await db.pool.fetchval("SELECT count(*) FROM response_actions") == 0


@pytest.mark.asyncio
async def test_role_change_before_socket_send_is_rechecked_by_worker(remote_case, db, monkeypatch):
    import netwatcher.response.remote as remote
    case = remote_case
    action_id = (await approve(case)).json()["action_id"]
    await case.users.create("other-admin", PASSWORD, "admin", "admin")
    admin = await case.users.get_by_username("admin")
    original = remote.send_command

    async def race(*args, **kwargs):
        await case.users.update(admin["id"], admin["version"], role="viewer", enabled=True, actor="other-admin")
        return await original(*args, **kwargs)

    monkeypatch.setattr(remote, "send_command", race)
    reply = await case.client.post(f"/api/response-actions/{action_id}/activate", headers=case.header, json=activation(case))
    assert reply.status_code == 409
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0


@pytest.mark.asyncio
async def test_response_loss_after_actual_worker_commit_does_not_reexecute(remote_case, db, monkeypatch):
    import netwatcher.response.remote as remote
    case = remote_case
    action_id = (await approve(case)).json()["action_id"]
    original = remote.send_command
    calls = []

    async def lost(*args, **kwargs):
        result = await original(*args, **kwargs)
        calls.append(result)
        raise LifecycleError("응답 유실 시험", 503)

    monkeypatch.setattr(remote, "send_command", lost)
    url = f"/api/response-actions/{action_id}/activate"
    assert (await case.client.post(url, headers=case.header, json=activation(case))).status_code == 503
    assert len(calls) == 1
    expires = await db.pool.fetchval("SELECT expire_at FROM response_actions")
    monkeypatch.setattr(remote, "send_command", original)
    retry = await case.client.post(url, headers=case.header, json=activation(case))
    assert retry.status_code == 200
    assert await db.pool.fetchval("SELECT expire_at FROM response_actions") == expires
    assert await db.pool.fetchval("SELECT attempt_count FROM response_actions") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM response_receipts") == 1


@pytest.mark.asyncio
async def test_gate_checks_admin_guards_on_remote_routes(remote_case):
    from scripts.gates import missing_admin_guards
    assert missing_admin_guards(remote_case.app.routes) == []


@pytest.mark.parametrize("settings", [
    None, [], {"enabled": "true"}, {"enabled": 0},
    {"enabled": True, "socket_path": "relative", "expected_uid": 1000},
    {"enabled": True, "socket_path": "/run/example.sock", "expected_uid": True},
    {"enabled": True, "socket_path": "/run/example.sock", "expected_uid": -1},
    {"enabled": True, "socket_path": "/run/example.sock", "expected_uid": 1000, "backend": "nftables"},
])
def test_remote_settings_fail_closed(settings):
    manager = SimpleNamespace(enabled=True, multi_user=True, users=object())
    with pytest.raises(ValueError):
        configured_remote_executor(Config({"response_execution": {"remote": settings}}), manager, object())


def test_remote_refuses_anonymous_or_legacy_blocking():
    settings = {"enabled": True, "socket_path": "/run/example.sock", "expected_uid": 1000}
    cfg = Config({"response_execution": {"remote": settings}})
    with pytest.raises(ValueError):
        configured_remote_executor(cfg, SimpleNamespace(enabled=False, multi_user=True, users=object()), object())
    with pytest.raises(ValueError):
        configured_remote_executor(cfg, SimpleNamespace(enabled=True, multi_user=False, users=object()), object())
    manager = SimpleNamespace(enabled=True, multi_user=True, users=object())
    cfg.raw["response"] = {"enabled": True}
    with pytest.raises(ValueError):
        configured_remote_executor(cfg, manager, object())


@pytest.mark.asyncio
async def test_operation_deadline_after_worker_commit_is_unknown_without_retry(remote_case, db, monkeypatch):
    from netwatcher.response.remote import RemoteExecutor
    import netwatcher.web.routes.remote_response as routes
    case = remote_case
    action_id = (await approve(case)).json()["action_id"]
    original = RemoteExecutor.execute
    calls = []

    async def delayed(self, command):
        result = await original(self, command)
        calls.append(result)
        await asyncio.sleep(2)
        return result

    monkeypatch.setattr(RemoteExecutor, "execute", delayed)
    monkeypatch.setattr(routes, "OPERATION_TIMEOUT_SECONDS", 1)
    reply = await case.client.post(f"/api/response-actions/{action_id}/activate", headers=case.header, json=activation(case))
    assert reply.status_code == 503
    assert len(calls) == 1
    assert await db.pool.fetchval("SELECT attempt_count FROM response_actions") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM response_receipts") == 1
