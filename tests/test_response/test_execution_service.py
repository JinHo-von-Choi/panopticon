"""실제 PostgreSQL의 승인 대조·중복 방지·결과 저장 실패."""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import threading
from uuid import UUID, uuid4

import pytest

from netwatcher.response.command import ExecutionCommand
from netwatcher.response.executor import ExecutionResult
from netwatcher.response.lifecycle import Approval, LifecycleError, candidate_hash
from netwatcher.response.service import ExecutionService
from netwatcher.storage.execution_claims import ExecutionClaims
from netwatcher.storage.repositories import ResponseActionRepository

pytestmark = pytest.mark.asyncio


class Backend:
    name = "test"

    def __init__(self):
        self.calls = []

    def apply(self, request):
        self.calls.append(request)
        return ExecutionResult("confirmed", "present", rule_fingerprint="a" * 64, backend=self.name)

    def remove(self, request):
        self.calls.append(request)
        return ExecutionResult("absent", "absent", backend=self.name)

    def verify(self, request):
        return ExecutionResult("confirmed", "present", rule_fingerprint="a" * 64, backend=self.name)


async def setup_action(db):
    actor = uuid4()
    await db.pool.execute("""INSERT INTO user_accounts(id,username,password_hash,role,version,changed_by)
        VALUES($1,'admin','fixture','admin',2,'fixture')""", actor)
    device = await db.pool.fetchval("""INSERT INTO devices(mac_address,ip_address)
        VALUES('02:00:00:00:00:01','8.8.8.8') RETURNING id""")
    key = str(uuid4())
    now = datetime.now(timezone.utc)
    scope = {"asset": "router"}
    action_id = await ResponseActionRepository(db).create_requested(
        proposal_id=None, approval=Approval(candidate_hash("8.8.8.8", "input", 300, scope),
        f"device:{device}:0", str(actor), now, "8.8.8.8", "input", 300), idempotency_key=key, mapping_confirmed_at=now)
    claims = ExecutionClaims(db)
    binding = await claims.bind(action_id, actor_id=str(actor), actor_version=2, device_id=device,
                                scope=scope, reason="격리된 시험 경로에서 승인")
    command = ExecutionCommand.from_bytes(json.dumps(dict(
        version=1, operation="apply", action_id=action_id, idempotency_key=key,
        actor_id=str(actor), actor_version=2, ownership_version=binding["ownership_version"],
        target="8.8.8.8", direction="input", ttl_seconds=300, scope=scope,
        reason=binding["reason"], approval_expires_at=binding["approval_expires_at"])).encode())
    return claims, command, device


async def test_completed_request_is_not_reapplied_or_extended(db):
    claims, command, _ = await setup_action(db)
    backend = Backend()
    shortened = await db.pool.fetchval("""UPDATE response_execution_bindings
        SET approval_expires_at=clock_timestamp()+interval '1 second' RETURNING approval_expires_at""")
    command = replace(command, approval_expires_at=datetime.fromisoformat(shortened))
    first = await ExecutionService(claims, backend)(command)
    initial = await ResponseActionRepository(db).get(command.action_id)
    # 실제 저장된 승인 기간이 끝나도 기존 영수증을 되돌려 주며 다시 실행하지 않는다.
    await asyncio.sleep(1.1)
    second = await ExecutionService(ExecutionClaims(db), backend)(command)
    assert first.as_dict() == second.as_dict()
    current = await ResponseActionRepository(db).get(command.action_id)
    assert current["expire_at"] == initial["expire_at"]
    assert current["attempt_count"] == 1
    assert len(backend.calls) == 1
    assert backend.calls[0].expires_at == datetime.fromisoformat(initial["expire_at"])
    assert await db.pool.fetchval("SELECT count(*) FROM response_receipts") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='execution_prepared'") == 1


async def test_prepared_request_after_restart_is_unknown_not_reexecuted(db):
    claims, command, _ = await setup_action(db)
    assert await claims.prepare(command) is None
    backend = Backend()
    result = await ExecutionService(ExecutionClaims(db), backend)(command)
    assert result.observed == "unknown" and not result.verified
    assert backend.calls == []
    assert await db.pool.fetchval("SELECT attempt_count FROM response_actions") == 1


@pytest.mark.parametrize("change", ["disabled", "role", "version", "mapping", "shared", "scope", "ownership", "base_version", "reason", "expiry"])
async def test_independent_database_changes_refuse_execution(db, change):
    claims, command, device = await setup_action(db)
    if change == "disabled":
        await db.pool.execute("UPDATE user_accounts SET enabled=FALSE")
    elif change == "role":
        await db.pool.execute("UPDATE user_accounts SET role='viewer'")
    elif change == "version":
        await db.pool.execute("UPDATE user_accounts SET version=3")
    elif change == "mapping":
        await db.pool.execute("UPDATE devices SET ip_address='8.8.4.4' WHERE id=$1", device)
    elif change == "shared":
        await db.pool.execute("INSERT INTO devices(mac_address,ip_address) VALUES('02:00:00:00:00:02','8.8.8.8')")
    elif change == "scope":
        command = replace(command, scope_json=b'{"asset":"different"}')
    elif change == "ownership":
        command = replace(command, ownership_version="forged-v2")
    elif change == "base_version":
        await db.pool.execute("UPDATE response_actions SET base_version='forged-v2'")
    elif change == "reason":
        command = replace(command, reason="위조 사유")
    elif change == "expiry":
        command = replace(command, approval_expires_at=command.approval_expires_at.replace(year=2027))
    backend = Backend()
    with pytest.raises(LifecycleError):
        await ExecutionService(claims, backend)(command)
    assert backend.calls == []
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0


async def reject_insert(db, table, condition="TRUE"):
    # 테이블과 조건은 시험 안에서 정한 고정값만 사용한다.
    await db.pool.execute(f"""CREATE FUNCTION reject_execution_insert() RETURNS trigger AS $$
        BEGIN IF {condition} THEN RAISE EXCEPTION 'injected storage failure'; END IF; RETURN NEW; END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER reject_execution_insert BEFORE INSERT ON {table}
        FOR EACH ROW EXECUTE FUNCTION reject_execution_insert();""")


async def test_required_intent_audit_failure_has_no_execution_or_claim(db):
    claims, command, _ = await setup_action(db)
    await reject_insert(db, "audit_log", "NEW.action = 'execution_prepared'")
    backend = Backend()
    with pytest.raises(LifecycleError) as error:
        await ExecutionService(claims, backend)(command)
    assert error.value.status_code == 503
    assert backend.calls == []
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0
    action = await ResponseActionRepository(db).get(command.action_id)
    assert action["state"] == "requested" and action["expire_at"] is None


async def test_result_storage_failure_preserves_prepared_and_never_retries(db):
    claims, command, _ = await setup_action(db)
    await reject_insert(db, "response_receipts")
    backend = Backend()
    with pytest.raises(LifecycleError) as error:
        await ExecutionService(claims, backend)(command)
    assert error.value.status_code == 503
    assert len(backend.calls) == 1
    assert await db.pool.fetchval("SELECT status FROM response_execution_claims") == "prepared"
    assert await db.pool.fetchval("SELECT count(*) FROM response_receipts") == 0
    result = await ExecutionService(ExecutionClaims(db), backend)(command)
    assert result.observed == "unknown" and len(backend.calls) == 1


async def test_concurrent_requests_execute_once(db):
    claims, command, _ = await setup_action(db)
    backend = Backend()
    results = await asyncio.gather(*(ExecutionService(ExecutionClaims(db), backend)(command) for _ in range(4)))
    assert len(backend.calls) == 1
    assert any(result.verified for result in results)
    assert all(result.verified or result.observed == "unknown" for result in results)


async def test_account_change_waits_until_backend_finishes(db):
    claims, command, _ = await setup_action(db)
    started, release = threading.Event(), threading.Event()

    class WaitingBackend(Backend):
        def apply(self, request):
            started.set()
            if not release.wait(3):
                raise TimeoutError("test release missing")
            return super().apply(request)

    backend = WaitingBackend()
    execute = asyncio.create_task(ExecutionService(claims, backend)(command))
    update = None
    try:
        assert await asyncio.to_thread(started.wait, 3)
        update = asyncio.create_task(db.pool.execute("UPDATE user_accounts SET enabled=FALSE WHERE id=$1", UUID(command.actor_id)))
        await asyncio.sleep(0.05)
        assert not update.done()
    finally:
        release.set()
        result = await execute
        if update is not None:
            await update
    assert result.verified
    with pytest.raises(LifecycleError):
        await ExecutionService(claims, backend)(command)
    assert len(backend.calls) == 1


async def test_removal_after_expiry_and_mapping_change_preserves_original_target(db):
    claims, command, device = await setup_action(db)
    backend = Backend()
    shortened = await db.pool.fetchval("""UPDATE response_execution_bindings
        SET approval_expires_at=clock_timestamp()+interval '1 second' RETURNING approval_expires_at""")
    command = replace(command, approval_expires_at=datetime.fromisoformat(shortened))
    await ExecutionService(claims, backend)(command)
    await asyncio.sleep(1.1)
    await db.pool.execute("UPDATE devices SET ip_address='8.8.4.4' WHERE id=$1", device)
    remove = replace(command, operation="remove")
    result = await ExecutionService(claims, backend)(remove)
    assert result.observed == "absent"
    assert backend.calls[-1].target == "8.8.8.8"
    assert await db.pool.fetchval("SELECT state FROM response_actions") == "removed_verified"
    await ExecutionService(claims, backend)(remove)
    assert len(backend.calls) == 2


async def test_remove_without_apply_has_no_execution(db):
    claims, command, _ = await setup_action(db)
    backend = Backend()
    with pytest.raises(LifecycleError):
        await ExecutionService(claims, backend)(replace(command, operation="remove"))
    assert backend.calls == []
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_claims") == 0


async def test_global_apply_rate_limit_and_claim_capacity(db, monkeypatch):
    import netwatcher.storage.execution_claims as module
    claims, command, _ = await setup_action(db)
    await ExecutionService(claims, Backend())(command)
    # 독립적으로 승인한 두 번째 조치에도 같은 DB 제한을 적용한다.
    action = await ResponseActionRepository(db).get(command.action_id)
    now = datetime.now(timezone.utc)
    key = str(uuid4())
    second_id = await ResponseActionRepository(db).create_requested(
        proposal_id=None, approval=Approval(action["approved_hash"], command.ownership_version, command.actor_id, now,
        command.target, command.direction, command.ttl_seconds), idempotency_key=key, mapping_confirmed_at=now)
    device_id = await db.pool.fetchval("SELECT id FROM devices LIMIT 1")
    binding = await claims.bind(second_id, actor_id=command.actor_id, actor_version=2, device_id=device_id,
                               scope=json.loads(command.scope_json), reason="second test")
    second = replace(command, action_id=second_id, idempotency_key=key, ownership_version=binding["ownership_version"],
                     reason=binding["reason"], approval_expires_at=datetime.fromisoformat(binding["approval_expires_at"]))
    with pytest.raises(LifecycleError) as error:
        await claims.prepare(second)
    assert error.value.status_code == 429
    await db.pool.execute("UPDATE response_execution_claims SET prepared_at=NOW()-interval '2 minutes'")
    monkeypatch.setattr(module, "MAX_APPLY_CLAIMS", 1)
    with pytest.raises(LifecycleError) as error:
        await claims.prepare(second)
    assert error.value.status_code == 429
    assert await db.pool.fetchval("SELECT state FROM response_actions WHERE id=$1", second_id) == "requested"


async def test_unverified_os_backend_cannot_start_service(db):
    claims = ExecutionClaims(db)
    backend = Backend()
    backend.applies_to_os = True
    with pytest.raises(ValueError):
        ExecutionService(claims, backend)


async def test_active_admin_can_recover_disabled_approvers_action(db):
    claims, command, _ = await setup_action(db)
    backend = Backend()
    await ExecutionService(claims, backend)(command)
    successor = uuid4()
    await db.pool.execute("""INSERT INTO user_accounts(id,username,password_hash,role,changed_by)
        VALUES($1,'successor','fixture','admin','fixture')""", successor)
    await db.pool.execute("UPDATE user_accounts SET enabled=FALSE WHERE id=$1", UUID(command.actor_id))
    successor_command = replace(command, actor_id=str(successor), actor_version=1)
    with pytest.raises(LifecycleError):
        await ExecutionService(claims, backend)(successor_command)
    assert (await ExecutionService(claims, backend)(replace(successor_command, operation="verify"))).verified
    removed = await ExecutionService(claims, backend)(replace(successor_command, operation="remove"))
    assert removed.observed == "absent"
    third = uuid4()
    await db.pool.execute("""INSERT INTO user_accounts(id,username,password_hash,role,changed_by)
        VALUES($1,'third-admin','fixture','admin','fixture')""", third)
    replayed = await ExecutionService(claims, backend)(replace(command, operation="remove", actor_id=str(third), actor_version=1))
    assert replayed.as_dict() == removed.as_dict()
    assert len(backend.calls) == 2
    receipts = await db.pool.fetch("SELECT user_id FROM audit_log WHERE action='execution_result' AND details->>'operation'='remove'")
    assert [row["user_id"] for row in receipts] == [str(successor)]


async def test_mapping_change_before_binding_requires_new_approval(db):
    claims, command, device = await setup_action(db)
    action = await ResponseActionRepository(db).get(command.action_id)
    now = datetime.now(timezone.utc)
    pending_id = await ResponseActionRepository(db).create_requested(
        proposal_id=None, approval=Approval(action["approved_hash"], command.ownership_version,
        command.actor_id, now, command.target, command.direction, command.ttl_seconds),
        idempotency_key=str(uuid4()), mapping_confirmed_at=now)
    await db.pool.execute("UPDATE devices SET ip_address='8.8.4.4' WHERE id=$1", device)
    await db.pool.execute("UPDATE devices SET ip_address='8.8.8.8' WHERE id=$1", device)
    with pytest.raises(LifecycleError):
        await claims.bind(pending_id, actor_id=command.actor_id, actor_version=2, device_id=device,
                          scope=json.loads(command.scope_json), reason="stale ownership")
    assert await db.pool.fetchval("SELECT count(*) FROM response_execution_bindings WHERE action_id=$1", pending_id) == 0


async def test_non_utc_database_session_produces_canonical_wire_expiry(db):
    from netwatcher.storage.database import _init_connection

    # 이 시험만의 독립 풀을 사용하고 기존 fixture 풀과 자료를 공유한다.
    import asyncpg
    original = db.pool
    pool = await asyncpg.create_pool(
        host=db._pg_host, port=db._pg_port, database=db._pg_database,
        user=db._pg_user, password=db._pg_password, min_size=1, max_size=1,
        server_settings={"search_path": db._search_path, "timezone": "Asia/Seoul"}, init=_init_connection,
    )
    db._pool = pool
    try:
        local_clock = datetime.fromisoformat(await pool.fetchval("SELECT clock_timestamp()"))
        assert local_clock.utcoffset() == timedelta(hours=9)
        claims, command, _ = await setup_action(db)
        assert command.approval_expires_at.utcoffset().total_seconds() == 0
        assert ExecutionCommand.from_bytes(command.to_bytes()) == command
        assert (await ExecutionService(claims, Backend())(command)).verified
    finally:
        db._pool = original
        await pool.close()
