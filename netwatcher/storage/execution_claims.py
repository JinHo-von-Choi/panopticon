"""실행기의 독립 승인 조회와 영속 중복 실행 방지."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID
from uuid import uuid4
from contextlib import asynccontextmanager

from netwatcher.response.command import ActionAuthorization, ExecutionCommand, MAX_APPROVAL_AGE_SECONDS
from netwatcher.response.executor import ExecutionResult
from netwatcher.response.lifecycle import LifecycleError, candidate_hash

MAX_APPLY_CLAIMS = 10000

def _time(value) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("실행 기록의 시각에는 시간대가 필요합니다")
    return parsed.astimezone(timezone.utc)


def _refuse() -> LifecycleError:
    return LifecycleError("조치의 승인·계정·소유 관계를 확인할 수 없습니다", 409)


def command_hash(command: ExecutionCommand) -> str:
    values = dict(command.__dict__)
    values["scope_json"] = command.scope_json.decode()
    values["approval_expires_at"] = command.approval_expires_at.isoformat()
    if command.operation == "remove":
        # 인계받은 활성 관리자도 같은 해제 결과를 조회할 수 있다.
        values.pop("actor_id")
        values.pop("actor_version")
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ExecutionClaims:
    def __init__(self, db, *, protected: tuple[str, ...] = ()) -> None:
        self.db = db
        self.protected = protected

    @asynccontextmanager
    async def _connection(self, existing=None):
        if existing is not None:
            if not existing.is_in_transaction():
                raise ValueError("승인 연결에는 트랜잭션이 필요합니다")
            yield existing
        else:
            async with self.db.pool.acquire() as conn, conn.transaction():
                yield conn

    async def approve(self, proposal_id: int, *, actor_id: str, actor_version: int,
                      device_id: int, target: str, direction: str, ttl_seconds: int,
                      scope: dict, base_version: str, reason: str) -> dict:
        """계정 재검증·승인 조치·소유 연결·감사를 한 트랜잭션에 저장한다."""
        async with self._connection() as conn:
            user = await conn.fetchrow("SELECT * FROM user_accounts WHERE id=$1 FOR SHARE", UUID(actor_id))
            proposal = await conn.fetchrow("SELECT * FROM response_proposals WHERE id=$1 FOR UPDATE", proposal_id)
            if (user is None or not user["enabled"] or user["role"] != "admin"
                    or user["version"] != actor_version or proposal is None
                    or proposal["status"] != "proposed" or proposal["source_ip"] != target
                    or proposal["ttl_seconds"] != ttl_seconds
                    or proposal["visibility_state"] not in {"observed", "partial"}):
                raise _refuse()
            mapping = proposal["target_mapping"]
            match = proposal["match_scope"]
            if (not isinstance(mapping, dict) or not isinstance(match, dict)
                    or mapping.get("ip") != target or mapping.get("shared") is not False
                    or mapping.get("protected") is not False or not mapping.get("confirmed_at")
                    or match.get("kind") != "asset" or match.get("service_aware") is not False
                    or not isinstance(scope, dict) or set(scope) != {"asset"}
                    or scope["asset"] != mapping.get("asset_id") or scope["asset"] != match.get("asset_id")):
                raise _refuse()
            now = _time(await conn.fetchval("SELECT clock_timestamp()"))
            key = str(uuid4())
            await conn.execute("""INSERT INTO audit_log(user_id,action,resource,details)
                VALUES($1,'execution_approval_intent','response_proposals',$2)""", actor_id,
                {"proposal_id": proposal_id, "device_id": device_id, "reason": reason})
            action_id = await conn.fetchval("""INSERT INTO response_actions
                (proposal_id,target,direction,ttl_seconds,state,approved_hash,base_version,
                 approved_by,approved_at,idempotency_key,mapping_confirmed_at)
                VALUES($1,$2,$3,$4,'requested',$5,$6,$7,$8,$9,$10) RETURNING id""",
                proposal_id, target, direction, ttl_seconds,
                candidate_hash(target, direction, ttl_seconds, scope), base_version, actor_id,
                now, key, _time(mapping["confirmed_at"]))
            binding = await self.bind(action_id, actor_id=actor_id, actor_version=actor_version,
                                      device_id=device_id, scope=scope, reason=reason, _connection=conn)
            await conn.execute("UPDATE response_proposals SET status='approved' WHERE id=$1", proposal_id)
            return {"action_id": action_id, "state": "requested", "idempotency_key": key, **binding}

    async def bind(self, action_id: int, *, actor_id: str, actor_version: int,
                   device_id: int, scope: dict, reason: str, _connection=None) -> dict:
        """승인 조치에 실제 계정·현재 장치 소유 관계를 한 번만 연결한다."""
        if not isinstance(reason, str) or not 0 < len(reason) <= 512 or not reason.isprintable():
            raise _refuse()
        async with self._connection(_connection) as conn:
            await conn.execute("SELECT pg_advisory_xact_lock(178903421, 2)")
            if await conn.fetchval("SELECT count(*) FROM response_execution_bindings") >= MAX_APPLY_CLAIMS:
                raise LifecycleError("승인 연결 한도에 도달했습니다", 429)
            user = await conn.fetchrow("SELECT * FROM user_accounts WHERE id=$1 FOR SHARE", UUID(actor_id))
            action = await conn.fetchrow("SELECT * FROM response_actions WHERE id=$1 FOR UPDATE", action_id)
            device = await conn.fetchrow("SELECT * FROM devices WHERE id=$1 FOR SHARE", device_id)
            now = _time(await conn.fetchval("SELECT clock_timestamp()"))
            if (user is None or action is None or device is None or not user["enabled"]
                    or user["role"] != "admin" or user["version"] != actor_version
                    or action["approved_by"] != actor_id or action["state"] != "requested"
                    or device["ip_address"] != action["target"] or action["approved_at"] is None
                    or action["mapping_confirmed_at"] is None
                    or await conn.fetchval("SELECT count(*) FROM devices WHERE ip_address=$1", action["target"]) != 1):
                raise _refuse()
            expires = _time(action["approved_at"]) + timedelta(seconds=MAX_APPROVAL_AGE_SECONDS)
            if not _time(action["approved_at"]) <= now < expires:
                raise _refuse()
            if candidate_hash(action["target"], action["direction"], action["ttl_seconds"], scope) != action["approved_hash"]:
                raise _refuse()
            ownership = f"device:{device_id}:{device['ip_mapping_version']}"
            if action["base_version"] != ownership:
                raise _refuse()
            # 같은 전송 계약으로 scope·주소 등도 제한한다.
            command = ExecutionCommand.from_bytes(json.dumps(dict(
                version=1, operation="apply", action_id=action_id,
                idempotency_key=action["idempotency_key"], actor_id=actor_id,
                actor_version=actor_version, ownership_version=ownership, target=action["target"],
                direction=action["direction"], ttl_seconds=action["ttl_seconds"], scope=scope,
                reason=reason, approval_expires_at=expires.isoformat(),
            )).encode())
            command.validate_authorization(ActionAuthorization(
                action_id, action["idempotency_key"], action["approved_hash"],
                _time(action["approved_at"]), expires, actor_id, user["version"], user["enabled"],
                user["role"], ownership, _time(action["mapping_confirmed_at"]), True, reason,
            ), now=now, protected=self.protected)
            inserted = await conn.fetchval("""INSERT INTO response_execution_bindings
                (action_id,actor_id,actor_version,device_id,mapping_version,scope,reason,approval_expires_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING RETURNING action_id""",
                action_id, UUID(actor_id), actor_version, device_id, device["ip_mapping_version"], scope, reason, expires)
            if inserted is None:
                raise _refuse()
            await self._audit(conn, command, "execution_authorized", {"device_id": device_id, "reason": reason})
            return {"ownership_version": ownership, "approval_expires_at": expires.isoformat(), "reason": reason}

    async def command(self, action_id: int, *, operation: str, actor_id: str, actor_version: int) -> ExecutionCommand:
        """웹은 저장된 승인 내용만 메시지로 복사한다. 실행기에서 다시 검증한다."""
        async with self.db.pool.acquire() as conn, conn.transaction(isolation="repeatable_read", readonly=True):
            row = await conn.fetchrow("""SELECT a.*,b.device_id,b.mapping_version,b.scope,b.reason,
                b.approval_expires_at FROM response_actions a JOIN response_execution_bindings b
                ON a.id=b.action_id WHERE a.id=$1""", action_id)
        if row is None:
            raise _refuse()
        return ExecutionCommand.from_bytes(json.dumps(dict(
            version=1, operation=operation, action_id=action_id, idempotency_key=row["idempotency_key"],
            actor_id=actor_id, actor_version=actor_version,
            ownership_version=f"device:{row['device_id']}:{row['mapping_version']}",
            target=row["target"], direction=row["direction"], ttl_seconds=row["ttl_seconds"], scope=row["scope"],
            reason=row["reason"], approval_expires_at=_time(row["approval_expires_at"]).isoformat(),
        )).encode())

    async def bindings(self, action_ids: list[int]) -> dict:
        """조치 화면에 필요한 승인 범위를 한 번에 읽는다."""
        if len(action_ids) > 200:
            raise ValueError("조치 조회 한도 초과")
        rows = await self.db.pool.fetch("""SELECT action_id,device_id,mapping_version,scope,reason,
            approval_expires_at FROM response_execution_bindings WHERE action_id=ANY($1::bigint[])""", action_ids)
        return {row["action_id"]: {**dict(row), "approval_expires_at": _time(row["approval_expires_at"]).isoformat()}
                for row in rows}

    async def validate(self, conn, command: ExecutionCommand, *, for_execution: bool = True) -> dict:
        """호출자가 유지하는 트랜잭션에서 계정·조치·장치 변경을 잠근다."""
        user = await conn.fetchrow("SELECT * FROM user_accounts WHERE id=$1 FOR SHARE", UUID(command.actor_id))
        action = await conn.fetchrow("SELECT * FROM response_actions WHERE id=$1 FOR UPDATE", command.action_id)
        binding = await conn.fetchrow("SELECT * FROM response_execution_bindings WHERE action_id=$1 FOR SHARE", command.action_id)
        if user is None or action is None or binding is None:
            raise _refuse()
        device = await conn.fetchrow("SELECT * FROM devices WHERE id=$1 FOR SHARE", binding["device_id"])
        if device is None:
            raise _refuse()
        if action["base_version"] != f"device:{binding['device_id']}:{binding['mapping_version']}":
            raise _refuse()
        if command.operation == "apply" and (
            str(binding["actor_id"]) != command.actor_id
            or binding["actor_version"] != command.actor_version
            or action["approved_by"] != command.actor_id
        ):
            raise _refuse()
        if for_execution and command.operation == "apply" and (
            device["ip_address"] != action["target"]
            or device["ip_mapping_version"] != binding["mapping_version"]
            or await conn.fetchval("SELECT count(*) FROM devices WHERE ip_address=$1", action["target"]) != 1
        ):
            raise _refuse()
        now = _time(await conn.fetchval("SELECT clock_timestamp()"))
        snapshot = ActionAuthorization(
            action["id"], action["idempotency_key"], action["approved_hash"],
            _time(action["approved_at"]), _time(binding["approval_expires_at"]),
            str(user["id"]), user["version"], user["enabled"], user["role"],
            f"device:{binding['device_id']}:{binding['mapping_version']}",
            _time(action["mapping_confirmed_at"]), action["state"] in {"requested", "applying"}, binding["reason"],
        )
        check = replace(command, operation="verify") if command.operation == "apply" and not for_execution else command
        check.validate_authorization(snapshot, now=now, protected=self.protected)
        if (command.target != action["target"] or command.direction != action["direction"]
                or command.ttl_seconds != action["ttl_seconds"] or json.loads(command.scope_json) != binding["scope"]):
            raise _refuse()
        return dict(action)

    async def prepare(self, command: ExecutionCommand) -> ExecutionResult | None:
        """의도·만료·감사를 먼저 커밋한다. 기존 prepared는 재실행하지 않는다."""
        if command.operation not in {"apply", "remove"}:
            raise LifecycleError("조회는 실행 의도를 예약하지 않습니다", 409)
        async with self.db.pool.acquire() as conn, conn.transaction():
            # 여러 실행기에서도 적용 속도 제한은 하나의 DB 시계로 계산한다.
            await conn.execute("SELECT pg_advisory_xact_lock(178903421, 1)")
            existing = await conn.fetchrow("SELECT * FROM response_execution_claims WHERE action_id=$1 AND operation=$2",
                                           command.action_id, command.operation)
            await self.validate(conn, command, for_execution=existing is None)
            fingerprint = command_hash(command)
            if existing is not None:
                if existing["request_hash"] != fingerprint:
                    raise _refuse()
                value = existing["result"]
                if value is None:
                    return ExecutionResult("unverified", "unknown", detail="기존 실행 의도의 결과를 대조해야 합니다", backend="executor")
                return ExecutionResult(value["outcome"], value["observed"], value.get("rule_fingerprint"), value.get("detail", ""), value["backend"])
            if command.operation == "apply":
                if await conn.fetchval("SELECT count(*) FROM response_execution_claims WHERE operation='apply'") >= MAX_APPLY_CLAIMS:
                    raise LifecycleError("실행 기록 한도에 도달했습니다", 429)
                recent = await conn.fetchval("""SELECT count(*) FROM response_execution_claims
                    WHERE operation='apply' AND prepared_at > clock_timestamp()-interval '1 minute'""")
                active = await conn.fetchval("""SELECT count(*) FROM response_actions
                    WHERE state IN ('applying','active_verified','unknown')""")
                if recent >= 1 or active >= 3:
                    raise LifecycleError("실행기 적용 한도를 초과했습니다", 429)
                await conn.execute("""UPDATE response_actions SET state='applying',attempt_count=attempt_count+1,
                    expire_at=COALESCE(expire_at,clock_timestamp()+ttl_seconds*interval '1 second'),updated_at=NOW()
                    WHERE id=$1""", command.action_id)
            elif not await conn.fetchval("""SELECT EXISTS(SELECT 1 FROM response_execution_claims
                WHERE action_id=$1 AND operation='apply')""", command.action_id):
                raise LifecycleError("해제할 적용 의도가 없습니다", 409)
            await conn.execute("""INSERT INTO response_execution_claims(action_id,operation,request_hash,status)
                VALUES($1,$2,$3,'prepared')""", command.action_id, command.operation, fingerprint)
            await self._audit(conn, command, "execution_prepared", {})
        return None

    @staticmethod
    async def _audit(conn, command: ExecutionCommand, action: str, details: dict) -> None:
        await conn.execute("""INSERT INTO audit_log(user_id,action,resource,details)
            VALUES($1,$2,'response_actions',$3)""", command.actor_id, action,
            {"action_id": command.action_id, "operation": command.operation,
             "idempotency_key": command.idempotency_key, **details})
