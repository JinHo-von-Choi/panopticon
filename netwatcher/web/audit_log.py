"""감사 로그 (Audit Trail).

API 호출에 대한 사용자 행위를 PostgreSQL에 기록한다.
저장 성공 여부를 반환한다. 필수 감사 호출자는 저장 실패 시 변경을 거절한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import asyncpg

logger = logging.getLogger("netwatcher.web.audit_log")


GENESIS_HASH = "0" * 64
ZERO_TENANT = UUID(int=0)


def _entry_hash(prev_hash, tenant_id, user_id, action, resource, details, ip, created_at):
    # JSONB 키 순서와 연결 세션의 시간대에 독립적인 표현을 사용한다.
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    timestamp = created_at.astimezone(timezone.utc).isoformat()
    payload = "".join((prev_hash, str(tenant_id), user_id or "", action,
                       resource or "", details_json, ip or "", timestamp))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _details(value):
    decoded = json.loads(value) if isinstance(value, str) else value
    if decoded is None:
        return {}
    if not isinstance(decoded, dict):
        raise ValueError("Invalid stored audit details")
    return decoded


class AuditLogger:
    """비동기 감사 로그 기록 및 조회."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def change_history(self, request_id: str) -> list[dict[str, Any]]:
        """한 변경의 의도·상세·결과를 조회한다. 저장소 실패를 빈 이력으로 숨기지 않는다."""
        rows = await self._pool.fetch(
            """WITH decisive AS (
                   SELECT id FROM audit_log WHERE details->>'request_id'=$1
                     AND action IN ('sensor_change_prepared','sensor_change_applied','sensor_change_archived')
                   ORDER BY created_at DESC,id DESC LIMIT 3
               ), recent AS (
                   SELECT id FROM audit_log WHERE details->>'request_id'=$1
                     AND action IN ('authorized_intent','change_prepared','api_mutation',
                                    'sensor_change_prepared','sensor_change_applied','sensor_change_archived')
                   ORDER BY created_at DESC,id DESC LIMIT 17
               )
               SELECT user_id,action,resource,details,created_at FROM audit_log
               WHERE id IN (SELECT id FROM decisive UNION SELECT id FROM recent)
               ORDER BY created_at,id""", request_id,
        )
        return [{"user": row["user_id"], "action": row["action"], "resource": row["resource"],
                 "details": _details(row["details"]),
                 "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"])} for row in rows]

    async def log(
        self,
        user: str,
        action: str,
        resource: str,
        details: dict[str, Any] | None = None,
        ip: str = "",
        tenant_id: UUID | str | None = None,
    ) -> bool:
        """감사 이벤트와 테넌트별 해시 연결을 원자적으로 저장한다."""
        try:
            async with self._pool.acquire() as conn, conn.transaction():
                # 새 테넌트의 첫 행은 전체 최신 행에 연결되므로 전체 기록을 직렬화한다.
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(current_schema()), "
                    "hashtext('audit_log_hash_chain'))"
                )
                if tenant_id is None:
                    context = await conn.fetchval("SELECT current_setting('app.current_tenant_id', true)")
                    tenant = UUID(context) if context and context != "system" else ZERO_TENANT
                else:
                    tenant = UUID(str(tenant_id))
                prev_hash = await conn.fetchval(
                    "SELECT entry_hash FROM audit_log WHERE tenant_id=$1 ORDER BY id DESC LIMIT 1", tenant,
                )
                if prev_hash is None:
                    prev_hash = await conn.fetchval("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
                prev_hash = prev_hash if prev_hash is not None else GENESIS_HASH
                action = action[:50]
                resource = resource[:200] if resource else ""
                ip = ip[:45] if ip else ""
                # PostgreSQL의 숫자 정규화까지 반영한 JSON으로 해시와 INSERT를 맞춘다.
                details_json = await conn.fetchval(
                    "SELECT $1::text::jsonb::text", json.dumps(details or {}, allow_nan=False),
                )
                now = datetime.now(timezone.utc)
                entry_hash = _entry_hash(prev_hash, tenant, user, action, resource,
                                         json.loads(details_json), ip, now)
                await conn.execute(
                    """INSERT INTO audit_log
                       (tenant_id,user_id,action,resource,details,ip,created_at,prev_hash,entry_hash)
                       VALUES ($1,$2,$3,$4,$5::text::jsonb,$6,$7,$8,$9)""",
                    tenant, user, action, resource, details_json, ip, now, prev_hash, entry_hash,
                )
            return True
        except asyncpg.UndefinedTableError:
            logger.debug("audit_log table does not exist; skipping audit entry")
        except Exception:
            logger.exception("Failed to write audit log entry")
        return False

    async def verify_chain(self, tenant_id: UUID | str | None = None) -> dict[str, Any]:
        """ID 순서로 연결과 내용을 검증한다. DB 오류는 호출자에게 전달한다.

        테넌트의 첫 행은 다른 테넌트의 최신 행을 참조할 수 있어 보이는 전체
        이력을 읽는다. 0 해시인 기존 행도 검증 성공으로 취급하지 않는다.
        """
        tenant = UUID(str(tenant_id)) if tenant_id is not None else None
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM audit_log ORDER BY id")
        heads = {}
        latest = GENESIS_HASH
        count = 0
        for row in rows:
            key = UUID(str(row["tenant_id"]))
            expected_prev = heads.get(key, latest)
            if tenant is None or key == tenant:
                if row["prev_hash"] != expected_prev:
                    return {"valid": False, "broken_id": row["id"], "count": count,
                            "reason": "prev_hash_mismatch"}
                try:
                    details = json.loads(row["details"]) if isinstance(row["details"], str) else row["details"]
                    expected = _entry_hash(expected_prev, key, row["user_id"], row["action"],
                                           row["resource"], details, row["ip"], row["created_at"])
                except (TypeError, ValueError, AttributeError):
                    return {"valid": False, "broken_id": row["id"], "count": count,
                            "reason": "invalid_payload"}
                if row["entry_hash"] != expected:
                    return {"valid": False, "broken_id": row["id"], "count": count,
                            "reason": "entry_hash_mismatch"}
                count += 1
            heads[key] = row["entry_hash"]
            latest = row["entry_hash"]
        return {"valid": True, "count": count}

    async def query(
        self,
        limit: int = 100,
        user: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        """감사 로그를 조회한다."""
        conditions: list[str] = []
        params: list[Any]     = []
        idx                   = 1

        if user is not None:
            conditions.append(f"user_id = ${idx}")
            params.append(user)
            idx += 1

        if action is not None:
            conditions.append(f"action = ${idx}")
            params.append(action)
            idx += 1

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(min(limit, 1000))

        sql = f"""
            SELECT id, user_id, action, resource, details, ip, created_at
            FROM audit_log
            {where}
            ORDER BY created_at DESC
            LIMIT ${idx}
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        results = []
        for r in rows:
            results.append({
                "id":         r["id"],
                "user":       r["user_id"],
                "action":     r["action"],
                "resource":   r["resource"],
                "details":    _details(r["details"]),
                "ip":         r["ip"],
                "created_at": r["created_at"].isoformat() if isinstance(r["created_at"], datetime) else str(r["created_at"]),
            })
        return results
