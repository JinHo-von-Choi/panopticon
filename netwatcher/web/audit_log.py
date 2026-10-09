"""감사 로그 (Audit Trail).

API 호출에 대한 사용자 행위를 PostgreSQL에 기록한다.
저장 성공 여부를 반환한다. 필수 감사 호출자는 저장 실패 시 변경을 거절한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import asyncpg

logger = logging.getLogger("netwatcher.web.audit_log")


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
    ) -> bool:
        """감사 이벤트를 audit_log 테이블에 기록한다."""
        sql = """
            INSERT INTO audit_log (user_id, action, resource, details, ip, created_at)
            VALUES ($1, $2, $3, $4::text::jsonb, $5, $6)
        """
        now = datetime.now(timezone.utc)
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    sql,
                    user,
                    action[:50],
                    resource[:200] if resource else "",
                    json.dumps(details or {}),
                    ip[:45] if ip else "",
                    now,
                )
            return True
        except asyncpg.UndefinedTableError:
            logger.debug("audit_log table does not exist; skipping audit entry")
        except Exception:
            logger.exception("Failed to write audit log entry")
        return False

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
