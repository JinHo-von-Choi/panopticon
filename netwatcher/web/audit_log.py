"""감사 로그 (Audit Trail).

API 호출에 대한 사용자 행위를 PostgreSQL에 기록한다.
audit_log 테이블이 존재할 때만 동작하며, 부재 시 graceful하게 무시한다.

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


class AuditLogger:
    """비동기 감사 로그 기록 및 조회."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def log(
        self,
        user: str,
        action: str,
        resource: str,
        details: dict[str, Any] | None = None,
        ip: str = "",
    ) -> None:
        """감사 이벤트를 audit_log 테이블에 기록한다."""
        sql = """
            INSERT INTO audit_log (user_id, action, resource, details, ip, created_at)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6)
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
        except asyncpg.UndefinedTableError:
            logger.debug("audit_log table does not exist; skipping audit entry")
        except Exception:
            logger.exception("Failed to write audit log entry")

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
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(sql, *params)
        except asyncpg.UndefinedTableError:
            return []
        except Exception:
            logger.exception("Failed to query audit log")
            return []

        results = []
        for r in rows:
            details = r["details"]
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except (json.JSONDecodeError, TypeError):
                    details = {}
            results.append({
                "id":         r["id"],
                "user":       r["user_id"],
                "action":     r["action"],
                "resource":   r["resource"],
                "details":    details if details is not None else {},
                "ip":         r["ip"],
                "created_at": r["created_at"].isoformat() if isinstance(r["created_at"], datetime) else str(r["created_at"]),
            })
        return results
