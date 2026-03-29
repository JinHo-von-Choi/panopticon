"""위협 타임라인 빌더: 특정 엔티티에 대한 시간순 이벤트 추적."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from netwatcher.storage.repositories import EventRepository

logger = logging.getLogger("netwatcher.hunting.timeline")


@dataclass
class TimelineEntry:
    """타임라인의 단일 항목."""
    timestamp: datetime
    event_type: str
    engine: str
    severity: str
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "engine": self.engine,
            "severity": self.severity,
            "description": self.description,
            "metadata": self.metadata,
        }


class ThreatTimeline:
    """특정 엔티티(IP/도메인)의 시간순 위협 타임라인을 구축한다."""

    def __init__(self, event_repo: EventRepository) -> None:
        self._event_repo = event_repo

    async def build(
        self,
        entity_type: str,
        entity_value: str,
        hours: int = 24,
    ) -> list[TimelineEntry]:
        """지정된 시간 범위 내 엔티티 관련 이벤트로 타임라인을 구축한다."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        events = await self._fetch_events(entity_type, entity_value, since_str)
        return self._events_to_timeline(events)

    async def _fetch_events(
        self,
        entity_type: str,
        entity_value: str,
        since: str,
    ) -> list[dict[str, Any]]:
        """엔티티 타입별로 이벤트를 조회한다."""
        db = self._event_repo._db

        if entity_type == "ip":
            rows = await db.pool.fetch(
                """SELECT * FROM events
                   WHERE (source_ip = $1::inet OR dest_ip = $1::inet)
                     AND timestamp >= $2
                   ORDER BY timestamp ASC""",
                entity_value, since,
            )
        elif entity_type == "domain":
            pattern = f"%{entity_value}%"
            rows = await db.pool.fetch(
                """SELECT * FROM events
                   WHERE (title LIKE $1 OR description LIKE $1
                          OR metadata::text LIKE $1)
                     AND timestamp >= $2
                   ORDER BY timestamp ASC""",
                pattern, since,
            )
        else:
            logger.warning("Unsupported entity type: %s", entity_type)
            return []

        return [dict(r) for r in rows]

    def _events_to_timeline(self, events: list[dict[str, Any]]) -> list[TimelineEntry]:
        """이벤트 목록을 TimelineEntry 리스트로 변환한다."""
        entries: list[TimelineEntry] = []

        for ev in events:
            ts = ev.get("timestamp")
            if isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    continue
            elif isinstance(ts, datetime):
                dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            else:
                continue

            meta = ev.get("metadata") or {}
            entries.append(TimelineEntry(
                timestamp=dt,
                event_type=ev.get("title", ""),
                engine=ev.get("engine", "unknown"),
                severity=ev.get("severity", "INFO"),
                description=ev.get("description", ""),
                metadata={
                    "event_id": ev.get("id"),
                    "source_ip": str(ev["source_ip"]) if ev.get("source_ip") else None,
                    "dest_ip": str(ev["dest_ip"]) if ev.get("dest_ip") else None,
                    "mitre_attack_id": ev.get("mitre_attack_id"),
                    **(meta if isinstance(meta, dict) else {}),
                },
            ))

        return entries
