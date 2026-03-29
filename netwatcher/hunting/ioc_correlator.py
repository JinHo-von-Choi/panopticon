"""IOC 교차 상관분석: IP/도메인/해시 간 관계를 이벤트 DB에서 추출한다."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from netwatcher.storage.repositories import EventRepository

logger = logging.getLogger("netwatcher.hunting.ioc_correlator")


@dataclass
class IOCReport:
    """IOC 상관분석 결과."""
    ioc_type: str
    ioc_value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    related_ips: list[str] = field(default_factory=list)
    related_domains: list[str] = field(default_factory=list)
    engines_triggered: list[str] = field(default_factory=list)
    severity_max: str = "INFO"
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """딕셔너리로 직렬화한다."""
        return {
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "event_count": self.event_count,
            "related_ips": self.related_ips,
            "related_domains": self.related_domains,
            "engines_triggered": self.engines_triggered,
            "severity_max": self.severity_max,
            "timeline": self.timeline,
        }


_SEVERITY_ORDER = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}


def _max_severity(a: str, b: str) -> str:
    """두 심각도 중 더 높은 것을 반환한다."""
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b


class IOCCorrelator:
    """이벤트 DB를 기반으로 IOC 간 교차 상관관계를 분석한다."""

    def __init__(self, event_repo: EventRepository) -> None:
        self._event_repo = event_repo

    async def correlate_ip(self, ip: str) -> IOCReport:
        """특정 IP와 관련된 모든 이벤트, 도메인, 엔진을 조회한다."""
        events = await self._fetch_events_by_ip(ip)
        return self._build_report("ip", ip, events)

    async def correlate_domain(self, domain: str) -> IOCReport:
        """특정 도메인과 관련된 모든 이벤트, IP를 조회한다."""
        events = await self._fetch_events_by_domain(domain)
        return self._build_report("domain", domain, events)

    async def find_related(self, ioc_type: str, ioc_value: str) -> list[dict[str, Any]]:
        """IOC 타입/값으로 관련 이벤트를 조회한다."""
        if ioc_type == "ip":
            events = await self._fetch_events_by_ip(ioc_value)
        elif ioc_type == "domain":
            events = await self._fetch_events_by_domain(ioc_value)
        else:
            events = await self._fetch_events_by_metadata(ioc_type, ioc_value)
        return events

    async def _fetch_events_by_ip(self, ip: str) -> list[dict[str, Any]]:
        """source_ip 또는 dest_ip가 해당 IP인 이벤트를 조회한다."""
        db = self._event_repo._db
        rows = await db.pool.fetch(
            """SELECT * FROM events
               WHERE source_ip = $1::inet OR dest_ip = $1::inet
               ORDER BY timestamp ASC""",
            ip,
        )
        return [dict(r) for r in rows]

    async def _fetch_events_by_domain(self, domain: str) -> list[dict[str, Any]]:
        """metadata 또는 title/description에 도메인이 포함된 이벤트를 조회한다."""
        pattern = f"%{domain}%"
        db = self._event_repo._db
        rows = await db.pool.fetch(
            """SELECT * FROM events
               WHERE title LIKE $1 OR description LIKE $1
                  OR metadata::text LIKE $1
               ORDER BY timestamp ASC""",
            pattern,
        )
        return [dict(r) for r in rows]

    async def _fetch_events_by_metadata(
        self, key: str, value: str,
    ) -> list[dict[str, Any]]:
        """metadata JSON 내 특정 키-값 패턴으로 이벤트를 조회한다."""
        pattern = f"%{value}%"
        db = self._event_repo._db
        rows = await db.pool.fetch(
            """SELECT * FROM events
               WHERE metadata::text LIKE $1
               ORDER BY timestamp ASC""",
            pattern,
        )
        return [dict(r) for r in rows]

    def _build_report(
        self,
        ioc_type: str,
        ioc_value: str,
        events: list[dict[str, Any]],
    ) -> IOCReport:
        """이벤트 목록에서 IOCReport를 조립한다."""
        report = IOCReport(ioc_type=ioc_type, ioc_value=ioc_value)

        if not events:
            return report

        report.event_count = len(events)

        ips: set[str] = set()
        domains: set[str] = set()
        engines: set[str] = set()
        severity_max = "INFO"

        for ev in events:
            ts = ev.get("timestamp")
            if ts:
                if isinstance(ts, str):
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except ValueError:
                        dt = None
                elif isinstance(ts, datetime):
                    dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
                else:
                    dt = None

                if dt:
                    if report.first_seen is None or dt < report.first_seen:
                        report.first_seen = dt
                    if report.last_seen is None or dt > report.last_seen:
                        report.last_seen = dt

            if ev.get("source_ip"):
                ips.add(str(ev["source_ip"]))
            if ev.get("dest_ip"):
                ips.add(str(ev["dest_ip"]))

            meta = ev.get("metadata") or {}
            if isinstance(meta, dict):
                for k in ("domain", "query_name", "hostname"):
                    if meta.get(k):
                        domains.add(meta[k])

            engines.add(ev.get("engine", "unknown"))
            severity_max = _max_severity(severity_max, ev.get("severity", "INFO"))

            report.timeline.append({
                "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts) if ts else None,
                "engine": ev.get("engine"),
                "severity": ev.get("severity"),
                "title": ev.get("title"),
                "source_ip": str(ev["source_ip"]) if ev.get("source_ip") else None,
                "dest_ip": str(ev["dest_ip"]) if ev.get("dest_ip") else None,
            })

        # IOC 값 자체는 related에서 제외
        ips.discard(ioc_value)
        report.related_ips = sorted(ips)
        report.related_domains = sorted(domains)
        report.engines_triggered = sorted(engines)
        report.severity_max = severity_max

        return report
