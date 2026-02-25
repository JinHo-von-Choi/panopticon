"""이벤트, 디바이스, 트래픽 통계, 인시던트 데이터 접근 리포지토리 (PostgreSQL/asyncpg)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from netwatcher.inventory import device_classifier
from netwatcher.storage.database import Database

logger = logging.getLogger("netwatcher.storage.repositories")


def _now_utc() -> datetime:
    """현재 UTC 시각을 반환한다."""
    return datetime.now(timezone.utc)


# hostname_sources 우선순위 (인벤토리 모듈과 동기화)
_HOSTNAME_SOURCE_PRIORITY = ("dhcp", "netbios", "mdns", "llmnr", "reverse_dns")


def _best_hostname_from_sources(sources: dict) -> str | None:
    """hostname_sources dict에서 우선순위에 따라 최적 호스트명을 반환한다."""
    for src in _HOSTNAME_SOURCE_PRIORITY:
        entry = sources.get(src)
        if entry and entry.get("name"):
            return entry["name"]
    return None


def _sanitize(obj: Any) -> Any:
    """dict/list를 재귀 순회하며 문자열 내 PostgreSQL 저장 불가 null 바이트(\x00)를 제거한다."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj


class EventRepository:
    """events 테이블에 대한 CRUD 연산."""

    def __init__(self, db: Database) -> None:
        """데이터베이스 인스턴스를 주입받아 초기화한다."""
        self._db = db

    async def insert(
        self,
        engine: str,
        severity: str,
        title: str,
        description: str = "",
        source_ip: str | None = None,
        source_mac: str | None = None,
        dest_ip: str | None = None,
        dest_mac: str | None = None,
        metadata: dict[str, Any] | None = None,
        packet_info: dict[str, Any] | None = None,
    ) -> int:
        """새 이벤트를 삽입하고 해당 id를 반환한다."""
        row_id = await self._db.pool.fetchval(
            """INSERT INTO events
               (engine, severity, title, description, source_ip, source_mac,
                dest_ip, dest_mac, metadata, packet_info)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               RETURNING id""",
            engine, severity,
            _sanitize(title), _sanitize(description),
            source_ip, source_mac, dest_ip, dest_mac,
            _sanitize(metadata or {}), _sanitize(packet_info or {}),
        )
        return row_id

    async def get_by_id(self, event_id: int) -> dict | None:
        """ID로 단일 이벤트를 반환한다."""
        row = await self._db.pool.fetchrow(
            "SELECT * FROM events WHERE id = $1", event_id,
        )
        if not row:
            return None
        return dict(row)

    async def list_recent(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        engine: str | None = None,
        since: str | None = None,
        until: str | None = None,
        search: str | None = None,
        source_ip: str | None = None,
    ) -> list[dict]:
        """선택적 필터를 적용하여 최신순으로 최근 이벤트를 반환한다."""
        query = "SELECT * FROM events WHERE TRUE"
        params: list[Any] = []

        if severity:
            params.append(severity)
            query += f" AND severity = ${len(params)}"
        if engine:
            params.append(engine)
            query += f" AND engine = ${len(params)}"
        if since:
            params.append(since)
            query += f" AND timestamp >= ${len(params)}"
        if until:
            params.append(until)
            query += f" AND timestamp <= ${len(params)}"
        if search:
            search_term = f"%{search}%"
            params.append(search_term)
            idx = len(params)
            query += (
                f" AND (title LIKE ${idx}"
                f" OR description LIKE ${idx}"
                f" OR source_ip::text LIKE ${idx})"
            )
        if source_ip:
            params.append(source_ip)
            query += f" AND source_ip = ${len(params)}::inet"

        params.append(limit)
        query += f" ORDER BY timestamp DESC LIMIT ${len(params)}"
        params.append(offset)
        query += f" OFFSET ${len(params)}"

        rows = await self._db.pool.fetch(query, *params)
        return [dict(row) for row in rows]

    async def count(
        self,
        severity: str | None = None,
        engine: str | None = None,
        since: str | None = None,
        until: str | None = None,
        search: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        """선택적 필터 조건을 적용하여 이벤트 총 수를 반환한다."""
        query = "SELECT COUNT(*) FROM events"
        params: list[Any] = []
        conditions: list[str] = []

        if severity:
            params.append(severity)
            conditions.append(f"severity = ${len(params)}")
        if engine:
            params.append(engine)
            conditions.append(f"engine = ${len(params)}")
        if since:
            params.append(since)
            conditions.append(f"timestamp >= ${len(params)}")
        if until:
            params.append(until)
            conditions.append(f"timestamp <= ${len(params)}")
        if search:
            search_term = f"%{search}%"
            params.append(search_term)
            idx = len(params)
            conditions.append(
                f"(title LIKE ${idx} OR description LIKE ${idx} OR source_ip::text LIKE ${idx})"
            )
        if source_ip:
            params.append(source_ip)
            conditions.append(f"source_ip = ${len(params)}::inet")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        return await self._db.pool.fetchval(query, *params)

    async def count_by_severity_since(self, since: str) -> dict[str, int]:
        """특정 타임스탬프 이후 심각도별로 이벤트 수를 집계한다."""
        rows = await self._db.pool.fetch(
            """SELECT severity, COUNT(*) as cnt FROM events
               WHERE timestamp >= $1 GROUP BY severity""",
            since,
        )
        return {row["severity"]: row["cnt"] for row in rows}

    async def count_by_engine_since(self, since: str) -> dict[str, int]:
        """특정 타임스탬프 이후 엔진별로 이벤트 수를 집계한다."""
        rows = await self._db.pool.fetch(
            """SELECT engine, COUNT(*) as cnt FROM events
               WHERE timestamp >= $1 GROUP BY engine ORDER BY cnt DESC""",
            since,
        )
        return {row["engine"]: row["cnt"] for row in rows}

    async def top_sources_since(self, since: str, limit: int = 5) -> list[dict]:
        """특정 타임스탬프 이후 이벤트 수 기준 상위 출발지 IP를 반환한다."""
        rows = await self._db.pool.fetch(
            """SELECT source_ip, COUNT(*) as cnt FROM events
               WHERE timestamp >= $1 AND source_ip IS NOT NULL
               GROUP BY source_ip ORDER BY cnt DESC LIMIT $2""",
            since, limit,
        )
        return [{"ip": str(row["source_ip"]), "count": row["cnt"]} for row in rows]

    async def resolve(self, event_id: int) -> None:
        """이벤트를 해결 완료 상태로 변경한다."""
        await self._db.pool.execute(
            "UPDATE events SET resolved = TRUE WHERE id = $1", event_id,
        )

    async def delete_older_than(self, days: int) -> int:
        """지정된 일수보다 오래된 이벤트를 삭제한다."""
        cutoff = _now_utc() - timedelta(days=days)
        result = await self._db.pool.execute(
            "DELETE FROM events WHERE timestamp < $1",
            cutoff.isoformat(),
        )
        return int(result.split()[-1])


class DeviceRepository:
    """devices 테이블에 대한 CRUD 연산."""

    def __init__(self, db: Database) -> None:
        """데이터베이스 인스턴스를 주입받아 초기화한다."""
        self._db = db

    async def upsert(
        self,
        mac_address: str,
        ip_address: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        packet_bytes: int = 0,
        os_hint: str | None = None,
    ) -> None:
        """디바이스 레코드를 삽입하거나 업데이트한다."""
        now = _now_utc()
        await self._db.pool.execute(
            """INSERT INTO devices (mac_address, ip_address, hostname, vendor,
                                    first_seen, last_seen, total_packets, total_bytes, os_hint)
               VALUES ($1::macaddr, $2, $3, $4, $5, $6, 1, $7, $8)
               ON CONFLICT(mac_address) DO UPDATE SET
                   ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                   hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                   vendor = COALESCE(EXCLUDED.vendor, devices.vendor),
                   os_hint = COALESCE(EXCLUDED.os_hint, devices.os_hint),
                   last_seen = EXCLUDED.last_seen,
                   total_packets = devices.total_packets + 1,
                   total_bytes = devices.total_bytes + EXCLUDED.total_bytes""",
            mac_address, ip_address, hostname, vendor, now, now, packet_bytes, os_hint,
        )

    async def batch_upsert(self, device_buffer: dict[str, dict]) -> None:
        """인메모리 버퍼에서 디바이스를 일괄 upsert한다.

        device_buffer: mac -> {
            ip, hostname, vendor, os_hint, bytes, packets,
            hostname_sources: {source: {name, updated}, ...}  # 선택
        }

        hostname_sources 처리:
        - 기존 JSONB와 병합(||): 새 소스가 기존 소스를 덮어쓴다.
        - hostname 컬럼은 sources 우선순위로 자동 갱신된다.

        ip_history 처리:
        - IP가 변경된 경우 이전 IP를 history 앞에 prepend (최대 20건 유지).
        """
        if not device_buffer:
            return
        now = _now_utc()
        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                for mac, info in device_buffer.items():
                    sources: dict = info.get("hostname_sources") or {}
                    # hostname 컬럼: sources 우선순위 → 기존 역방향DNS hostname 순
                    best_hostname = _best_hostname_from_sources(sources) or info.get("hostname")
                    # 기기 타입 추론
                    inferred_type = device_classifier.classify(
                        vendor=info.get("vendor"),
                        os_hint=info.get("os_hint"),
                        hostname=best_hostname,
                        hostname_sources=sources,
                    )
                    await conn.execute(
                        """INSERT INTO devices
                               (mac_address, ip_address, hostname, vendor,
                                first_seen, last_seen, total_packets, total_bytes,
                                os_hint, hostname_sources, device_type)
                           VALUES ($1::macaddr, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                           ON CONFLICT(mac_address) DO UPDATE SET
                               ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                               hostname   = COALESCE(EXCLUDED.hostname,   devices.hostname),
                               vendor     = COALESCE(EXCLUDED.vendor,     devices.vendor),
                               os_hint    = COALESCE(EXCLUDED.os_hint,    devices.os_hint),
                               last_seen      = EXCLUDED.last_seen,
                               total_packets  = devices.total_packets + EXCLUDED.total_packets,
                               total_bytes    = devices.total_bytes   + EXCLUDED.total_bytes,
                               hostname_sources = devices.hostname_sources || EXCLUDED.hostname_sources,
                               device_type = CASE
                                   WHEN EXCLUDED.device_type = 'unknown' THEN devices.device_type
                                   ELSE EXCLUDED.device_type
                               END,
                               ip_history = CASE
                                   WHEN EXCLUDED.ip_address IS NOT NULL
                                        AND devices.ip_address IS NOT NULL
                                        AND devices.ip_address::text != EXCLUDED.ip_address::text
                                   THEN (
                                       SELECT COALESCE(jsonb_agg(e), '[]'::jsonb)
                                       FROM (
                                           SELECT jsonb_build_object(
                                               'ip',        devices.ip_address::text,
                                               'last_seen', devices.last_seen
                                           ) AS e
                                           UNION ALL
                                           SELECT e
                                           FROM jsonb_array_elements(devices.ip_history) AS e
                                           LIMIT 19
                                       ) sub
                                   )
                                   ELSE devices.ip_history
                               END""",
                        mac,
                        info.get("ip"),
                        best_hostname,
                        info.get("vendor"),
                        now, now,
                        info.get("packets", 0),
                        info.get("bytes", 0),
                        info.get("os_hint"),
                        sources,
                        inferred_type,
                    )

    async def update_open_ports(self, mac_address: str, ports: list[int]) -> None:
        """디바이스의 관측된 열린 포트를 업데이트한다."""
        await self._db.pool.execute(
            "UPDATE devices SET open_ports = $1 WHERE mac_address = $2::macaddr",
            sorted(set(ports)), mac_address,
        )

    async def list_all(self) -> list[dict]:
        """모든 디바이스를 최근 활동순으로 반환한다."""
        rows = await self._db.pool.fetch(
            "SELECT * FROM devices ORDER BY last_seen DESC",
        )
        return [dict(row) for row in rows]

    async def get_by_mac(self, mac: str) -> dict | None:
        """MAC 주소로 단일 디바이스를 반환한다."""
        row = await self._db.pool.fetchrow(
            "SELECT * FROM devices WHERE mac_address = $1::macaddr", mac,
        )
        if not row:
            return None
        return dict(row)

    async def count(self) -> int:
        """등록된 디바이스 총 수를 반환한다."""
        return await self._db.pool.fetchval("SELECT COUNT(*) FROM devices")

    async def get_all_macs(self) -> set[str]:
        """DB에 등록된 모든 디바이스의 MAC 주소 집합을 반환한다.

        PacketProcessor가 새 기기 감지용 캐시를 초기화할 때 사용한다.
        """
        rows = await self._db.pool.fetch("SELECT mac_address FROM devices")
        return {str(row["mac_address"]) for row in rows}

    async def inventory_summary(self) -> dict:
        """기기 타입별 집계, 인가/미인가 카운트, 오늘 신규 기기 수를 반환한다."""
        rows = await self._db.pool.fetch(
            """
            SELECT
                device_type,
                COUNT(*)                                              AS cnt,
                COUNT(*) FILTER (WHERE is_known = TRUE)               AS known_cnt,
                COUNT(*) FILTER (WHERE is_known = FALSE)              AS unknown_cnt,
                COUNT(*) FILTER (
                    WHERE first_seen >= NOW() - INTERVAL '24 hours'
                )                                                     AS new_today
            FROM devices
            GROUP BY device_type
            ORDER BY cnt DESC
            """
        )
        by_type: dict[str, int] = {}
        total = known = unknown = new_today = 0
        for row in rows:
            dt = row["device_type"] or "unknown"
            by_type[dt] = row["cnt"]
            total    += row["cnt"]
            known    += row["known_cnt"]
            unknown  += row["unknown_cnt"]
            new_today += row["new_today"]
        return {
            "total":     total,
            "known":     known,
            "unknown":   unknown,
            "new_today": new_today,
            "by_type":   by_type,
        }

    async def get_known_macs(self) -> set[str]:
        """등록된(is_known=TRUE) 디바이스의 MAC 주소 집합을 반환한다."""
        rows = await self._db.pool.fetch(
            "SELECT mac_address FROM devices WHERE is_known = TRUE",
        )
        return {str(row["mac_address"]) for row in rows}

    async def get_mac_ip_map(self) -> dict[str, str]:
        """MAC -> 마지막으로 알려진 IP 매핑을 반환한다."""
        rows = await self._db.pool.fetch(
            "SELECT mac_address, ip_address FROM devices WHERE ip_address IS NOT NULL",
        )
        return {str(row["mac_address"]): str(row["ip_address"]) for row in rows}

    async def register(
        self,
        mac_address: str,
        nickname: str,
        ip_address: str | None = None,
        hostname: str | None = None,
        os_hint: str | None = None,
        notes: str = "",
    ) -> dict:
        """사용자 제공 정보로 새 디바이스를 등록하거나 기존 디바이스를 업데이트한다."""
        now = _now_utc()
        await self._db.pool.execute(
            """INSERT INTO devices (mac_address, ip_address, hostname, nickname,
                                    os_hint, notes, is_known, first_seen, last_seen,
                                    total_packets, total_bytes)
               VALUES ($1::macaddr, $2, $3, $4, $5, $6, TRUE, $7, $8, 0, 0)
               ON CONFLICT(mac_address) DO UPDATE SET
                   nickname = EXCLUDED.nickname,
                   notes = EXCLUDED.notes,
                   is_known = TRUE,
                   ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                   hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                   os_hint = COALESCE(EXCLUDED.os_hint, devices.os_hint)""",
            mac_address, ip_address, hostname, nickname, os_hint, notes, now, now,
        )
        return await self.get_by_mac(mac_address)

    async def update_device(
        self,
        mac_address: str,
        **kwargs: Any,
    ) -> dict | None:
        """기존 디바이스의 특정 필드를 업데이트한다."""
        allowed = {"nickname", "hostname", "ip_address", "os_hint", "notes", "is_known"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return await self.get_by_mac(mac_address)

        set_parts: list[str] = []
        params: list[Any] = []
        for col, val in updates.items():
            params.append(val)
            set_parts.append(f"{col} = ${len(params)}")

        params.append(mac_address)
        mac_idx = len(params)

        await self._db.pool.execute(
            f"UPDATE devices SET {', '.join(set_parts)} WHERE mac_address = ${mac_idx}::macaddr",
            *params,
        )
        return await self.get_by_mac(mac_address)


class BlocklistRepository:
    """custom_blocklist 테이블에 대한 CRUD 연산."""

    def __init__(self, db: Database) -> None:
        """데이터베이스 인스턴스를 주입받아 초기화한다."""
        self._db = db

    async def add(self, entry_type: str, value: str, notes: str = "") -> int | None:
        """커스텀 차단 목록 항목을 추가한다. 행 ID를 반환하거나 중복 시 None."""
        try:
            row_id = await self._db.pool.fetchval(
                """INSERT INTO custom_blocklist (entry_type, value, notes)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (entry_type, value) DO NOTHING
                   RETURNING id""",
                entry_type, value, notes,
            )
            return row_id  # ON CONFLICT로 삽입이 생략되면 None
        except Exception:
            logger.exception("Failed to add blocklist entry")
            return None

    async def remove_by_value(self, entry_type: str, value: str) -> bool:
        """커스텀 차단 목록 항목을 제거한다. 행이 삭제되면 True를 반환한다."""
        result = await self._db.pool.execute(
            "DELETE FROM custom_blocklist WHERE entry_type = $1 AND value = $2",
            entry_type, value,
        )
        # asyncpg는 'DELETE 1'과 같은 명령 태그를 반환
        return result.split()[-1] != "0"

    async def list_custom(
        self,
        entry_type: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """선택적 필터를 적용하여 커스텀 차단 목록 항목을 조회한다."""
        query = "SELECT * FROM custom_blocklist WHERE TRUE"
        params: list[Any] = []

        if entry_type:
            params.append(entry_type)
            query += f" AND entry_type = ${len(params)}"
        if search:
            term = f"%{search}%"
            params.append(term)
            idx = len(params)
            query += f" AND (value LIKE ${idx} OR notes LIKE ${idx})"

        params.append(limit)
        query += f" ORDER BY created_at DESC LIMIT ${len(params)}"
        params.append(offset)
        query += f" OFFSET ${len(params)}"

        rows = await self._db.pool.fetch(query, *params)
        return [dict(row) for row in rows]

    async def count_custom(
        self,
        entry_type: str | None = None,
        search: str | None = None,
    ) -> int:
        """커스텀 차단 목록 항목 수를 반환한다."""
        query = "SELECT COUNT(*) FROM custom_blocklist WHERE TRUE"
        params: list[Any] = []

        if entry_type:
            params.append(entry_type)
            query += f" AND entry_type = ${len(params)}"
        if search:
            term = f"%{search}%"
            params.append(term)
            idx = len(params)
            query += f" AND (value LIKE ${idx} OR notes LIKE ${idx})"

        return await self._db.pool.fetchval(query, *params)

    async def get_all_custom_ips(self) -> set[str]:
        """모든 커스텀 차단 IP를 반환한다."""
        rows = await self._db.pool.fetch(
            "SELECT value FROM custom_blocklist WHERE entry_type = 'ip'",
        )
        return {row["value"] for row in rows}

    async def get_all_custom_domains(self) -> set[str]:
        """모든 커스텀 차단 도메인을 반환한다."""
        rows = await self._db.pool.fetch(
            "SELECT value FROM custom_blocklist WHERE entry_type = 'domain'",
        )
        return {row["value"] for row in rows}


class TrafficStatsRepository:
    """분 단위 트래픽 통계에 대한 CRUD."""

    def __init__(self, db: Database) -> None:
        """데이터베이스 인스턴스를 주입받아 초기화한다."""
        self._db = db

    async def insert(
        self,
        timestamp: str,
        total_packets: int,
        total_bytes: int,
        tcp_count: int,
        udp_count: int,
        arp_count: int,
        dns_count: int,
    ) -> None:
        """분 단위 트래픽 통계를 삽입하거나 기존 레코드에 누적한다."""
        await self._db.pool.execute(
            """INSERT INTO traffic_stats
               (timestamp, total_packets, total_bytes, tcp_count, udp_count,
                arp_count, dns_count)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (timestamp) DO UPDATE SET
                   total_packets = traffic_stats.total_packets + EXCLUDED.total_packets,
                   total_bytes = traffic_stats.total_bytes + EXCLUDED.total_bytes,
                   tcp_count = traffic_stats.tcp_count + EXCLUDED.tcp_count,
                   udp_count = traffic_stats.udp_count + EXCLUDED.udp_count,
                   arp_count = traffic_stats.arp_count + EXCLUDED.arp_count,
                   dns_count = traffic_stats.dns_count + EXCLUDED.dns_count""",
            timestamp, total_packets, total_bytes, tcp_count, udp_count,
            arp_count, dns_count,
        )

    async def recent(self, minutes: int = 60) -> list[dict]:
        """최근 N분간의 트래픽 통계를 반환한다."""
        rows = await self._db.pool.fetch(
            """SELECT * FROM traffic_stats
               ORDER BY timestamp DESC LIMIT $1""",
            minutes,
        )
        return [dict(row) for row in rows]

    async def summary_since(self, since: str) -> dict[str, int]:
        """특정 타임스탬프 이후의 트래픽 통계를 집계한다."""
        row = await self._db.pool.fetchrow(
            """SELECT
                COALESCE(SUM(total_packets), 0) as total_packets,
                COALESCE(SUM(total_bytes), 0) as total_bytes,
                COALESCE(SUM(tcp_count), 0) as tcp_count,
                COALESCE(SUM(udp_count), 0) as udp_count,
                COALESCE(SUM(arp_count), 0) as arp_count,
                COALESCE(SUM(dns_count), 0) as dns_count
               FROM traffic_stats WHERE timestamp >= $1""",
            since,
        )
        return dict(row)

    async def summary(self) -> dict[str, int]:
        """전체 기간의 트래픽 통계 합산을 반환한다."""
        row = await self._db.pool.fetchrow(
            """SELECT
                COALESCE(SUM(total_packets), 0) as total_packets,
                COALESCE(SUM(total_bytes), 0) as total_bytes,
                COALESCE(SUM(tcp_count), 0) as tcp_count,
                COALESCE(SUM(udp_count), 0) as udp_count,
                COALESCE(SUM(arp_count), 0) as arp_count,
                COALESCE(SUM(dns_count), 0) as dns_count
               FROM traffic_stats""",
        )
        return dict(row)

    async def delete_older_than(self, days: int) -> int:
        """지정된 일수보다 오래된 트래픽 통계를 삭제한다."""
        cutoff = _now_utc() - timedelta(days=days)
        result = await self._db.pool.execute(
            "DELETE FROM traffic_stats WHERE timestamp < $1",
            cutoff.isoformat(),
        )
        return int(result.split()[-1])


class IncidentRepository:
    """incidents 테이블에 대한 CRUD 연산."""

    def __init__(self, db: Database) -> None:
        """데이터베이스 인스턴스를 주입받아 초기화한다."""
        self._db = db

    async def insert(
        self,
        severity: str,
        title: str,
        description: str = "",
        alert_ids: list[int] | None = None,
        source_ips: list[str] | None = None,
        engines: list[str] | None = None,
        kill_chain_stages: list[str] | None = None,
        rule: str = "",
    ) -> int:
        """새 인시던트를 삽입하고 해당 id를 반환한다."""
        row_id = await self._db.pool.fetchval(
            """INSERT INTO incidents
               (severity, title, description, alert_ids, source_ips,
                engines, kill_chain_stages, rule)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id""",
            severity, title, description,
            alert_ids or [],
            source_ips or [],
            engines or [],
            kill_chain_stages or [],
            rule,
        )
        return row_id

    async def update(
        self,
        incident_id: int,
        severity: str | None = None,
        alert_ids: list[int] | None = None,
        engines: list[str] | None = None,
        kill_chain_stages: list[str] | None = None,
        resolved: bool | None = None,
    ) -> None:
        """기존 인시던트를 업데이트한다."""
        set_parts: list[str] = []
        params: list = []

        if severity is not None:
            params.append(severity)
            set_parts.append(f"severity = ${len(params)}")
        if alert_ids is not None:
            params.append(alert_ids)
            set_parts.append(f"alert_ids = ${len(params)}")
        if engines is not None:
            params.append(engines)
            set_parts.append(f"engines = ${len(params)}")
        if kill_chain_stages is not None:
            params.append(kill_chain_stages)
            set_parts.append(f"kill_chain_stages = ${len(params)}")
        if resolved is not None:
            params.append(resolved)
            set_parts.append(f"resolved = ${len(params)}")

        if not set_parts:
            return

        set_parts.append("updated_at = NOW()")
        params.append(incident_id)
        query = f"UPDATE incidents SET {', '.join(set_parts)} WHERE id = ${len(params)}"
        await self._db.pool.execute(query, *params)

    async def get_by_id(self, incident_id: int) -> dict | None:
        """ID로 단일 인시던트를 반환한다."""
        row = await self._db.pool.fetchrow(
            "SELECT * FROM incidents WHERE id = $1", incident_id,
        )
        return dict(row) if row else None

    async def list_recent(
        self, limit: int = 50, include_resolved: bool = False,
    ) -> list[dict]:
        """최근 인시던트 목록을 반환한다. 해결 완료 건 포함 여부를 선택할 수 있다."""
        if include_resolved:
            rows = await self._db.pool.fetch(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT $1",
                limit,
            )
        else:
            rows = await self._db.pool.fetch(
                "SELECT * FROM incidents WHERE resolved = FALSE ORDER BY created_at DESC LIMIT $1",
                limit,
            )
        return [dict(row) for row in rows]

    async def resolve(self, incident_id: int) -> bool:
        """인시던트를 해결 완료 상태로 변경한다. 성공 시 True를 반환한다."""
        result = await self._db.pool.execute(
            "UPDATE incidents SET resolved = TRUE, updated_at = NOW() WHERE id = $1",
            incident_id,
        )
        return result.split()[-1] != "0"

    async def delete_older_than(self, days: int) -> int:
        """지정된 일수보다 오래된 인시던트를 삭제한다."""
        cutoff = _now_utc() - timedelta(days=days)
        result = await self._db.pool.execute(
            "DELETE FROM incidents WHERE created_at < $1",
            cutoff.isoformat(),
        )
        return int(result.split()[-1])
