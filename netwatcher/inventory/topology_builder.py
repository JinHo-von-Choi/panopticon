"""저장된 기록으로 토폴로지와 위험도를 주기적으로 다시 만든다.

콘솔은 센서 메모리를 볼 수 없으므로, 콘솔이 읽을 수 있는 영속 기록만 쓴다.
재시작해도 같은 기록에서 같은 그래프를 다시 만든다.

- EVE 흐름 기록(eve_records의 flow)
- 경보의 출발지→목적지(events)
- 호스트 에이전트의 연결 이벤트(에이전트 저장소)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from datetime import datetime

from netwatcher.inventory.dynamic_risk import DynamicRiskScorer
from netwatcher.inventory.topology_mapper import TopologyMapper

logger = logging.getLogger("netwatcher.inventory.topology_builder")


def _seconds(value) -> float:
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return moment.timestamp()


def _endpoint(address: str) -> tuple[str, int] | None:
    """'10.0.0.1:443' 또는 '[2001:db8::1]:443'에서 IP와 포트를 얻는다."""
    host, _, port = address.rpartition(":")
    host = host.strip("[]")
    try:
        return str(ipaddress.ip_address(host)), int(port)
    except ValueError:
        return None


class TopologyBuilder:
    def __init__(self, database, mapper: TopologyMapper, scorer: DynamicRiskScorer, agent_store=None,
                 *, interval: float = 60, window_hours: int = 24, max_rows: int = 20_000, include_eve: bool = True):
        self.database, self.mapper, self.scorer, self.agent_store = database, mapper, scorer, agent_store
        # 네이티브 분리 콘솔의 DB 역할은 eve_records를 읽지 못한다. EVE 모드에서만 흐름 기록을 쓴다.
        self.include_eve = include_eve
        self.interval, self.window_hours, self.max_rows = interval, window_hours, max_rows
        self.last_built: float | None = None
        self.truncated = False
        self._task: asyncio.Task | None = None

    async def rebuild(self) -> None:
        pool = getattr(self.database, "_pool", None)
        if pool is None:
            return
        mapper, scorer = TopologyMapper(), DynamicRiskScorer()
        rows_seen = 0
        async with pool.acquire() as conn:
            flows = [] if not self.include_eve else await conn.fetch(
                """SELECT record->>'src_ip' AS src, record->>'dest_ip' AS dst, record->>'src_mac' AS smac,
                          record->>'dest_mac' AS dmac, record->>'proto' AS proto,
                          (record->>'dest_port')::int AS port,
                          COALESCE((record->'details'->>'bytes_toserver')::bigint, 0)
                            + COALESCE((record->'details'->>'bytes_toclient')::bigint, 0) AS bytes,
                          observed_at
                   FROM eve_records
                   WHERE event_type = 'flow' AND observed_at >= clock_timestamp() - make_interval(hours => $1)
                     AND record ? 'src_ip' AND record ? 'dest_ip'
                   ORDER BY observed_at DESC LIMIT $2""", self.window_hours, self.max_rows)
            alerts = await conn.fetch(
                """SELECT host(source_ip) AS src, source_mac AS smac, host(dest_ip) AS dst, dest_mac AS dmac,
                          engine, severity, timestamp
                   FROM events
                   WHERE timestamp >= clock_timestamp() - make_interval(hours => $1) AND source_ip IS NOT NULL
                   ORDER BY timestamp DESC LIMIT $2""", self.window_hours, self.max_rows)
        for row in reversed(flows):
            mapper.record_connection(row["smac"] or "", row["src"], row["dmac"] or "", row["dst"],
                                     (row["proto"] or "").lower(), row["port"] or 0, row["bytes"] or 0, at=_seconds(row["observed_at"]))
        for row in reversed(alerts):
            at = _seconds(row["timestamp"])
            scorer.record_alert(row["src"], row["severity"], row["engine"], at=at)
            if row["dst"]:
                mapper.record_connection(row["smac"] or "", row["src"], row["dmac"] or "", row["dst"],
                                         "alert", 0, 0, at=at)
        rows_seen = len(flows) + len(alerts)
        if self.agent_store is not None:
            rows_seen += await asyncio.to_thread(self._agent_connections, mapper)
        self.mapper.replace_with(mapper)
        self.scorer.replace_with(scorer)
        self.truncated = len(flows) >= self.max_rows or len(alerts) >= self.max_rows
        self.last_built = time.time()
        logger.debug("Topology rebuilt from %d records", rows_seen)

    def _agent_connections(self, mapper: TopologyMapper) -> int:
        since = time.time() - self.window_hours * 3600
        seen = 0
        with self.agent_store.connect() as db:
            rows = db.execute("SELECT payload FROM agent_events WHERE received_at >= ? ORDER BY received_at LIMIT ?",
                              (since, self.max_rows)).fetchall()
        for row in rows:
            for event in json.loads(row["payload"])["events"]:
                local, remote = _endpoint(event.get("local_address", "")), _endpoint(event.get("remote_address", ""))
                if local is None or remote is None or event.get("kind") != "connection":
                    continue
                mapper.record_connection("", local[0], "", remote[0], "tcp", remote[1], 0, at=float(event["observed_at"]))
                seen += 1
        return seen

    async def _run(self) -> None:
        while True:
            try:
                await self.rebuild()
            except Exception as exc:
                logger.warning("Topology rebuild failed (%s)", type(exc).__name__)
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
