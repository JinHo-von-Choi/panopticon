"""Suricata가 관측한 내부 주소를 요약한다.

장치 목록(devices)은 MAC이 필수라 EVE만으로는 채울 수 없다. 여기서는 가짜 MAC을 만들지 않고
주소 단위로 처음·마지막 관측 시각과 이벤트 종류별 건수만 남긴다. 전수 자산 목록이 아니다.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime

# 설정이 없으면 사설·링크 로컬 대역을 내부로 본다.
DEFAULT_LOCAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                          "fc00::/7", "fe80::/10")
MAX_LOCAL_NETWORKS = 64
BACKFILL_LIMIT = 200_000

UPSERT_SQL = """
INSERT INTO observed_assets(sensor_id, source_id, ip, mac, first_seen, last_seen, evidence)
SELECT $1, $2, a.ip, a.mac, a.first_seen, a.last_seen, a.evidence
FROM jsonb_to_recordset($3::jsonb) AS a(ip inet, mac macaddr, first_seen timestamptz,
                                         last_seen timestamptz, evidence jsonb)
ON CONFLICT (sensor_id, source_id, ip) DO UPDATE SET
    mac = COALESCE(EXCLUDED.mac, observed_assets.mac),
    first_seen = LEAST(observed_assets.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(observed_assets.last_seen, EXCLUDED.last_seen),
    evidence = (SELECT jsonb_object_agg(k, COALESCE((observed_assets.evidence->>k)::bigint, 0)
                                          + COALESCE((EXCLUDED.evidence->>k)::bigint, 0))
                FROM (SELECT jsonb_object_keys(observed_assets.evidence)
                      UNION SELECT jsonb_object_keys(EXCLUDED.evidence)) AS keys(k))
"""


def parse_networks(values) -> tuple:
    if values is None:
        values = DEFAULT_LOCAL_NETWORKS
    if (not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_LOCAL_NETWORKS
            or not all(isinstance(value, str) for value in values)):
        raise ValueError(f"input.eve.local_networks must list 1-{MAX_LOCAL_NETWORKS} CIDR strings")
    return tuple(ipaddress.ip_network(value, strict=True) for value in values)


def summarize(records, networks) -> list[dict]:
    """기록 묶음을 내부 주소별 한 행으로 줄인다. 내부 대역 밖 주소는 통신 상대라 넣지 않는다."""
    assets: dict[str, dict] = {}
    for record in records:
        seen = record.get("observed_at")
        if not seen:
            continue
        moment = datetime.fromisoformat(seen)
        for side in ("src", "dest"):
            value = record.get(f"{side}_ip")
            if not value:
                continue
            address = ipaddress.ip_address(value)
            if not any(address in network for network in networks):
                continue
            asset = assets.setdefault(str(address), {"ip": str(address), "mac": None, "first_seen": moment,
                                                     "last_seen": moment, "evidence": {}})
            asset["mac"] = record.get(f"{side}_mac") or asset["mac"]
            asset["first_seen"] = min(asset["first_seen"], moment)
            asset["last_seen"] = max(asset["last_seen"], moment)
            kind = record.get("event_type", "unknown")
            asset["evidence"][kind] = asset["evidence"].get(kind, 0) + 1
    return [{**asset, "first_seen": asset["first_seen"].isoformat(), "last_seen": asset["last_seen"].isoformat()}
            for asset in assets.values()]


async def record_assets(conn, sensor_id: str, source_id: str, records, networks) -> int:
    rows = summarize(records, networks)
    if rows:
        await conn.execute(UPSERT_SQL, sensor_id, source_id, rows)
    return len(rows)


async def backfill(db, sensor_id: str, source_id: str, networks, *, limit: int = BACKFILL_LIMIT) -> int | None:
    """이미 보존된 EVE 기록에서 한 번만 자산을 만든다. 이미 했으면 None.

    수집을 시작하기 전에 부른다. 수집이 먼저 돌면 같은 기록이 두 번 세어진다.
    """
    async with db.pool.acquire() as conn, conn.transaction():
        claimed = await conn.fetchval(
            """INSERT INTO observed_asset_backfills(sensor_id, source_id) VALUES($1, $2)
               ON CONFLICT DO NOTHING RETURNING sensor_id""", sensor_id, source_id)
        if claimed is None:
            return None
        # 최근 기록부터 상한까지만 읽는다. 오래 쌓인 설치에서 시동이 길어지지 않게 한다.
        rows = await conn.fetch(
            """SELECT record FROM eve_records WHERE sensor_id=$1 AND source_id=$2
               ORDER BY received_at DESC LIMIT $3""", sensor_id, source_id, limit)
        records = [row["record"] if isinstance(row["record"], dict) else json.loads(row["record"]) for row in rows]
        await record_assets(conn, sensor_id, source_id, records, networks)
        await conn.execute("UPDATE observed_asset_backfills SET records=$3 WHERE sensor_id=$1 AND source_id=$2",
                           sensor_id, source_id, len(records))
        return len(records)
