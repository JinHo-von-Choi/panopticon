"""관측 API: 실제 PostgreSQL에서 패널 집계 값과 요청 검증을 확인한다."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.observability.panels import PANELS, bucket_seconds
from netwatcher.web.routes.observability import create_observability_router

START = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=1)


def _app(db, mode):
    app = FastAPI()
    app.include_router(create_observability_router(db, mode), prefix="/api")
    return app


async def _query(app, panels, start=START, end=END, **extra):
    params = {"panels": panels, "from": start.isoformat(), "to": end.isoformat()} | extra
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get("/api/observability/query", params=params)


@pytest_asyncio.fixture
async def seeded(db):
    async with db.pool.acquire() as conn:
        rows = [(START + timedelta(minutes=1), "CRITICAL", "port_scan", "10.0.0.1", "T1046"),
                (START + timedelta(minutes=1), "CRITICAL", "port_scan", "10.0.0.1", "T1046"),
                (START + timedelta(minutes=30), "WARNING", "arp_spoof", "10.0.0.2", "T1557"),
                (START - timedelta(minutes=5), "CRITICAL", "port_scan", "10.0.0.9", "T1046")]
        for ts, severity, engine, source, technique in rows:
            await conn.execute(
                "INSERT INTO events(timestamp, engine, severity, title, source_ip, mitre_attack_id) "
                "VALUES($1,$2,$3,'t',$4::inet,$5)", ts, engine, severity, source, technique)
        for minute, packets in ((0, 600), (1, 1200)):
            await conn.execute(
                "INSERT INTO traffic_stats(timestamp,total_packets,total_bytes,tcp_count,udp_count,arp_count,dns_count) "
                "VALUES($1,$2,$3,$4,0,0,0)", START + timedelta(minutes=minute), packets, packets * 100, packets)
    return db


@pytest.mark.asyncio
async def test_bucketed_alert_counts_match_rows_in_range(seeded):
    body = (await _query(_app(seeded, "native"), "alerts_by_severity,top_sources,top_techniques,alerts_by_engine")).json()
    assert body["bucket_seconds"] == 60
    series = body["panels"]["alerts_by_severity"]["series"]
    assert sum(value for _, value in series["CRITICAL"]) == 2
    assert sum(value for _, value in series["WARNING"]) == 1
    assert body["panels"]["top_sources"]["rows"][0] == {"label": "10.0.0.1", "value": 2}
    assert {row["label"] for row in body["panels"]["top_techniques"]["rows"]} == {"T1046", "T1557"}
    assert body["panels"]["alerts_by_engine"]["rows"][0] == {"label": "port_scan", "value": 2}


@pytest.mark.asyncio
async def test_traffic_is_reported_per_second_of_bucket(seeded):
    body = (await _query(_app(seeded, "native"), "traffic_throughput,protocol_counts")).json()
    pps = dict(body["panels"]["traffic_throughput"]["series"]["pps"])
    assert pps[START.isoformat()] == 600 / 60
    assert pps[(START + timedelta(minutes=1)).isoformat()] == 1200 / 60
    assert {"label": "TCP", "value": 1800} in body["panels"]["protocol_counts"]["rows"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["eve", "native"])
async def test_every_panel_runs_or_reports_unsupported(db, mode):
    response = await _query(_app(db, mode), ",".join(PANELS), tz="Asia/Seoul")
    assert response.status_code == 200
    for name, result in response.json()["panels"].items():
        expected = "ok" if mode in PANELS[name].modes else "unsupported"
        assert result["state"] == expected, (name, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [
    {"panels": "nope"},
    {"panels": "alerts_by_severity", "to": (START + timedelta(days=93)).isoformat()},
    {"panels": "alerts_by_severity", "from": "2026-10-10T00:00:00"},
    {"panels": "alerts_by_severity", "tz": "Mars/Base"},
    {"panels": "alerts_by_severity,alerts_by_severity"},
])
async def test_invalid_requests_are_rejected(db, params):
    app = _app(db, "native")
    query = {"panels": "alerts_by_severity", "from": START.isoformat(), "to": END.isoformat()} | params
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/observability/query", params=query)).status_code == 422


def test_bucket_width_grows_with_range():
    assert bucket_seconds(3600) == 60
    assert bucket_seconds(86400) == 900
    assert bucket_seconds(30 * 86400) == 21600


@pytest.mark.asyncio
async def test_traffic_history_window_uses_real_row_spacing(db):
    """실제 저장소 행(timestamptz 문자열)에서 기록 주기를 구한다."""
    from types import SimpleNamespace
    from netwatcher.storage.repositories import TrafficStatsRepository
    from netwatcher.web.routes.stats import create_stats_router
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    async with db.pool.acquire() as conn:
        for minutes_ago in (15, 10, 5):
            await conn.execute(
                "INSERT INTO traffic_stats(timestamp,total_packets,total_bytes,tcp_count,udp_count,arp_count,dns_count) "
                "VALUES($1,300,0,0,0,0,0)", now - timedelta(minutes=minutes_ago))
    app = FastAPI()
    app.include_router(create_stats_router(TrafficStatsRepository(db), SimpleNamespace()), prefix="/api")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = (await client.get("/api/stats/traffic?minutes=60")).json()
    assert len(body["traffic"]) == 3
    assert body["window_seconds"] == 300
