"""관찰 자산: 내부 대역만, MAC 없이도, 재수집·백필에도 건수가 한 번만 늘어난다."""

import json
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.ingest.assets import backfill, parse_networks, summarize
from netwatcher.ingest.eve import decode_eve_line
from netwatcher.ingest.repository import EveRepository
from netwatcher.web.routes.observed_assets import create_observed_assets_router

GENERATION = str(uuid.uuid4())
NETWORKS = parse_networks(["10.0.0.0/8"])


def line(offset, event_type, src, dest, ts="2026-10-10T01:00:00Z", **extra):
    data = {"timestamp": ts, "event_type": event_type, "src_ip": src, "dest_ip": dest, event_type: {}, **extra}
    raw = json.dumps(data).encode()
    return decode_eve_line(raw, sensor_id="s1", source_id="eve", generation=GENERATION, offset=offset)


def test_only_internal_addresses_become_assets_and_mac_is_optional():
    rows = summarize([
        line(0, "flow", "10.0.0.5", "198.51.100.7"),
        line(1, "dns", "10.0.0.5", "10.0.0.53", ts="2026-10-10T02:00:00Z",
             ether={"src_mac": "AA:BB:CC:00:00:05", "dest_mac": "aa:bb:cc:00:00:35"}),
    ], NETWORKS)
    by_ip = {row["ip"]: row for row in rows}
    assert set(by_ip) == {"10.0.0.5", "10.0.0.53"}
    assert by_ip["10.0.0.5"]["mac"] == "aa:bb:cc:00:00:05"
    assert by_ip["10.0.0.5"]["evidence"] == {"flow": 1, "dns": 1}
    assert by_ip["10.0.0.5"]["first_seen"].startswith("2026-10-10T01:00")
    assert by_ip["10.0.0.5"]["last_seen"].startswith("2026-10-10T02:00")


@pytest.mark.parametrize("value", [[], ["10.0.0.1/8"], "10.0.0.0/8", ["nope"]])
def test_invalid_local_networks_are_rejected(value):
    with pytest.raises(ValueError):
        parse_networks(value)


async def _assets(db):
    return {row["ip"]: row for row in await db.pool.fetch(
        "SELECT host(ip) AS ip, mac::text AS mac, evidence FROM observed_assets")}


@pytest.mark.asyncio
async def test_reread_range_does_not_double_count(db):
    repo = EveRepository(db, local_networks=["10.0.0.0/8"])
    records = [line(0, "flow", "10.0.0.5", "198.51.100.7"), line(1, "flow", "10.0.0.5", "10.0.0.6")]
    revision = await repo.commit("s1", "eve", None, {"offset": 2}, records)
    # 회전·재시작 뒤 같은 범위를 다시 읽은 경우
    await repo.commit("s1", "eve", revision, {"offset": 2}, records + [line(2, "alert", "10.0.0.6", "203.0.113.9",
                      alert={"signature_id": 1, "severity": 2, "signature": "x"})])
    assets = await _assets(db)
    assert set(assets) == {"10.0.0.5", "10.0.0.6"}
    assert assets["10.0.0.5"]["evidence"] == {"flow": 2}
    assert assets["10.0.0.6"]["evidence"] == {"flow": 1, "alert": 1}
    assert assets["10.0.0.5"]["mac"] is None


@pytest.mark.asyncio
async def test_backfill_runs_once_and_retries_after_failure(db, monkeypatch):
    repo = EveRepository(db, local_networks=["192.168.0.0/16"])
    await repo.commit("s1", "eve", None, {"offset": 1}, [line(0, "flow", "10.0.0.5", "10.0.0.6")])
    assert await _assets(db) == {}

    import netwatcher.ingest.assets as assets_module
    original = assets_module.record_assets

    async def broken(*args):
        raise RuntimeError("interrupted")
    monkeypatch.setattr(assets_module, "record_assets", broken)
    with pytest.raises(RuntimeError):
        await backfill(db, "s1", "eve", NETWORKS)
    monkeypatch.setattr(assets_module, "record_assets", original)

    assert await backfill(db, "s1", "eve", NETWORKS) == 1
    assert await backfill(db, "s1", "eve", NETWORKS) is None
    assert {ip: row["evidence"] for ip, row in (await _assets(db)).items()} == {
        "10.0.0.5": {"flow": 1}, "10.0.0.6": {"flow": 1}}


@pytest.mark.asyncio
async def test_route_filters_by_cidr_and_rejects_bad_search(db):
    repo = EveRepository(db, local_networks=["10.0.0.0/8"])
    await repo.commit("s1", "eve", None, {"offset": 2}, [line(0, "flow", "10.0.0.5", "10.1.0.6")])
    app = FastAPI()
    app.include_router(create_observed_assets_router(db), prefix="/api")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = (await client.get("/api/observed-assets", params={"search": "10.1.0.0/16"})).json()
        assert [asset["ip"] for asset in body["assets"]] == ["10.1.0.6"] and body["total"] == 1
        assert (await client.get("/api/observed-assets", params={"search": "host-1"})).status_code == 422
