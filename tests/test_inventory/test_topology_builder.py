"""저장된 흐름·경보·에이전트 기록에서 토폴로지와 위험도를 다시 만든다."""

from datetime import datetime, timedelta, timezone
import json
import time
import uuid

import pytest

from netwatcher.inventory.dynamic_risk import DynamicRiskScorer
from netwatcher.inventory.topology_builder import TopologyBuilder, _endpoint
from netwatcher.inventory.topology_mapper import TopologyMapper
from netwatcher.web.routes.agent_gateway import AgentGatewayStore


def test_endpoint_parsing():
    assert _endpoint("10.0.0.5:443") == ("10.0.0.5", 443)
    assert _endpoint("[2001:db8::1]:22") == ("2001:db8::1", 22)
    assert _endpoint("not-an-address") is None


@pytest.mark.asyncio
async def test_rebuild_combines_sources_and_replaces_previous_graph(db, tmp_path):
    now = datetime.now(timezone.utc)
    async with db.pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO eve_records(ingest_id, sensor_id, source_id, event_type, observed_at, record) VALUES($1,'s','e','flow',$2,$3)",
            uuid.uuid4(), now - timedelta(minutes=5),
            {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.9", "proto": "TCP", "dest_port": 445,
             "details": {"bytes_toserver": 1000, "bytes_toclient": 500}})
        for _ in range(3):
            await conn.execute(
                "INSERT INTO events(timestamp, engine, severity, title, source_ip, dest_ip) "
                "VALUES($1,'port_scan','CRITICAL','t','10.0.0.7'::inet,'10.0.0.9'::inet)", now - timedelta(minutes=1))
    store = AgentGatewayStore(str(tmp_path / "agents.sqlite3"), "")
    with store.connect() as conn, conn:
        conn.execute("INSERT INTO agents(agent_uuid, token_hash, signing_key, hostname, platform, enrolled_at) VALUES('a','h','k','h','l',0)")
        conn.execute("INSERT INTO agent_events VALUES('a', 1, 'd', ?, ?)", (json.dumps({"events": [
            {"kind": "connection", "local_address": "10.0.0.20:50000", "remote_address": "198.51.100.7:443",
             "state": "ESTABLISHED", "inode": 1, "observed_at": int(time.time())}]}), time.time()))
    mapper, scorer = TopologyMapper(), DynamicRiskScorer()
    builder = TopologyBuilder(db, mapper, scorer, store)
    for _ in range(2):
        await builder.rebuild()
    links = {(link["source"], link["target"]): link for link in mapper.get_graph()["links"]}
    assert links[("10.0.0.5", "10.0.0.9")]["bytes_total"] == 1500
    assert links[("10.0.0.5", "10.0.0.9")]["dst_port"] == 445
    assert links[("10.0.0.7", "10.0.0.9")]["packet_count"] == 3   # 다시 만들어도 누적되지 않는다
    assert ("10.0.0.20", "198.51.100.7") in links
    assert [device["ip"] for device in scorer.get_high_risk(threshold=0.1)] == ["10.0.0.7"]
    assert builder.last_built is not None and builder.truncated is False


@pytest.mark.asyncio
async def test_native_console_does_not_read_eve_records(db):
    """분리 콘솔 역할은 eve_records를 읽지 못한다. 네이티브 모드 재구성이 그 테이블을 건드리면 전체가 실패한다."""
    async with db.pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO events(timestamp, engine, severity, title, source_ip, dest_ip) "
            "VALUES(clock_timestamp(),'port_scan','WARNING','t','10.0.0.7'::inet,'10.0.0.9'::inet)")
        await conn.execute("REVOKE ALL ON eve_records FROM PUBLIC")
        role = f"nw_topology_{uuid.uuid4().hex[:8]}"
        await conn.execute(f"CREATE ROLE {role}")
        schema = await conn.fetchval("SELECT current_schema()")
        await conn.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO {role}')
        await conn.execute(f"GRANT SELECT ON events TO {role}")
        try:
            async with conn.transaction():
                await conn.execute(f"SET LOCAL ROLE {role}")
                await conn.execute("SET LOCAL app.current_tenant_id = '00000000-0000-0000-0000-000000000000'")

                class Single:
                    """한 연결을 풀처럼 내준다."""
                    def acquire(self):
                        class Context:
                            async def __aenter__(self_inner):
                                return conn

                            async def __aexit__(self_inner, *exc):
                                return False
                        return Context()

                mapper, scorer = TopologyMapper(), DynamicRiskScorer()
                await TopologyBuilder(type("Db", (), {"_pool": Single()})(), mapper, scorer,
                                      include_eve=False).rebuild()
                assert {(link["source"], link["target"]) for link in mapper.get_graph()["links"]} == {
                    ("10.0.0.7", "10.0.0.9")}
        finally:
            await conn.execute(f"DROP OWNED BY {role}")
            await conn.execute(f"DROP ROLE {role}")
