"""EVE 기록과 위협 피드 대조: 표시만 하고 경보·차단은 만들지 않는다."""

import json
import uuid

import pytest

from netwatcher.ingest.eve import decode_eve_line
from netwatcher.ingest.repository import EveRepository

GENERATION = str(uuid.uuid4())


class Feeds:
    def match_ip(self, ip):
        return {"source": "feodo", "category": "malware"} if ip == "198.51.100.7" else None

    def match_domain(self, domain):
        return {"source": "urlhaus", "category": "malware"} if domain == "bad.example" else None


def line(offset, event_type, detail, src="10.0.0.5", dest="198.51.100.7", feeds=None):
    raw = json.dumps({"timestamp": "2026-10-10T01:00:00Z", "event_type": event_type,
                      "src_ip": src, "dest_ip": dest, event_type: detail}).encode()
    return decode_eve_line(raw, sensor_id="s1", source_id="eve", generation=GENERATION, offset=offset, feeds=feeds)


def test_addresses_dns_names_and_sni_are_matched_without_keeping_other_names():
    assert line(0, "flow", {}, feeds=Feeds())["feed_match"] == [
        {"field": "dest_ip", "indicator": "198.51.100.7", "source": "feodo"}]
    dns = line(1, "dns", {"rrname": "bad.example"}, dest="10.0.0.53", feeds=Feeds())
    assert [m["field"] for m in dns["feed_match"]] == ["rrname"]
    assert [m["field"] for m in line(2, "tls", {"sni": "bad.example"}, dest="10.0.0.9", feeds=Feeds())["feed_match"]] == ["sni"]
    clean = line(3, "dns", {"rrname": "private.example"}, dest="10.0.0.9", feeds=Feeds())
    assert "feed_match" not in clean and "private" not in json.dumps(clean)


@pytest.mark.asyncio
async def test_matches_are_stored_without_creating_alerts(db):
    repo = EveRepository(db, feeds=Feeds())
    await repo.commit("s1", "eve", None, {"offset": 2}, [line(0, "flow", {}, feeds=repo.feeds),
                      line(1, "dns", {"rrname": "ok.example"}, dest="10.0.0.53", feeds=repo.feeds)])
    rows = await db.pool.fetch("SELECT event_type, record ? 'feed_match' AS matched FROM eve_records ORDER BY event_type")
    assert [(row["event_type"], row["matched"]) for row in rows] == [("dns", False), ("flow", True)]
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 0
