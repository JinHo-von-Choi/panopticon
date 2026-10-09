"""실제 EVE 사건의 업무 판정·수명·감사·동시 수정 계약."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import secrets

import bcrypt
import jwt

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from netwatcher.ingest.repository import EveRepository
from netwatcher.ingest.runtime import EveConsole
from netwatcher.ingest.tailer import EveTailer


@pytest_asyncio.fixture
async def review_case(db, config, device_repo, tmp_path):
    now = datetime.now(timezone.utc)
    mac, ip = "02:00:00:00:00:10", "192.0.2.10"
    await device_repo.upsert(mac, ip)
    await device_repo.confirm_context(mac, ip, 0, {"role": "backup", "confirmed_by": "operator",
        "confirmed_at": now.isoformat(), "expires_at": (now + timedelta(days=7)).isoformat()})
    common = {"timestamp": now.isoformat(), "flow_id": 123, "src_ip": ip, "src_port": 40000,
              "dest_ip": "198.51.100.20", "dest_port": 443, "proto": "TCP", "ether": {"src_mac": mac}}
    records = [common | {"event_type": "alert", "alert": {"signature_id": 100, "severity": 1}},
               common | {"event_type": "flow", "flow": {"bytes_toserver": 1000, "bytes_toclient": 500}}]
    (tmp_path / "eve.json").write_text("".join(json.dumps(row) + "\n" for row in records))
    reader = EveTailer(EveRepository(db), directory=tmp_path, sensor_id="test", source_id="office")
    try:
        assert await reader.poll_once() == 2
    finally:
        reader.close()
    config.raw.update({"input": {"mode": "eve", "eve": {"sources": [{"directory": tmp_path,
                       "sensor_id": "test", "source_id": "office"}]}}, "web": {"host": "127.0.0.1"}})
    event_id = await db.pool.fetchval("SELECT id FROM events")
    app = EveConsole(config, database=db).build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client, f"/api/events/{event_id}/business-review", event_id


def decision(**changes):
    return {"decision": "expected_backup", "note": "승인한 백업 작업을 담당자에게 확인했습니다",
            "expected_version": 0, "valid_hours": 24, "max_bytes": 4096} | changes


@pytest.mark.asyncio
async def test_normal_review_preserves_original_alert_and_audit(db, review_case):
    client, path, event_id = review_case
    response = await client.put(path, json=decision())
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["state"] == "normal_confirmed"
    assert data["review"]["scope"]["flow_bytes"] == 1500
    assert data["review"]["version"] == 1
    assert "T" in data["review"]["expires_at"]
    assert data["review"]["expires_at"].endswith("+00:00")
    assert (await client.get(path)).json()["state"] == "normal_confirmed"
    assert await db.pool.fetchval("SELECT severity FROM events WHERE id=$1", event_id) == "CRITICAL"
    actions = await db.pool.fetch("SELECT action,details FROM audit_log ORDER BY id")
    assert {row["action"] for row in actions} == {"authorized_intent", "change_prepared", "api_mutation"}
    assert {row["details"]["request_id"] for row in actions} == {response.headers["X-Request-ID"]}
    assert decision()["note"] not in str(actions)


@pytest.mark.asyncio
@pytest.mark.parametrize("change,reason", [
    ("UPDATE business_reviews SET expires_at=NOW()-interval '1 second'", "expired"),
    ("UPDATE devices SET ip_address='192.0.2.11'", "ownership_changed"),
    ("UPDATE events SET dest_ip='198.51.100.21'", "communication_changed"),
    ("DELETE FROM eve_records WHERE event_type='flow'", "flow_evidence_missing"),
])
async def test_expiry_changed_ownership_peer_and_missing_evidence_reopen(db, review_case, change, reason):
    client, path, _ = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    await db.pool.execute(change)
    data = (await client.get(path)).json()
    assert data["state"] == "needs_review"
    assert data["reason"] == reason


@pytest.mark.asyncio
@pytest.mark.parametrize("change,reason", [
    ("UPDATE events SET source_mac=NULL", "ownership_unconfirmed"),
    ("DELETE FROM eve_records WHERE event_type='flow'", "flow_evidence_incomplete"),
])
async def test_missing_identity_or_flow_prevents_normal_decision(db, review_case, change, reason):
    client, path, _ = review_case
    await db.pool.execute(change)
    response = await client.put(path, json=decision())
    assert response.status_code == 409
    assert response.json()["detail"] == reason
    assert await db.pool.fetchval("SELECT count(*) FROM business_reviews") == 0


@pytest.mark.asyncio
async def test_over_budget_flow_prevents_normal_decision(db, review_case):
    client, path, _ = review_case
    response = await client.put(path, json=decision(max_bytes=100))
    assert response.status_code == 409
    assert response.json()["detail"] == "volume_exceeded"
    assert await db.pool.fetchval("SELECT count(*) FROM business_reviews") == 0


@pytest.mark.asyncio
async def test_stale_and_concurrent_changes_do_not_overwrite(db, review_case):
    client, path, _ = review_case
    responses = await asyncio.gather(client.put(path, json=decision()), client.put(path, json=decision()))
    assert sorted(response.status_code for response in responses) == [200, 409]
    assert await db.pool.fetchval("SELECT version FROM business_reviews") == 1
    response = await client.put(path, json=decision(decision="investigate", expected_version=1))
    assert response.status_code == 200
    assert response.json()["state"] == "investigate"


@pytest.mark.asyncio
async def test_missing_mandatory_audit_prevents_review(db, review_case):
    client, path, _ = review_case
    await db.pool.execute("DROP TABLE audit_log")
    assert (await client.put(path, json=decision())).status_code == 503
    assert await db.pool.fetchval("SELECT count(*) FROM business_reviews") == 0


@pytest.mark.asyncio
async def test_retention_removes_review_with_expired_source_event(db, review_case):
    client, path, _ = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    await db.pool.execute("UPDATE eve_records SET received_at=NOW()-interval '40 days'")
    assert await EveRepository(db).prune("test", "office", days=30) == 2
    assert await db.pool.fetchval("SELECT count(*) FROM business_reviews") == 0


@pytest.mark.asyncio
async def test_later_flow_volume_reopens_saved_normal_review(db, review_case, tmp_path):
    client, path, _ = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    row = {"timestamp": (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),
        "event_type": "flow", "flow_id": 123, "src_ip": "192.0.2.10", "src_port": 40000,
        "dest_ip": "198.51.100.20", "dest_port": 443, "proto": "TCP",
        "flow": {"bytes_toserver": 5000, "bytes_toclient": 500}}
    with (tmp_path / "eve.json").open("a") as stream:
        stream.write(json.dumps(row) + "\n")
    reader = EveTailer(EveRepository(db), directory=tmp_path, sensor_id="test", source_id="office")
    try:
        assert await reader.poll_once() == 1
    finally:
        reader.close()
    data = (await client.get(path)).json()
    assert data["state"] == "needs_review" and data["reason"] == "volume_exceeded"


@pytest.mark.asyncio
@pytest.mark.parametrize("role,status", [(None, 401), ("viewer", 403), ("analyst", 403), ("admin", 200)])
async def test_review_requires_verified_admin(db, review_case, monkeypatch, role, status):
    from netwatcher.utils.config import Config
    from netwatcher.web.auth import AuthManager
    monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
    client, path, _ = review_case
    secret = secrets.token_hex(32)
    auth = AuthManager(Config({"auth": {"enabled": True, "jwt_secret": secret,
        "password": bcrypt.hashpw(b"review-test", bcrypt.gensalt(rounds=4)).decode()}}))
    client._transport.app.state.auth_manager = auth
    headers = {}
    if role:
        token = jwt.encode({"sub": "reviewer", "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, secret, algorithm="HS256")
        headers["Authorization"] = "Bearer " + token
    response = await client.put(path, json=decision(), headers=headers)
    assert response.status_code == status
    assert await db.pool.fetchval("SELECT count(*) FROM business_reviews") == int(status == 200)


@pytest.mark.asyncio
async def test_missing_event_is_not_reported_as_unreviewed(review_case):
    client, path, event_id = review_case
    missing = path.replace(f"/{event_id}/", f"/{event_id + 100000}/")
    assert (await client.get(missing)).status_code == 404


async def append_flow(db, tmp_path, *, counters=(2000, 600), changes=None, rotation=False):
    timestamp = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    row = {"timestamp": timestamp, "event_type": "flow", "flow_id": 123,
        "src_ip": "192.0.2.10", "src_port": 40000, "dest_ip": "198.51.100.20",
        "dest_port": 443, "proto": "TCP",
        "flow": {"bytes_toserver": counters[0], "bytes_toclient": counters[1]}}
    row.update(changes or {})
    path = tmp_path / "eve.json"
    if rotation:
        path.rename(tmp_path / "eve.json.1")
    with path.open("a") as stream:
        stream.write(json.dumps(row) + "\n")
    reader = EveTailer(EveRepository(db), directory=tmp_path, sensor_id="test", source_id="office",
                       rotation_grace=0)
    try:
        count = 0
        for _ in range(3):
            count += await reader.poll_once()
        assert count == 1
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_under_budget_update_preserves_normal_review(db, review_case, tmp_path):
    client, path, _ = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    await append_flow(db, tmp_path)
    data = (await client.get(path)).json()
    assert data["state"] == "normal_confirmed"
    assert data["review"]["scope"]["flow_bytes"] == 1500


@pytest.mark.asyncio
@pytest.mark.parametrize("counters", [(900, 2000), (2000, 400)])
async def test_each_direction_counter_reset_reopens(db, review_case, tmp_path, counters):
    client, path, _ = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    await append_flow(db, tmp_path, counters=counters)
    data = (await client.get(path)).json()
    assert (data["state"], data["reason"]) == ("needs_review", "flow_counter_reset")


@pytest.mark.asyncio
async def test_long_flow_survives_real_file_rotation(db, review_case, tmp_path):
    client, path, event_id = review_case
    event_time = datetime.fromisoformat(str(await db.pool.fetchval("SELECT timestamp FROM events WHERE id=$1", event_id)))
    start = (event_time - timedelta(hours=2)).isoformat()
    end = (event_time + timedelta(hours=1)).isoformat()
    record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='flow'")
    record["details"].update(start=start, end=end)
    await db.pool.execute("UPDATE eve_records SET record=$1,observed_at=$2 WHERE event_type='flow'",
                          record, event_time + timedelta(hours=1))
    response = await client.put(path, json=decision())
    assert response.status_code == 200, response.text
    original_id = response.json()["review"]["scope"]["flow_evidence_id"]
    await append_flow(db, tmp_path, rotation=True, changes={
        "timestamp": (event_time + timedelta(hours=2)).isoformat(),
        "flow": {"start": start, "end": (event_time + timedelta(hours=2)).isoformat(),
                 "bytes_toserver": 2000, "bytes_toclient": 600},
        "ether": {"src_macs": ["02:00:00:00:00:10"]}})
    generations = await db.pool.fetchval("SELECT count(DISTINCT record->'original_ref'->>'generation') FROM eve_records")
    assert generations == 2
    data = (await client.get(path)).json()
    assert data["state"] == "normal_confirmed"
    assert data["review"]["scope"]["flow_evidence_id"] == original_id


@pytest.mark.asyncio
@pytest.mark.parametrize("changes,reason", [
    ({"ether": {"src_macs": ["02:00:00:00:00:11"]}}, "flow_evidence_ambiguous"),
    ({"ether": {"dest_macs": ["02:00:00:00:00:20", "02:00:00:00:00:21"]}}, "flow_evidence_ambiguous"),
])
async def test_conflicting_mac_evidence_reopens(db, review_case, tmp_path, changes, reason):
    client, path, _ = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    await append_flow(db, tmp_path, changes=changes)
    data = (await client.get(path)).json()
    assert (data["state"], data["reason"]) == ("needs_review", reason)


@pytest.mark.asyncio
async def test_different_flow_start_cannot_share_normal_approval(db, review_case, tmp_path):
    client, path, event_id = review_case
    event_time = datetime.fromisoformat(str(await db.pool.fetchval("SELECT timestamp FROM events WHERE id=$1", event_id)))
    record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='flow'")
    record["details"].update(start=(event_time - timedelta(seconds=1)).isoformat(),
                              end=(event_time + timedelta(seconds=1)).isoformat())
    await db.pool.execute("UPDATE eve_records SET record=$1 WHERE event_type='flow'", record)
    assert (await client.put(path, json=decision())).status_code == 200
    await append_flow(db, tmp_path, changes={"flow": {
        "start": (event_time - timedelta(seconds=2)).isoformat(),
        "end": (event_time + timedelta(seconds=2)).isoformat(),
        "bytes_toserver": 2000, "bytes_toclient": 600}})
    data = (await client.get(path)).json()
    assert (data["state"], data["reason"]) == ("needs_review", "flow_evidence_ambiguous")


@pytest.mark.asyncio
async def test_same_timestamp_conflicting_counters_block_normal_decision(db, review_case, tmp_path):
    client, path, _ = review_case
    timestamp = await db.pool.fetchval("SELECT observed_at FROM eve_records WHERE event_type='flow'")
    await append_flow(db, tmp_path, changes={"timestamp": str(timestamp)})
    response = await client.put(path, json=decision())
    assert response.status_code == 409
    assert response.json()["detail"] == "flow_evidence_ambiguous"


@pytest.mark.asyncio
async def test_partial_flow_range_cannot_confirm_normal(db, review_case):
    client, path, _ = review_case
    record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='flow'")
    record["details"]["start"] = record["observed_at"]
    await db.pool.execute("UPDATE eve_records SET record=$1 WHERE event_type='flow'", record)
    response = await client.put(path, json=decision())
    assert response.status_code == 409
    assert response.json()["detail"] == "flow_evidence_incomplete"


@pytest.mark.asyncio
async def test_excess_candidates_block_normal_decision(db, review_case, tmp_path):
    client, path, _ = review_case
    now = datetime.now(timezone.utc)
    with (tmp_path / "eve.json").open("a") as stream:
        for index in range(64):
            stream.write(json.dumps({"timestamp": (now + timedelta(microseconds=index)).isoformat(),
                "event_type": "flow", "flow_id": 123, "src_ip": "192.0.2.10", "src_port": 40000,
                "dest_ip": "198.51.100.20", "dest_port": 443, "proto": "TCP",
                "flow": {"bytes_toserver": 1000 + index, "bytes_toclient": 500}}) + "\n")
    reader = EveTailer(EveRepository(db), directory=tmp_path, sensor_id="test", source_id="office")
    try:
        assert await reader.poll_once() == 64
    finally:
        reader.close()
    response = await client.put(path, json=decision())
    assert response.status_code == 409
    assert response.json()["detail"] == "flow_evidence_ambiguous"


@pytest.mark.asyncio
async def test_peer_mac_changes_between_updates_reopen(db, review_case, tmp_path):
    client, path, _ = review_case
    record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='flow'")
    record["dest_macs"] = ["02:00:00:00:00:20"]
    await db.pool.execute("UPDATE eve_records SET record=$1 WHERE event_type='flow'", record)
    assert (await client.put(path, json=decision())).status_code == 200
    await append_flow(db, tmp_path, changes={"ether": {"dest_macs": ["02:00:00:00:00:21"]}})
    data = (await client.get(path)).json()
    assert (data["state"], data["reason"]) == ("needs_review", "flow_evidence_ambiguous")


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("sensor_id", "other-sensor"), ("source_id", "other-input"),
                                           ("dest_ip", "198.51.100.21"), ("dest_port", 8443)])
async def test_other_sensor_input_or_peer_is_not_approval_evidence(db, review_case, field, value):
    client, path, _ = review_case
    record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='flow'")
    record[field] = value
    if field in ("sensor_id", "source_id"):
        await db.pool.execute(f"UPDATE eve_records SET record=$1,{field}=$2 WHERE event_type='flow'", record, value)
    else:
        await db.pool.execute("UPDATE eve_records SET record=$1 WHERE event_type='flow'", record)
    response = await client.put(path, json=decision())
    assert response.status_code == 409
    assert response.json()["detail"] == "flow_evidence_incomplete"


@pytest.mark.asyncio
async def test_flow_range_excluding_alert_does_not_confirm_normal(db, review_case):
    client, path, event_id = review_case
    event_time = datetime.fromisoformat(str(await db.pool.fetchval("SELECT timestamp FROM events WHERE id=$1", event_id)))
    record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='flow'")
    record["details"].update(start=(event_time + timedelta(seconds=1)).isoformat(),
                              end=(event_time + timedelta(seconds=2)).isoformat())
    await db.pool.execute("UPDATE eve_records SET record=$1 WHERE event_type='flow'", record)
    response = await client.put(path, json=decision())
    assert response.status_code == 409
    assert response.json()["detail"] == "flow_evidence_incomplete"
