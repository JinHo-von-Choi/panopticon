"""실제 HTTP·Unix 소켓·DB·패킷으로 위협 지표 변경을 검증한다."""

from uuid import uuid4

import pytest
import pytest_asyncio
from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR

from netwatcher.detection.engines.threat_intel import ThreatIntelEngine
from netwatcher.services.sensor_blocklist import SensorBlocklist
from tests.test_services.test_sensor_control import control
from tests.test_web.test_remote_engines import engine_api
from tests.test_threatintel.test_custom_feed_consistency import manager


@pytest_asyncio.fixture
async def blocklist_api(engine_api, manager):
    assert (await manager.update_all()).succeeded
    service, registry = engine_api[2:4]
    service.blocklist = SensorBlocklist(manager)
    registry.set_feeds(manager)
    yield (*engine_api, manager)


async def entry(client, header, kind, value):
    return await client.get("/api/blocklist/entry", headers=header, params={"entry_type": kind, "value": value})


def body(state, kind, value, present=True, notes="operator evidence"):
    return {"request_id": str(uuid4()), "base_version": state["base_version"],
            "type": kind, "value": value, "present": present, "notes": notes}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,value,normalized,packet", [
    ("ip", "198.51.100.7", "198.51.100.7", Ether()/IP(src="192.0.2.1",dst="198.51.100.7")/TCP(flags="S")),
    ("ip", "198.51.100.7/24", "198.51.100.0/24", Ether()/IP(src="192.0.2.1",dst="198.51.100.9")/TCP(flags="S")),
    ("ip", "2001:db8:1::7/64", "2001:db8:1::/64", Ether()/IPv6(src="2001:db8:2::1",dst="2001:db8:1::9")/TCP(flags="S")),
    ("domain", "Custom.Evil.Example", "custom.evil.example", Ether()/IP(src="192.0.2.1",dst="192.0.2.53")/UDP(dport=53)/DNS(qd=DNSQR(qname="CUSTOM.Evil.Example."))),
])
async def test_http_add_duplicate_remove_store_and_detect_actual_packets(db, blocklist_api, kind, value, normalized, packet):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    assert (await entry(client, {}, kind, value)).status_code == 401
    read = await entry(client, header, kind, value)
    assert read.status_code == 200, read.text
    command = body(read.json(), kind, value)
    added = await client.put("/api/blocklist/entry", headers=header, json=command)
    assert added.status_code == 200, added.text
    assert added.json()["entry"]["value"] == normalized
    assert (await client.put("/api/blocklist/entry", headers=header, json=command)).json() == added.json()
    assert await db.pool.fetchval("SELECT notes FROM custom_blocklist WHERE entry_type=$1 AND value=$2", kind, normalized) == command["notes"]
    engine = ThreatIntelEngine({})
    engine.set_feeds(manager)
    assert engine.analyze(packet).metadata["feed_source"] == "Custom"
    stale = body(read.json(), kind, value, False)
    assert (await client.put("/api/blocklist/entry", headers=header, json=stale)).status_code == 409
    removed = await client.put("/api/blocklist/entry", headers=header, json=body(added.json(), kind, normalized, False))
    assert removed.status_code == 200, removed.text
    assert not removed.json()["entry"]["present"]
    assert engine.analyze(packet) is None
    assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 0
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 2
    history = await client.get("/api/audit/changes/" + command["request_id"], headers=header)
    assert history.status_code == 200 and history.json()["outcome"] == "applied"
    assert stopped == []


@pytest.mark.asyncio
async def test_feed_overlap_removal_filters_paging_and_counts(db, blocklist_api):
    client, header, *_, manager = blocklist_api
    read = (await entry(client, header, "ip", "203.0.113.7")).json()
    added = await client.put("/api/blocklist/entry", headers=header, json=body(read, "ip", "203.0.113.7"))
    assert added.status_code == 200, added.text
    page = await client.get("/api/blocklist", headers=header, params={"source": "custom", "entry_type": "ip", "limit": 1})
    assert page.json()["total"] == 1
    assert page.json()["entries"] == [{"type": "ip", "value": "203.0.113.7", "source": "Custom"}]
    stats = (await client.get("/api/blocklist/stats", headers=header)).json()
    assert stats["total_ips"] == 1 and stats["custom_ips"] == 1
    empty = await client.get("/api/blocklist", headers=header, params={"limit": 0})
    assert empty.json()["entries"] == [] and empty.json()["total"] == 2
    assert (await client.get("/api/blocklist", headers=header, params={"offset": -1})).status_code == 422
    assert (await client.get("/api/blocklist", headers=header, params={"limit": 101})).status_code == 422
    removed = await client.put("/api/blocklist/entry", headers=header, json=body(added.json(), "ip", "203.0.113.7", False))
    assert removed.status_code == 200
    assert manager.match_ip("203.0.113.7")["source"] == "Owned IP feed"
    filtered = await client.get("/api/blocklist", headers=header, params={"source": "feed", "search": "MALWARE"})
    assert filtered.json()["total"] == 1
    assert filtered.json()["entries"][0]["value"] == "malware.example"
    hostile = await client.get("/api/blocklist", headers=header, params={"search": "%' OR TRUE --"})
    assert hostile.json()["total"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_non_admin_can_read_but_cannot_write_at_http_and_sensor(db, blocklist_api, control, role):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    account = await accounts.create(role, "a-strong-test-password-123", role, "test")
    login = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + login.json()["token"]}
    read = await entry(client, reader, "ip", "198.51.100.7")
    assert read.status_code == 200
    command = body(read.json(), "ip", "198.51.100.7")
    assert (await client.put("/api/blocklist/entry", headers=reader, json=command)).status_code == 403
    request, send = control[3:5]
    from netwatcher.services.sensor_control import SensorControlError
    with pytest.raises(SensorControlError) as failure:
        await send(request("blocklist.set", actor=account, engine="blocklist", base=command["base_version"],
            updates={key: command[key] for key in ("type", "value", "present", "notes")}))
    assert failure.value.status == 403
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_lost_response_records_once_and_requires_fresh_read(db, blocklist_api):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    command = body((await entry(client, header, "domain", "custom.example")).json(), "domain", "custom.example")
    delivered = []
    async def lost_reply(request):
        result = await service(request)
        if request.operation == "blocklist.set":
            delivered.append(request.request_id)
            raise ConnectionError("owned test reply loss")
        return result
    server.handler = lost_reply
    assert (await client.put("/api/blocklist/entry", headers=header, json=command)).status_code == 503
    assert delivered == [command["request_id"]]
    assert (await entry(client, header, "domain", "custom.example")).json()["entry"]["present"]
    server.handler = service
    receipt = await client.put("/api/blocklist/entry", headers=header, json=command)
    assert receipt.status_code == 200 and receipt.json()["status"] == "applied"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["sensor_change_prepared", "sensor_change_applied"])
async def test_actual_audit_failure_never_reports_success_and_stops_unknown_sensor(db, blocklist_api, phase):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    command = body((await entry(client, header, "ip", "198.51.100.7")).json(), "ip", "198.51.100.7")
    async with db.pool.acquire() as conn:
        await conn.execute("""CREATE FUNCTION reject_owned_sensor_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF NEW.action=TG_ARGV[0] THEN RAISE EXCEPTION 'owned audit rejection'; END IF; RETURN NEW; END $$""")
        await conn.execute("CREATE TRIGGER reject_owned_sensor_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_owned_sensor_audit('" + phase + "')")
    response = await client.put("/api/blocklist/entry", headers=header, json=command)
    assert response.status_code == 503, response.text
    assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 0
    if phase == "sensor_change_prepared":
        assert manager.match_ip("198.51.100.7") is None
        assert stopped == []
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    else:
        assert manager.match_ip("198.51.100.7")["source"] == "Custom"
        assert stopped == [True]
        assert (await entry(client, header, "ip", "198.51.100.7")).status_code == 503
        assert (await client.get("/api/blocklist", headers=header)).status_code == 503
        assert (await client.get("/api/blocklist/stats", headers=header)).status_code == 503
        assert (await client.put("/api/blocklist/entry", headers=header, json=command)).status_code == 503
        assert stopped == [True]
        assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"


@pytest.mark.asyncio
async def test_existing_noncanonical_entry_is_removed_by_its_displayed_value(db, blocklist_api):
    client, header, *_, manager = blocklist_api
    await db.pool.execute("INSERT INTO custom_blocklist(entry_type,value,notes) VALUES('domain',$1,$2)", "Legacy.Example", "preserved")
    manager.add_custom_domain("Legacy.Example")
    state = (await entry(client, header, "domain", "Legacy.Example")).json()
    assert state["entry"]["value"] == "Legacy.Example"
    response = await client.put("/api/blocklist/entry", headers=header, json=body(state, "domain", "Legacy.Example", False))
    assert response.status_code == 200
    assert manager.match_domain("legacy.example") is None
    assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 0


@pytest.mark.asyncio
async def test_remove_one_legacy_alias_does_not_remove_another_registered_indicator(db, blocklist_api):
    client, header, *_, manager = blocklist_api
    for value in ("Legacy.Example", "legacy.example"):
        await db.pool.execute("INSERT INTO custom_blocklist(entry_type,value,notes) VALUES('domain',$1,$2)", value, "preserved")
        manager.add_custom_domain(value)
    state = (await entry(client, header, "domain", "Legacy.Example")).json()
    response = await client.put("/api/blocklist/entry", headers=header, json=body(state, "domain", "Legacy.Example", False))
    assert response.status_code == 200, response.text
    assert response.json()["entry"]["value"] == "Legacy.Example"
    assert response.json()["entry"]["present"] is False
    assert manager.match_domain("legacy.example")["source"] == "Custom"
    assert await db.pool.fetchval("SELECT value FROM custom_blocklist") == "legacy.example"


@pytest.mark.asyncio
async def test_database_rejection_before_memory_change_preserves_confirmed_state(db, blocklist_api):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    command = body((await entry(client, header, "ip", "198.51.100.7")).json(), "ip", "198.51.100.7", notes="rejected note")
    await db.pool.execute("ALTER TABLE custom_blocklist ADD CONSTRAINT reject_owned_note CHECK(notes <> 'rejected note')")
    response = await client.put("/api/blocklist/entry", headers=header, json=command)
    assert response.status_code == 503
    assert manager.match_ip("198.51.100.7") is None
    assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 0
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
    assert stopped == []
    current = await entry(client, header, "ip", "198.51.100.7")
    assert current.status_code == 200 and current.json()["entry"]["present"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["status", "target", "presence", "version", "unknown_field"])
async def test_malformed_receipt_after_commit_is_unconfirmed_without_reapplying(db, blocklist_api, failure):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    command = body((await entry(client, header, "ip", "198.51.100.7")).json(), "ip", "198.51.100.7")
    async def malformed(request):
        result = await service(request)
        if request.operation != "blocklist.set":
            return result
        result = {**result, "entry": dict(result["entry"])}
        if failure == "status": result["status"] = "read"
        elif failure == "target": result["entry"]["value"] = "198.51.100.8"
        elif failure == "presence": result["entry"]["present"] = False
        elif failure == "version": result["base_version"] = "not a version"
        else: result["unexpected"] = True
        return result
    server.handler = malformed
    response = await client.put("/api/blocklist/entry", headers=header, json=command)
    assert response.status_code == 503
    assert manager.match_ip("198.51.100.7")["source"] == "Custom"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 1
    server.handler = service
    assert (await client.put("/api/blocklist/entry", headers=header, json=command)).status_code == 200
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 1


@pytest.mark.asyncio
async def test_read_page_rejects_out_of_filter_data(db, blocklist_api):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    async def wrong_filter(request):
        result = await service(request)
        if request.operation == "blocklist.list":
            result = {**result, "entries": [{"type": "ip", "value": "203.0.113.7", "source": "Custom"}], "total": 1}
        return result
    server.handler = wrong_filter
    response = await client.get("/api/blocklist", headers=header, params={"source": "feed", "entry_type": "domain"})
    assert response.status_code == 503
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_account_change_between_preparation_and_mutation_is_rechecked(db, blocklist_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped, manager = blocklist_api
    command = body((await entry(client, header, "ip", "198.51.100.7")).json(), "ip", "198.51.100.7")
    finish = service._finish
    async def change_role(request):
        await db.pool.execute("UPDATE user_accounts SET role='viewer',version=version+1")
        return await finish(request)
    monkeypatch.setattr(service, "_finish", change_role)
    assert (await client.put("/api/blocklist/entry", headers=header, json=command)).status_code == 403
    assert manager.match_ip("198.51.100.7") is None
    assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 0
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
    assert stopped == []
