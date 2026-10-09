"""실제 증거 기록기·HTTP·Unix 소켓·DB로 분리 센서 PCAP을 검증한다."""

import asyncio
import hashlib
import json
import time
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from scapy.all import Ether, IP, TCP, Raw, rdpcap

from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.detection.models import Alert, Severity
from netwatcher.services.evidence_writer import EvidenceWriter
from netwatcher.services.sensor_evidence import SensorEvidence, CHUNK_BYTES
from netwatcher.storage.repositories import EventRepository
from tests.test_services.test_sensor_control import control
from tests.test_web.test_remote_engines import engine_api


@pytest_asyncio.fixture
async def evidence_api(engine_api, db, tmp_path):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    repository = EventRepository(db)
    event_id = await repository.insert(engine="port_scan", severity="CRITICAL", title="Owned evidence test")
    writer = PCAPWriter(str(tmp_path / "owned-evidence"))
    packet = Ether(src="02:00:00:00:00:81", dst="02:00:00:00:00:82")/IP(src="192.0.2.81", dst="198.51.100.82")/TCP(dport=9443)/Raw(b"owned-evidence-" * 3000)
    writer.add_packet(packet)
    queue = EvidenceWriter(writer, repository)
    assert queue.submit(event_id, Alert(engine="port_scan", severity=Severity.CRITICAL, title="Owned capture",
        source_ip="192.0.2.81", dest_ip="198.51.100.82"))["state"] == "pending"
    await asyncio.wait_for(queue.queue.join(), 3)
    await queue.stop()
    path = Path(writer.get_pcap_path(event_id))
    assert (await repository.get_by_id(event_id))["metadata"]["pcap"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    service.evidence = SensorEvidence(writer)
    yield (*engine_api, writer, event_id, path)


async def availability(client, header, event_id):
    return await client.get(f"/api/events/{event_id}/evidence", headers=header)


def pin_body(state, enabled=True):
    return {"request_id": str(uuid4()), "base_version": state["base_version"],
            "enabled": enabled, "hours": 1, "reason": "Owned incident review"}


@pytest.mark.asyncio
async def test_evidence_record_download_checksum_and_no_shared_path(db, evidence_api, tmp_path):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    assert (await availability(client, {}, event_id)).status_code == 401
    state = await availability(client, header, event_id)
    assert state.status_code == 200, state.text
    assert state.json()["state"] == "available" and state.json()["integrity"] == "matched_record"
    assert str(path) not in state.text and "owned-evidence" not in state.text
    file = await client.get(f"/api/events/{event_id}/evidence/file", headers=header)
    assert file.status_code == 200
    assert file.content == path.read_bytes()
    assert file.headers["x-content-sha256"] == hashlib.sha256(file.content).hexdigest()
    assert int(file.headers["content-length"]) == len(file.content)
    assert str(event_id) in file.headers["content-disposition"] and str(path.parent) not in str(file.headers)
    downloaded = tmp_path / "downloaded.pcap"
    downloaded.write_bytes(file.content)
    assert bytes(rdpcap(str(downloaded))[0][Raw]).startswith(b"owned-evidence-")
    detail = await client.get(f"/api/events/{event_id}", headers=header)
    assert detail.json()["event"]["pcap_availability"]["sha256"] == state.json()["sha256"]
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert not stopped


@pytest.mark.asyncio
async def test_pin_cas_duplicate_unpin_manifest_restart_and_audit(db, evidence_api):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    before = (await availability(client, header, event_id)).json()
    body = pin_body(before)
    response = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=body)
    assert response.status_code == 200, response.text
    after = response.json()["evidence"]
    assert after["pin_state"] == "pinned" and after["pin"]["reason"] == body["reason"]
    assert (await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=body)).json() == response.json()
    assert PCAPWriter(str(path.parent)).evidence_availability(event_id)["pin"]["expires_at"] == after["pin"]["expires_at"]
    stale = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=pin_body(before, False))
    assert stale.status_code == 409
    released = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=pin_body(after, False))
    assert released.status_code == 200 and released.json()["evidence"]["pin_state"] == "unpinned"
    audit = await client.get("/api/audit/changes/" + body["request_id"], headers=header)
    assert audit.json()["outcome"] == "applied"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_evidence_roles_read_download_but_cannot_pin(db, evidence_api, role):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    await accounts.create(role, "a-strong-test-password-123", role, "test")
    login = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + login.json()["token"]}
    state = (await availability(client, reader, event_id)).json()
    assert (await client.get(f"/api/events/{event_id}/evidence/file", headers=reader)).content == path.read_bytes()
    assert (await client.post(f"/api/events/{event_id}/evidence/pin", headers=reader, json=pin_body(state))).status_code == 403
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("condition", ["tampered", "symlink", "hardlink", "deleted", "no_writer"])
async def test_unavailable_or_tampered_file_is_not_downloaded(db, evidence_api, tmp_path, condition):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    if condition == "tampered": path.write_bytes(path.read_bytes()[:-1] + b"x")
    elif condition == "hardlink":
        import os
        os.link(path, tmp_path / "linked.pcap")
    elif condition == "symlink":
        external = tmp_path / "outside.pcap"; path.replace(external); path.symlink_to(external)
    elif condition == "deleted": path.unlink()
    else: service.evidence = SensorEvidence(None)
    result = await client.get(f"/api/events/{event_id}/evidence/file", headers=header)
    assert result.status_code in {404, 503}, result.text
    if condition == "no_writer":
        assert (await client.get(f"/api/events/{event_id}", headers=header)).json()["event"]["pcap_availability"]["state"] == "unavailable"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert not stopped


@pytest.mark.asyncio
async def test_missing_event_and_lost_sensor_preserve_stored_event_detail(evidence_api):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    assert (await availability(client, header, event_id + 100000)).status_code == 404
    await server.close()
    assert (await availability(client, header, event_id)).status_code == 503
    detail = await client.get(f"/api/events/{event_id}", headers=header)
    assert detail.status_code == 200 and detail.json()["event"]["id"] == event_id
    assert detail.json()["event"]["pcap_availability"]["state"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["prepared", "applied"])
async def test_pin_sql_audit_failure_prevents_false_success_and_retry(db, evidence_api, phase):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    body = pin_body((await availability(client, header, event_id)).json())
    await db.pool.execute(f"""CREATE FUNCTION owned_reject_evidence_audit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.action='sensor_change_{phase}' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$;
      CREATE TRIGGER owned_reject_evidence_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION owned_reject_evidence_audit();""")
    result = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=body)
    assert result.status_code == 503
    if phase == "prepared":
        assert writer.evidence_availability(event_id)["pin_state"] == "unpinned" and not stopped
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    else:
        expires = writer.evidence_availability(event_id)["pin"]["expires_at"]
        assert stopped == [True]
        assert (await availability(client, header, event_id)).status_code == 503
        assert (await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=body)).status_code == 503
        assert writer.evidence_availability(event_id)["pin"]["expires_at"] == expires
        assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"


@pytest.mark.asyncio
async def test_lost_pin_receipt_reuses_claim_without_extending_ttl(db, evidence_api, monkeypatch):
    from netwatcher.services import sensor_control_transport as transport
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    body = pin_body((await availability(client, header, event_id)).json())
    write = transport._write_frame
    async def lost(stream, payload, **kwargs):
        if b'"status":"applied"' in payload:
            stream.close(); raise ConnectionError("Owned lost pin receipt")
        return await write(stream, payload, **kwargs)
    monkeypatch.setattr(transport, "_write_frame", lost)
    assert (await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=body)).status_code == 503
    expires = writer.evidence_availability(event_id)["pin"]["expires_at"]
    monkeypatch.setattr(transport, "_write_frame", write)
    result = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=body)
    assert result.status_code == 200 and result.json()["evidence"]["pin"]["expires_at"] == expires
    assert not stopped


@pytest.mark.asyncio
async def test_file_change_between_chunks_rejected_before_new_bytes(evidence_api):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    from netwatcher.services.remote_sensor_control import RemoteSensorControl
    import os
    remote = RemoteSensorControl(service.db, "office", server.path, expected_uid=os.getuid())
    admin = await accounts.get_by_username("control-admin")
    actor = {"uid": str(admin["id"]), "ver": admin["version"]}
    before = (await remote.read_evidence(event_id, actor))["evidence"]
    first = await remote.evidence_chunk(event_id, actor, file_version=before["file_version"], offset=0)
    assert first["next_offset"] == CHUNK_BYTES
    path.write_bytes(path.read_bytes()[:-1] + b"z")
    from netwatcher.services.sensor_control import SensorControlError
    with pytest.raises(SensorControlError) as error:
        await remote.evidence_chunk(event_id, actor, file_version=before["file_version"], offset=first["next_offset"])
    assert error.value.status == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["hash", "offset", "boolean", "data", "target", "size"])
async def test_invalid_evidence_socket_chunk_is_rejected_before_http_bytes(evidence_api, monkeypatch, kind):
    from netwatcher.services import sensor_control_transport as transport
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    write = transport._write_frame
    async def corrupt(stream, payload, **kwargs):
        value = json.loads(payload)
        if "data" in value:
            if kind == "hash": value["chunk_sha256"] = "0" * 64
            elif kind == "offset": value["offset"] = 1
            elif kind == "boolean": value["next_offset"] = True
            elif kind == "data": value["data"] = "not-base64"
            elif kind == "target": value["event_id"] += 1
            else: value["size"] = True
            payload = json.dumps(value).encode()
        return await write(stream, payload, **kwargs)
    monkeypatch.setattr(transport, "_write_frame", corrupt)
    response = await client.get(f"/api/events/{event_id}/evidence/file", headers=header)
    assert response.status_code == 503
    assert not stopped


@pytest.mark.asyncio
async def test_pin_capacity_rejected_before_prepared_record_or_file_change(db, evidence_api):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    before = (await availability(client, header, event_id)).json()
    writer._pins = {f"event_{index}_owned.pcap": {"expires_at": time.time()+3600,
        "confirmed_by": "owned-admin", "reason": "Owned preservation"} for index in range(100, 164)}
    result = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header, json=pin_body(before))
    assert result.status_code == 429
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert not writer._pins_path.exists() and not stopped


@pytest.mark.asyncio
async def test_actual_http_stream_rechecks_account_and_releases_download_slot(db, evidence_api, monkeypatch):
    import socket
    import httpx
    import uvicorn
    from netwatcher.services import sensor_control_transport as transport
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    app = client._transport.app
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(128); listener.setblocking(False)
    web = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off"))
    task = asyncio.create_task(web.serve(sockets=[listener]))
    write = transport._write_frame
    changed = False
    async def revoke(stream, payload, **kwargs):
        nonlocal changed
        value = json.loads(payload)
        if "data" in value and value["offset"] == 0 and not changed:
            changed = True
            await db.pool.execute("UPDATE user_accounts SET version=version+1 WHERE username='control-admin'")
        return await write(stream, payload, **kwargs)
    monkeypatch.setattr(transport, "_write_frame", revoke)
    try:
        async with asyncio.timeout(5):
            while not web.started:
                assert not task.done()
                await asyncio.sleep(.01)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{listener.getsockname()[1]}", timeout=10) as live:
            with pytest.raises(httpx.RemoteProtocolError):
                await live.get(f"/api/events/{event_id}/evidence/file", headers=header)
            monkeypatch.setattr(transport, "_write_frame", write)
            login = await live.post("/api/auth/login", json={"username":"control-admin","password":"a-strong-test-password-123"})
            assert login.status_code == 200
            fresh = {"Authorization": "Bearer " + login.json()["token"]}
            for _ in range(3):
                download = await live.get(f"/api/events/{event_id}/evidence/file", headers=fresh)
                assert download.status_code == 200 and download.content == path.read_bytes()
        assert changed and not stopped
    finally:
        web.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
