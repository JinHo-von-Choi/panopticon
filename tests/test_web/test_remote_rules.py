"""실제 HTTP·Unix 소켓·PostgreSQL·패킷으로 센서 규칙 제어를 검증한다."""

import asyncio
from pathlib import Path
import threading
from uuid import uuid4

import pytest
import pytest_asyncio
from scapy.all import Ether, IP, TCP, Raw
import yaml

from netwatcher.services.sensor_control import SensorControlError
from tests.test_services.test_sensor_control import control
from tests.test_web.test_remote_engines import engine_api


def document(rule_id="OWNED-001", content="owned-malicious-marker"):
    return {"id": rule_id, "name": "Owned packet rule", "severity": "WARNING",
            "protocol": "tcp", "dst_port": 9443, "content": [content]}


@pytest_asyncio.fixture
async def rules_api(engine_api, tmp_path):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    directory = tmp_path / "owned-rules"
    directory.mkdir()
    path = directory / "rules.yaml"
    path.write_text(yaml.safe_dump({"rules": [document()]}))
    cfg = {"enabled": True, "rules_dir": str(directory)}
    assert registry.reload_engine("signature", cfg)[0]
    config_file = Path(editor._path)
    config_doc = yaml.safe_load(config_file.read_text())
    config_doc["netwatcher"]["engines"]["signature"] = cfg
    config_file.write_text(yaml.safe_dump(config_doc))
    yield (*engine_api, path)


def packet():
    return Ether()/IP(src="192.0.2.1", dst="198.51.100.1")/TCP(dport=9443, flags="PA")/Raw(b"owned-malicious-marker")


def detects(registry):
    engine = registry._find_active("signature")
    result = engine.analyze(packet())
    return result.metadata["rule_id"] if result is not None else None


async def entry(client, header, rule_id="OWNED-001"):
    return await client.get("/api/rules/entry", headers=header, params={"rule_id": rule_id})


def command(state, *, enabled=False, rule_id="OWNED-001"):
    return {"request_id": str(uuid4()), "base_version": state["base_version"], "rule_id": rule_id, "enabled": enabled}


@pytest.mark.asyncio
async def test_rules_set_cas_duplicate_and_actual_detection(db, rules_api):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    assert (await client.get("/api/rules")).status_code == 401
    assert detects(registry) == "OWNED-001"
    listed = await client.get("/api/rules", headers=header)
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1 and listed.json()["rules"][0]["enabled"] is True
    before = (await entry(client, header)).json()
    body = command(before)
    disabled = await client.put("/api/rules/entry", headers=header, json=body)
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["rule"]["enabled"] is False
    assert detects(registry) is None
    assert (await client.put("/api/rules/entry", headers=header, json=body)).json() == disabled.json()
    stale = await client.put("/api/rules/entry", headers=header, json=command(before, enabled=True))
    assert stale.status_code == 409
    enabled = await client.put("/api/rules/entry", headers=header, json=command(disabled.json(), enabled=True))
    assert enabled.status_code == 200 and detects(registry) == "OWNED-001"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 2
    audit = await client.get("/api/audit/changes/" + body["request_id"], headers=header)
    assert audit.json()["outcome"] == "applied"
    assert not stopped


@pytest.mark.asyncio
async def test_rules_follow_signature_engine_disable_and_reenable_generation(db, rules_api):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    previous = (await entry(client, header)).json()
    engine = (await client.get("/api/engines/signature", headers=header)).json()
    disabled = await client.patch("/api/engines/signature/toggle", headers=header,
        json={"request_id": str(uuid4()), "base_version": engine["base_version"], "enabled": False})
    assert disabled.status_code == 200
    assert (await entry(client, header)).status_code == 503
    enabled = await client.patch("/api/engines/signature/toggle", headers=header,
        json={"request_id": str(uuid4()), "base_version": disabled.json()["base_version"], "enabled": True})
    assert enabled.status_code == 200 and detects(registry) == "OWNED-001"
    assert enabled.json()["engine"]["config"]["enable_yara"] is True
    assert editor.get_engine_config("signature")["enable_yara"] is True
    fresh = (await entry(client, header)).json()
    assert fresh["base_version"] != previous["base_version"]
    assert (await client.put("/api/rules/entry", headers=header, json=command(previous))).status_code == 409
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["hash", "target", "boolean", "status", "duplicates", "count"])
async def test_invalid_rule_socket_receipt_fails_closed(db, rules_api, monkeypatch, kind):
    import json
    from netwatcher.services import sensor_control_transport as transport
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    write = transport._write_frame
    async def corrupted(writer, payload, **kwargs):
        value = json.loads(payload)
        if value.get("status") == "read":
            if kind == "hash": value["rules_hash"] = "invalid"
            elif kind == "target": value["rule"]["id"] = "wrong-rule"
            elif kind == "boolean": value["rule"]["enabled"] = 1
            elif kind == "status": value["status"] = "applied"
            elif kind == "duplicates": value["rules"] *= 2; value["total"] = 2
            else: value["total"] = True
            payload = json.dumps(value).encode()
        return await write(writer, payload, **kwargs)
    monkeypatch.setattr(transport, "_write_frame", corrupted)
    result = await client.get("/api/rules", headers=header) if kind in {"duplicates", "count"} else await entry(client, header)
    assert result.status_code == 503
    assert detects(registry) == "OWNED-001" and not stopped
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_rules_read_roles_and_sensor_rechecks_mutation(db, rules_api, role):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    account = await accounts.create(role, "a-strong-test-password-123", role, "test")
    login = await client.post("/api/auth/login", json={"username": role, "password": "a-strong-test-password-123"})
    reader = {"Authorization": "Bearer " + login.json()["token"]}
    before = (await entry(client, reader)).json()
    assert (await client.get("/api/rules", headers=reader)).status_code == 200
    body = command(before)
    assert (await client.put("/api/rules/entry", headers=reader, json=body)).status_code == 403
    assert (await client.post("/api/rules/reload", headers=reader,
        json={key: body[key] for key in ("request_id", "base_version")})).status_code == 403
    from netwatcher.services.sensor_control import SensorControlRequest
    import json
    request = SensorControlRequest.from_bytes(json.dumps({"request_id": str(uuid4()), "sensor_id": "office",
        "owner": str(service.owner), "actor_id": str(account["id"]), "actor_version": account["version"],
        "operation": "rules.set", "engine": "rules", "base_version": before["base_version"],
        "updates": {"rule_id": "OWNED-001", "enabled": False}}).encode())
    with pytest.raises(SensorControlError) as error:
        await service(request)
    assert error.value.status == 403
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert detects(registry) == "OWNED-001"


@pytest.mark.asyncio
async def test_rules_reload_add_remove_reset_and_paged_read(db, rules_api):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    disabled = await client.put("/api/rules/entry", headers=header, json=command((await entry(client, header)).json()))
    assert disabled.status_code == 200
    path.write_text(yaml.safe_dump({"rules": [document(), document("OWNED-002", "other-marker")]}))
    body = {"request_id": str(uuid4()), "base_version": disabled.json()["base_version"]}
    reloaded = await client.post("/api/rules/reload", headers=header, json=body)
    assert reloaded.status_code == 200, reloaded.text
    assert reloaded.json()["total"] == 2 and detects(registry) == "OWNED-001"
    assert (await client.post("/api/rules/reload", headers=header, json=body)).json() == reloaded.json()
    page = await client.get("/api/rules?limit=1&offset=1", headers=header)
    assert page.json()["total"] == 2 and page.json()["rules"][0]["id"] == "OWNED-002"
    assert (await client.get("/api/rules?limit=51", headers=header)).status_code == 422
    assert (await entry(client, header, "unknown")).status_code == 404
    path.write_text(yaml.safe_dump({"rules": []}))
    cleared = await client.post("/api/rules/reload", headers=header,
        json={"request_id": str(uuid4()), "base_version": reloaded.json()["base_version"]})
    assert cleared.status_code == 200 and cleared.json()["total"] == 0
    assert detects(registry) is None
    assert not stopped


@pytest.mark.asyncio
async def test_valid_suricata_rule_reload_preserves_port_content_and_pcre(rules_api):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    before = (await entry(client, header)).json()
    path.write_text(yaml.safe_dump({"rules": []}))
    (path.parent / "owned.rules").write_text('alert tcp any any -> any 9443 (msg:"Owned payload"; content:"owned-malicious-marker"; pcre:"/marker$/"; sid:9001;)')
    result = await client.post("/api/rules/reload", headers=header,
        json={"request_id": str(uuid4()), "base_version": before["base_version"]})
    assert result.status_code == 200, result.text
    assert detects(registry) == "SID-9001"
    rule = (await entry(client, header, "SID-9001")).json()["rule"]
    assert rule["dst_port"] == 9443 and rule["has_content"] is True and rule["has_regex"] is True
    wrong_port = packet()
    wrong_port[TCP].dport = 9444
    assert registry._find_active("signature").analyze(wrong_port) is None
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["yaml", "duplicate", "suricata", "pcre", "directory", "port", "mixed_ports", "variable"])
async def test_invalid_reload_preserves_rules_without_prepared_claim(db, rules_api, invalid):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    before = (await entry(client, header)).json()
    if invalid == "yaml":
        (path.parent / "invalid.yaml").write_text("rules: [")
    elif invalid == "duplicate":
        (path.parent / "duplicate.yaml").write_text(yaml.safe_dump({"rules": [document()]}))
    elif invalid == "directory":
        path.unlink()
        path.parent.rmdir()
    else:
        lines = {"pcre": 'alert tcp any any -> any any (msg:"bad"; pcre:"/[/"; sid:9;)',
                 "port": 'alert tcp any any -> any invalid-port (msg:"bad"; sid:9;)',
                 "mixed_ports": 'alert tcp any any -> any [80,invalid] (msg:"bad"; sid:9;)',
                 "variable": 'alert tcp $UNDEFINED any -> any any (msg:"bad"; sid:9;)'}
        line = lines.get(invalid, "invalid-rule-line")
        (path.parent / "invalid.rules").write_text(line)
    result = await client.post("/api/rules/reload", headers=header,
        json={"request_id": str(uuid4()), "base_version": before["base_version"]})
    assert result.status_code == 400, result.text
    assert detects(registry) == "OWNED-001"
    assert (await entry(client, header)).json()["base_version"] == before["base_version"]
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert not stopped


@pytest.mark.asyncio
async def test_rule_reply_lost_after_commit_returns_original_receipt(db, rules_api, monkeypatch):
    from netwatcher.services import sensor_control_transport as transport
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    body = command((await entry(client, header)).json())
    write = transport._write_frame
    async def lost(writer, payload, **kwargs):
        if b'"status":"applied"' in payload:
            writer.close()
            raise ConnectionError("owned lost reply")
        return await write(writer, payload, **kwargs)
    monkeypatch.setattr(transport, "_write_frame", lost)
    result = await client.put("/api/rules/entry", headers=header, json=body)
    assert result.status_code == 503
    assert detects(registry) is None
    monkeypatch.setattr(transport, "_write_frame", write)
    duplicate = await client.put("/api/rules/entry", headers=header, json=body)
    assert duplicate.status_code == 200 and duplicate.json()["rule"]["enabled"] is False
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 1
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["prepared", "applied"])
async def test_rule_audit_sql_failure_and_unknown_quarantine(db, rules_api, phase):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    body = command((await entry(client, header)).json())
    await db.pool.execute(f"""CREATE FUNCTION owned_reject_rule_audit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.action='sensor_change_{phase}' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$;
      CREATE TRIGGER owned_reject_rule_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION owned_reject_rule_audit();""")
    result = await client.put("/api/rules/entry", headers=header, json=body)
    assert result.status_code == 503
    if phase == "prepared":
        assert detects(registry) == "OWNED-001" and not stopped
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    else:
        assert detects(registry) is None and stopped == [True]
        assert (await entry(client, header)).status_code == 503
        assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
        duplicate = await client.put("/api/rules/entry", headers=header, json=body)
        assert duplicate.status_code == 503


@pytest.mark.asyncio
async def test_reload_file_changed_after_prepared_cannot_apply_unreviewed_candidate(db, rules_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    before = (await entry(client, header)).json()
    finish = service._finish
    async def change_file(request):
        path.write_text(yaml.safe_dump({"rules": [document("UNREVIEWED", "replacement")]}))
        return await finish(request)
    monkeypatch.setattr(service, "_finish", change_file)
    result = await client.post("/api/rules/reload", headers=header,
        json={"request_id": str(uuid4()), "base_version": before["base_version"]})
    assert result.status_code == 409
    assert detects(registry) == "OWNED-001" and not stopped
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"


@pytest.mark.asyncio
async def test_cancelled_reload_preview_cannot_install_late_candidate(db, rules_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped, path = rules_api
    before = (await entry(client, header)).json()
    stage = service.rules.stage
    entered, release, exited = threading.Event(), threading.Event(), threading.Event()
    count = 0
    def held(operation, updates):
        nonlocal count
        count += 1
        if count == 2:
            entered.set()
            assert release.wait(5)
            try:
                return stage(operation, updates)
            finally:
                exited.set()
        return stage(operation, updates)
    monkeypatch.setattr(service.rules, "stage", held)
    body = {"request_id": str(uuid4()), "base_version": before["base_version"]}
    task = asyncio.create_task(client.post("/api/rules/reload", headers=header, json=body))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        # 소켓 처리 작업을 직접 취소해 prepared 이후 종료를 재현한다.
        server_task = next(iter(server._tasks))
        server_task.cancel()
        assert (await task).status_code == 503
        release.set()
        assert await asyncio.to_thread(exited.wait, 3)
        assert detects(registry) == "OWNED-001" and not stopped
        monkeypatch.setattr(service.rules, "stage", stage)
        changed = await client.put("/api/rules/entry", headers=header, json=command(before))
        assert changed.status_code == 200 and detects(registry) is None
        assert (await client.post("/api/rules/reload", headers=header, json=body)).status_code == 503
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 2
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
