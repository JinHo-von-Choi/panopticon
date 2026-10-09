"""실제 HTTP·Unix 소켓·DB·리플레이로 설정 제안의 분리 경계를 검증한다."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio

from netwatcher.replay.runs import ReplayRunService
from netwatcher.storage.repositories import ReplayRepository
from tests.test_detection.test_proposal_replay_validation import pair
from tests.test_services.test_sensor_control import control
from tests.test_web.test_remote_engines import engine_api


@pytest_asyncio.fixture
async def proposals_api(db, engine_api):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    baseline = {**editor.get_engine_config("port_scan"), "threshold": 5}
    assert registry.reload_engine("port_scan", baseline)[0]
    editor.update_engine_config("port_scan", baseline)
    replay = ReplayRunService(ReplayRepository(db))
    service.proposals.replay = replay
    try:
        yield (*engine_api, replay)
    finally:
        await replay.stop()


async def submit(api, threshold=10, header=None):
    client, admin, service, registry, editor, accounts, server, stopped, replay = api
    header = header or admin
    response = await client.get("/api/engines/port_scan", headers=header)
    assert response.status_code == 200, response.text
    state = response.json()
    body = {"request_id": str(uuid4()), "base_version": state["base_version"],
            "engine": "port_scan", "params": {"threshold": threshold}, "reason": "업무 트래픽 확인"}
    response = await client.post("/api/proposals", headers=header, json=body)
    assert response.status_code == 201, response.text
    return response.json(), body


async def login(client, accounts, role):
    await accounts.create("proposal-" + role, "a-strong-test-password-123", role, "test")
    response = await client.post("/api/auth/login", json={"username": "proposal-" + role,
                                                         "password": "a-strong-test-password-123"})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json()["token"]}


async def validate(api, state, header=None):
    client, admin, service, registry, editor, accounts, server, stopped, replay = api
    pid = state["proposal"]["id"]
    normal, attack = await pair(replay, pid, state["proposal"]["params"]["threshold"])
    body = {"request_id": str(uuid4()), "base_version": state["base_version"],
            "normal_run_id": normal, "attack_run_id": attack}
    response = await client.post(f"/api/proposals/{pid}/validation", headers=header or admin, json=body)
    assert response.status_code == 200, response.text
    return response.json(), body


@pytest.mark.asyncio
async def test_proposal_submit_validation_approve_changes_real_sensor_once(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    path = Path(editor._path)
    original = path.read_bytes()
    active = registry._find_active("port_scan")
    from scapy.all import Ether, IP, TCP
    packets = [Ether()/IP(src="192.0.2.42", dst="198.51.100.42")/TCP(dport=port, flags="S")
               for port in range(9000, 9012)]
    for packet in packets:
        active.analyze(packet)
    assert active.on_tick(0), "현재 설정에서 입력 포트 스캔을 탐지해야 한다"
    state, body = await submit(proposals_api)
    pid = state["proposal"]["id"]
    assert state["proposal"]["before"]["threshold"] == 5
    assert path.read_bytes() == original and registry._find_active("port_scan") is active
    assert (await client.post("/api/proposals", headers=header, json=body)).json() == state
    before_validation = await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims")
    refusal = await client.post(f"/api/proposals/{pid}/approve", headers=header,
        json={"request_id": str(uuid4()), "base_version": state["base_version"]})
    assert refusal.status_code == 400
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == before_validation
    state, validation_body = await validate(proposals_api, state)
    assert path.read_bytes() == original and registry._find_active("port_scan") is active
    assert state["proposal"]["validation_runs"]["scope"] == "offline_feature_observations"
    assert (await client.post(f"/api/proposals/{pid}/validation", headers=header, json=validation_body)).json() == state
    decision = {"request_id": str(uuid4()), "base_version": state["base_version"], "note": "정상·공격 특징값 확인"}
    response = await client.post(f"/api/proposals/{pid}/approve", headers=header, json=decision)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["proposal"]["status"] == "approved" and result["proposal"]["applied"] is True
    assert editor.get_engine_config("port_scan")["threshold"] == 10
    assert registry._find_active("port_scan")._threshold == 10
    changed = registry._find_active("port_scan")
    for packet in packets:
        changed.analyze(packet)
    assert changed.on_tick(0) == [], "승인한 임계값이 실제 패킷 판정에 반영되어야 한다"
    for port in range(9000, 9040):
        changed.analyze(Ether()/IP(src="192.0.2.42", dst="198.51.100.42")/TCP(dport=port, flags="S"))
    assert changed.on_tick(0), "변경 후에도 더 큰 포트 스캔은 탐지해야 한다"
    assert (await client.post(f"/api/proposals/{pid}/approve", headers=header, json=decision)).json() == result
    assert registry._find_active("port_scan") is changed
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 3
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_prepared'") == 3
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 3
    audit = await client.get("/api/audit/changes/" + decision["request_id"], headers=header)
    assert audit.status_code == 200 and audit.json()["outcome"] == "applied"
    assert not stopped


@pytest.mark.asyncio
async def test_analyst_proposes_and_validates_but_cannot_approve_viewer_cannot_propose(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    analyst = await login(client, accounts, "analyst")
    viewer = await login(client, accounts, "viewer")
    assert (await client.get("/api/proposals")).status_code == 401
    assert (await client.get("/api/proposals", headers=viewer)).status_code == 200
    state, body = await submit(proposals_api, header=analyst)
    assert (await client.post("/api/proposals", headers=viewer, json=body)).status_code == 403
    state, _ = await validate(proposals_api, state, header=analyst)
    pid = state["proposal"]["id"]
    decision = {"request_id": str(uuid4()), "base_version": state["base_version"]}
    for role in (analyst, viewer):
        assert (await client.post(f"/api/proposals/{pid}/approve", headers=role, json=decision)).status_code == 403
        assert (await client.post(f"/api/proposals/{pid}/reject", headers=role, json=decision)).status_code == 403
    assert editor.get_engine_config("port_scan")["threshold"] == 5
    assert not stopped


@pytest.mark.asyncio
async def test_rejection_is_audited_without_changing_runtime_or_yaml(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    original = Path(editor._path).read_bytes()
    active = registry._find_active("port_scan")
    pid = state["proposal"]["id"]
    body = {"request_id": str(uuid4()), "base_version": state["base_version"], "note": "추가 근거 필요"}
    response = await client.post(f"/api/proposals/{pid}/reject", headers=header, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["proposal"]["status"] == "rejected"
    assert Path(editor._path).read_bytes() == original and registry._find_active("port_scan") is active
    assert (await client.post(f"/api/proposals/{pid}/reject", headers=header, json=body)).json() == response.json()
    fresh = (await client.get(f"/api/proposals/{pid}", headers=header)).json()
    assert (await client.post(f"/api/proposals/{pid}/approve", headers=header,
        json={"request_id": str(uuid4()), "base_version": fresh["base_version"]})).status_code == 409
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["config", "proposal", "validation"])
async def test_stale_proposal_version_cannot_write(db, proposals_api, changed):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    pid = state["proposal"]["id"]
    if changed == "config":
        cfg = {**editor.get_engine_config("port_scan"), "threshold": 7}
        editor.update_engine_config("port_scan", cfg)
        assert registry.reload_engine("port_scan", cfg)[0]
    elif changed == "proposal":
        await db.pool.execute("UPDATE config_proposals SET reason='수정된 근거' WHERE id=$1", pid)
    else:
        await validate(proposals_api, state)
    response = await client.post(f"/api/proposals/{pid}/reject", headers=header,
        json={"request_id": str(uuid4()), "base_version": state["base_version"]})
    assert response.status_code == 409
    assert await db.pool.fetchval("SELECT status FROM config_proposals WHERE id=$1", pid) == "pending"
    assert not stopped


@pytest.mark.asyncio
async def test_foreign_or_lost_attack_evidence_cannot_validate(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    first, _ = await submit(proposals_api)
    second, _ = await submit(proposals_api)
    normal, attack = await pair(replay, first["proposal"]["id"])
    pid = second["proposal"]["id"]
    response = await client.post(f"/api/proposals/{pid}/validation", headers=header,
        json={"request_id": str(uuid4()), "base_version": second["base_version"],
              "normal_run_id": normal, "attack_run_id": attack})
    assert response.status_code == 400
    assert await db.pool.fetchval("SELECT validation_runs FROM config_proposals WHERE id=$1", pid) == {}
    assert editor.get_engine_config("port_scan")["threshold"] == 5
    assert not stopped


@pytest.mark.asyncio
async def test_committed_reply_loss_recovers_same_claim_without_second_application(db, proposals_api):
    from netwatcher.services.sensor_control import SensorControlError
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    state, _ = await validate(proposals_api, state)
    pid = state["proposal"]["id"]
    body = {"request_id": str(uuid4()), "base_version": state["base_version"]}
    async def lost(request):
        await service(request)
        raise SensorControlError("owned_reply_lost", 503)
    server.handler = lost
    response = await client.post(f"/api/proposals/{pid}/approve", headers=header, json=body)
    assert response.status_code == 503
    active = registry._find_active("port_scan")
    assert active._threshold == 10
    server.handler = service
    response = await client.post(f"/api/proposals/{pid}/approve", headers=header, json=body)
    assert response.status_code == 200, response.text
    assert registry._find_active("port_scan") is active
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 3
    assert not stopped


@pytest.mark.asyncio
async def test_applied_audit_failure_quarantines_proposals_and_stops_input(db, proposals_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    state, _ = await validate(proposals_api, state)
    pid = state["proposal"]["id"]
    original_audit = service._audit
    async def fail(conn, request, action, details):
        if action == "sensor_change_applied":
            raise OSError("owned audit failure")
        return await original_audit(conn, request, action, details)
    monkeypatch.setattr(service, "_audit", fail)
    body = {"request_id": str(uuid4()), "base_version": state["base_version"]}
    response = await client.post(f"/api/proposals/{pid}/approve", headers=header, json=body)
    assert response.status_code == 503
    assert stopped and service.proposals.unconfirmed
    assert registry._find_active("port_scan")._threshold == 10
    assert await db.pool.fetchval("SELECT status FROM config_proposals WHERE id=$1", pid) == "pending"
    assert (await client.get("/api/proposals", headers=header)).status_code == 503
    current_engine = (await client.get("/api/engines/port_scan", headers=header)).json()
    assert (await client.patch("/api/engines/port_scan/toggle", headers=header,
        json={"request_id": str(uuid4()), "base_version": current_engine["base_version"], "enabled": False})).status_code == 503
    assert (await client.post(f"/api/proposals/{pid}/approve", headers=header, json=body)).status_code == 503
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2


@pytest.mark.asyncio
async def test_prepared_audit_failure_cannot_insert_or_apply(db, proposals_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    original = Path(editor._path).read_bytes()
    async def fail(*args):
        raise OSError("owned prepared audit failure")
    monkeypatch.setattr(service, "_audit", fail)
    state = (await client.get("/api/engines/port_scan", headers=header)).json()
    response = await client.post("/api/proposals", headers=header,
        json={"request_id": str(uuid4()), "base_version": state["base_version"],
              "engine": "port_scan", "params": {"threshold": 10}})
    assert response.status_code == 503
    assert await db.pool.fetchval("SELECT count(*) FROM config_proposals") == 0
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert Path(editor._path).read_bytes() == original and not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["wrong_id", "bad_version", "false_policy", "wrong_status", "extra_field"])
async def test_invalid_receipt_is_not_success(db, proposals_api, monkeypatch, kind):
    from netwatcher.services import sensor_control_transport as transport
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    pid = state["proposal"]["id"]
    write = transport._write_frame
    async def corrupted(writer, payload, **kwargs):
        value = json.loads(payload)
        if value.get("proposal"):
            if kind == "wrong_id": value["proposal"]["id"] += 1
            elif kind == "bad_version": value["base_version"] = "invalid"
            elif kind == "false_policy": value["validation_required"] = False
            elif kind == "wrong_status": value["status"] = "applied"
            else: value["private_path"] = "/owned/internal"
            payload = json.dumps(value).encode()
        return await write(writer, payload, **kwargs)
    monkeypatch.setattr(transport, "_write_frame", corrupted)
    assert (await client.get(f"/api/proposals/{pid}", headers=header)).status_code == 503


@pytest.mark.asyncio
async def test_page_and_request_uuid_conflict_are_bounded(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    one, body = await submit(proposals_api)
    two, _ = await submit(proposals_api)
    response = await client.get("/api/proposals", headers=header, params={"limit": 1})
    assert response.status_code == 200, response.text
    assert response.json()["proposals"][0]["id"] == two["proposal"]["id"]
    assert response.json()["next_offset"] == 1 and response.json()["pending"] == 2
    response = await client.get("/api/proposals", headers=header, params={"limit": 1, "offset": 1})
    assert response.json()["proposals"][0]["id"] == one["proposal"]["id"]
    assert response.json()["next_offset"] is None
    body["params"] = {"threshold": 11}
    assert (await client.post("/api/proposals", headers=header, json=body)).status_code == 409
    assert await db.pool.fetchval("SELECT count(*) FROM config_proposals") == 2


@pytest.mark.asyncio
async def test_socket_cannot_bypass_analyst_approval_or_account_version(db, proposals_api):
    from netwatcher.services.sensor_control import SensorControlRequest, SensorControlError
    from netwatcher.services.sensor_control_transport import send_sensor_control
    import os
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    analyst_header = await login(client, accounts, "analyst")
    analyst = await accounts.get_by_username("proposal-analyst")
    state, _ = await submit(proposals_api, header=analyst_header)
    pid = state["proposal"]["id"]
    raw = {"request_id": str(uuid4()), "sensor_id": service.sensor_id, "owner": str(service.owner),
           "actor_id": str(analyst["id"]), "actor_version": analyst["version"],
           "operation": "proposal.reject", "engine": "proposals", "base_version": state["base_version"],
           "updates": {"proposal_id": pid, "note": ""}}
    command = SensorControlRequest.from_bytes(json.dumps(raw).encode())
    with pytest.raises(SensorControlError) as error:
        await send_sensor_control(server.path, command.to_bytes(), expected_uid=os.getuid())
    assert error.value.status == 403
    raw.update(operation="proposal.entry", base_version="", actor_version=analyst["version"] + 1,
               updates={"proposal_id": pid})
    with pytest.raises(SensorControlError) as error:
        await send_sensor_control(server.path, SensorControlRequest.from_bytes(json.dumps(raw).encode()).to_bytes(),
                                  expected_uid=os.getuid())
    assert error.value.status == 403
    assert await db.pool.fetchval("SELECT status FROM config_proposals WHERE id=$1", pid) == "pending"
    assert editor.get_engine_config("port_scan")["threshold"] == 5 and not stopped


@pytest.mark.asyncio
async def test_other_sensor_proposal_is_not_readable_or_actionable(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    pid = state["proposal"]["id"]
    await db.pool.execute("UPDATE config_proposals SET sensor_id='other-office' WHERE id=$1", pid)
    assert (await client.get("/api/proposals", headers=header)).json()["total"] == 0
    assert (await client.get(f"/api/proposals/{pid}", headers=header)).status_code == 404
    assert (await client.post(f"/api/proposals/{pid}/reject", headers=header,
        json={"request_id": str(uuid4()), "base_version": state["base_version"]})).status_code == 404
    assert await db.pool.fetchval("SELECT status FROM config_proposals WHERE id=$1", pid) == "pending"
    assert not stopped


@pytest.mark.asyncio
async def test_sensor_restart_blocks_old_evidence_but_allows_rejection(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    pid = state["proposal"]["id"]
    service.owner = uuid4()
    service._generations.clear()
    await db.pool.execute("UPDATE sensor_runtime_state SET owner=$1 WHERE sensor_id=$2", service.owner, service.sensor_id)
    state = (await client.get(f"/api/proposals/{pid}", headers=header)).json()
    body = {"request_id": str(uuid4()), "base_version": state["base_version"]}
    assert (await client.post(f"/api/proposals/{pid}/approve", headers=header, json=body)).status_code == 409
    body["request_id"] = str(uuid4())
    assert (await client.post(f"/api/proposals/{pid}/reject", headers=header, json=body)).status_code == 200
    assert editor.get_engine_config("port_scan")["threshold"] == 5 and not stopped


@pytest.mark.asyncio
async def test_same_config_reloaded_after_submission_invalidates_evidence(db, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    state, _ = await submit(proposals_api)
    pid = state["proposal"]["id"]
    engine = (await client.get("/api/engines/port_scan", headers=header)).json()
    old_active = registry._find_active("port_scan")
    response = await client.put("/api/engines/port_scan/config", headers=header,
        json={"request_id": str(uuid4()), "base_version": engine["base_version"], "config": editor.get_engine_config("port_scan")})
    assert response.status_code == 200
    assert registry._find_active("port_scan") is not old_active
    state = (await client.get(f"/api/proposals/{pid}", headers=header)).json()
    response = await client.post(f"/api/proposals/{pid}/approve", headers=header,
        json={"request_id": str(uuid4()), "base_version": state["base_version"]})
    assert response.status_code == 409
    assert await db.pool.fetchval("SELECT status FROM config_proposals WHERE id=$1", pid) == "pending"
    assert editor.get_engine_config("port_scan")["threshold"] == 5 and not stopped
