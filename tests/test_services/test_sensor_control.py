"""실제 DB·YAML·탐지 엔진·Unix 소켓으로 설정 전달 경계를 확인한다."""

import asyncio
import json
import os
import time
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
import yaml
from scapy.all import Ether, IP, TCP

from netwatcher.detection.registry import EngineRegistry
from netwatcher.detection.engines.port_scan import PortScanEngine
from netwatcher.detection.schema_utils import normalize_schema
from netwatcher.services.sensor_control import SensorControlError, SensorControlRequest, SensorControlService
from netwatcher.services.sensor_control_transport import SensorControlServer, send_sensor_control
from netwatcher.storage.sensor_state import SensorStateRepository
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.utils.yaml_editor import YamlConfigEditor


@pytest_asyncio.fixture
async def control(db, config, tmp_path):
    valid = {name: field["default"] for name, field in normalize_schema(PortScanEngine.config_schema).items()}
    valid["enabled"] = True
    config.raw["engines"]["port_scan"] = valid
    path = Path(config.config_path)
    document = yaml.safe_load(path.read_text())
    document["netwatcher"]["engines"]["port_scan"] = valid
    path.write_text(yaml.safe_dump(document))
    owner = uuid4()
    await SensorStateRepository(db).claim("office", owner)
    accounts = UserAccounts(db)
    admin = await accounts.create("control-admin", "a-strong-test-password-123", "admin", "test")
    registry = EngineRegistry(config)
    registry.discover_and_register()
    editor = YamlConfigEditor(config.config_path)
    stopped = []
    service = SensorControlService(db, "office", owner, registry, editor, lambda: stopped.append(True))
    socket = tmp_path / "control.sock"
    server = SensorControlServer(socket, allowed_uid=os.getuid(), handler=service)
    await server.start()
    def request(operation="engine.read", *, actor=None, base="", updates=None, request_id=None, **overrides):
        actor = actor or admin
        value = {"request_id": request_id or str(uuid4()), "sensor_id": "office", "owner": str(owner),
                 "actor_id": str(actor["id"]), "actor_version": actor["version"], "operation": operation,
                 "engine": "port_scan", "base_version": base, "updates": updates or {}, **overrides}
        return SensorControlRequest.from_bytes(json.dumps(value).encode())
    async def send(command):
        return await send_sensor_control(socket, command.to_bytes(), expected_uid=os.getuid())
    try:
        yield service, registry, editor, request, send, stopped, accounts, server
    finally:
        await server.close()
        registry.shutdown()


def packet(port):
    return Ether(src="02:00:00:00:00:71", dst="02:00:00:00:00:72") / IP(src="10.1.2.71", dst="203.0.113.2") / TCP(sport=50000, dport=port, flags="S")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,value,key,normalized", [
    ("ip", "10.1.2.71", "ips", "10.1.2.71"),
    ("ip_range", "10.1.2.71/24", "ip_ranges", "10.1.2.0/24"),
    ("mac", "02:AA:00:00:00:71", "macs", "02:aa:00:00:00:71"),
    ("domain", "Backup.Example", "domains", "backup.example"),
    ("suffix", ".Office.Example", "domain_suffixes", ".office.example"),
])
async def test_whitelist_socket_add_remove_preserves_engine_reference_and_duplicate(db, control, kind, value, key, normalized):
    service, registry, editor, request, send, stopped, *_ = control
    whitelist = registry.whitelist
    engine = registry._find_active("port_scan")
    before = await send(request("whitelist.read", engine="whitelist"))
    command = request("whitelist.set", engine="whitelist", base=before["base_version"],
                      updates={"type": kind, "value": value, "present": True})
    applied = await send(command)
    assert applied["status"] == "applied"
    assert normalized in applied["whitelist"][key]
    assert registry.whitelist is whitelist
    assert registry._find_active("port_scan") is engine
    assert await send(command) == applied
    assert yaml.safe_load(Path(editor._path).read_text())["netwatcher"]["whitelist"][key] == applied["whitelist"][key]
    if kind in {"ip", "ip_range"}:
        assert whitelist.is_ip_whitelisted("10.1.2.71")
        assert registry.process_packet(packet(9123)) == []
    elif kind == "mac":
        assert whitelist.is_mac_whitelisted(value)
    else:
        assert whitelist.is_domain_whitelisted("backup.example" if kind == "domain" else "backup.office.example")
    removed = await send(request("whitelist.set", engine="whitelist", base=applied["base_version"],
                         updates={"type": kind, "value": value, "present": False}))
    assert normalized not in removed["whitelist"][key]
    assert registry.whitelist is whitelist
    assert not stopped
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_whitelist_read_is_allowed_but_sensor_rejects_nonadmin_change(db, control, role):
    service, registry, editor, request, send, stopped, accounts, _ = control
    actor = await accounts.create("whitelist-reader", "a-strong-test-password-123", role, "test")
    before = await send(request("whitelist.read", engine="whitelist", actor=actor))
    with pytest.raises(SensorControlError) as error:
        await send(request("whitelist.set", engine="whitelist", actor=actor, base=before["base_version"],
                   updates={"type": "ip", "value": "10.1.2.71", "present": True}))
    assert error.value.status == 403
    assert not registry.whitelist.is_ip_whitelisted("10.1.2.71")
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_whitelist_stale_version_rejected_before_audit_or_mutation(db, control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request("whitelist.read", engine="whitelist"))
    await send(request("whitelist.set", engine="whitelist", base=before["base_version"],
               updates={"type": "ip", "value": "10.1.2.71", "present": True}))
    with pytest.raises(SensorControlError) as error:
        await send(request("whitelist.set", engine="whitelist", base=before["base_version"],
                   updates={"type": "ip", "value": "10.1.2.72", "present": True}))
    assert error.value.code == "whitelist_configuration_changed"
    assert not registry.whitelist.is_ip_whitelisted("10.1.2.72")
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 1
    assert not stopped


@pytest.mark.asyncio
async def test_whitelist_failed_persistence_never_changes_detection_or_retries(db, control, monkeypatch):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request("whitelist.read", engine="whitelist"))
    command = request("whitelist.set", engine="whitelist", base=before["base_version"],
                      updates={"type": "ip", "value": "10.1.2.71", "present": True})
    attempts = []
    def fail(values):
        attempts.append(values)
        raise OSError("test storage unavailable")
    monkeypatch.setattr(editor, "update_whitelist_config", fail)
    with pytest.raises(SensorControlError) as error:
        await send(command)
    assert error.value.status == 503
    assert not registry.whitelist.is_ip_whitelisted("10.1.2.71")
    assert stopped == [True]
    assert (await send(command))["status"] == "unknown"
    assert len(attempts) == 1
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"


@pytest.mark.parametrize("kind,value,present", [
    ("ip", "not-an-ip", True), ("ip", "fe80::1%eth0", True),
    ("ip_range", "invalid/99", True), ("mac", "bad-mac", True),
    ("domain", "a..example", True), ("domain", "example/path", True),
    ("suffix", "example.com", True), ("domain", " example.com", True),
    ("ip", "10.1.2.71", "true"),
])
@pytest.mark.asyncio
async def test_invalid_whitelist_command_is_rejected_before_transmission(control, kind, value, present):
    # 실제 request 파서는 서버 호출 없이도 잘못된 변경을 거절한다.
    _, _, _, request, *_ = control
    with pytest.raises((ValueError, TypeError)):
        request("whitelist.set", engine="whitelist", base="a" * 64,
                updates={"type": kind, "value": value, "present": present})


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["sensor_change_prepared", "sensor_change_applied"])
async def test_whitelist_audit_failure_controls_mutation_and_unknown(db, control, monkeypatch, phase):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request("whitelist.read", engine="whitelist"))
    audit = service._audit
    async def fail(conn, command, action, details):
        if action == phase:
            raise OSError("test audit unavailable")
        await audit(conn, command, action, details)
    monkeypatch.setattr(service, "_audit", fail)
    command = request("whitelist.set", engine="whitelist", base=before["base_version"],
                      updates={"type": "ip", "value": "10.1.2.71", "present": True})
    with pytest.raises(SensorControlError) as error:
        await send(command)
    assert error.value.status == 503
    changed = phase == "sensor_change_applied"
    assert registry.whitelist.is_ip_whitelisted("10.1.2.71") is changed
    assert bool(stopped) is changed
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == int(changed)
    if changed:
        assert (await send(command))["status"] == "unknown"
        persisted = yaml.safe_load(Path(editor._path).read_text())["netwatcher"]["whitelist"]
        assert "10.1.2.71" in persisted["ips"]


@pytest.mark.asyncio
async def test_whitelist_external_file_change_is_preserved(db, control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request("whitelist.read", engine="whitelist"))
    document = yaml.safe_load(Path(editor._path).read_text())
    document["netwatcher"]["whitelist"]["ips"] = ["10.1.2.72"]
    Path(editor._path).write_text(yaml.safe_dump(document))
    with pytest.raises(SensorControlError) as error:
        await send(request("whitelist.set", engine="whitelist", base=before["base_version"],
                   updates={"type": "ip", "value": "10.1.2.71", "present": True}))
    assert error.value.code == "whitelist_configuration_changed"
    assert editor.get_whitelist_config()["ips"] == ["10.1.2.72"]
    assert not registry.whitelist.is_ip_whitelisted("10.1.2.71")
    assert not stopped
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_socket_configuration_changes_real_detection_and_duplicate_keeps_state(db, control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    command = request("engine.configure", base=before["base_version"], updates={"threshold": 5})
    result = await send(command)
    assert result["status"] == "applied"
    assert editor.get_engine_config("port_scan")["threshold"] == 5
    engine = registry._find_active("port_scan")
    for port in range(9101, 9107):
        assert not [a for a in registry.process_packet(packet(port)) if a.engine == "port_scan"]
    assert engine.on_tick(time.time()) == []
    assert await send(command) == result
    assert registry._find_active("port_scan") is engine
    registry.process_packet(packet(9107))
    alerts = engine.on_tick(time.time())
    assert any(a.engine == "port_scan" for a in alerts)
    assert not stopped
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 1
    actions = await db.pool.fetch("SELECT action FROM audit_log ORDER BY id")
    assert [row["action"] for row in actions] == ["sensor_change_prepared", "sensor_change_applied"]


@pytest.mark.asyncio
async def test_toggle_and_read_disabled_engine_report_persisted_settings(control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    result = await send(request("engine.toggle", base=before["base_version"], updates={"enabled": False}))
    assert result["engine"]["enabled"] is False
    assert result["engine"]["config"]["enabled"] is False
    assert not registry._find_active("port_scan")
    read = await send(request())
    assert read["base_version"] == result["base_version"]
    enabled = await send(request("engine.toggle", base=read["base_version"], updates={"enabled": True}))
    assert enabled["engine"]["enabled"] is True
    assert registry._find_active("port_scan") is not None


@pytest.mark.asyncio
async def test_empty_schema_engine_toggle_preserves_feed_detection(db, config, control):
    from netwatcher.threatintel.feed_manager import FeedManager

    service, registry, editor, request, send, stopped, *_ = control
    feeds = FeedManager(config)
    feeds.add_custom_ip("203.0.113.2")
    registry.set_feeds(feeds)
    assert registry.get_engine_schema("threat_intel") == {}
    assert any(a.engine == "threat_intel" for a in registry.process_packet(packet(9443)))
    before = await send(request(engine="threat_intel"))
    with pytest.raises(SensorControlError) as invalid:
        await send(request("engine.configure", engine="threat_intel",
            base=before["base_version"], updates={"undeclared_threshold": 10}))
    assert invalid.value.code == "engine_configuration_invalid"
    assert editor.get_engine_config("threat_intel") == before["engine"]["config"]
    disabled = await send(request("engine.toggle", engine="threat_intel",
        base=before["base_version"], updates={"enabled": False}))
    assert disabled["status"] == "applied"
    assert disabled["engine"]["enabled"] is False
    assert not any(a.engine == "threat_intel" for a in registry.process_packet(packet(9443)))
    enabled = await send(request("engine.toggle", engine="threat_intel",
        base=disabled["base_version"], updates={"enabled": True}))
    assert enabled["status"] == "applied"
    assert editor.get_engine_config("threat_intel")["enabled"] is True
    assert registry._find_active("threat_intel")._feed_mgr is feeds
    assert any(a.engine == "threat_intel" for a in registry.process_packet(packet(9443)))
    assert not stopped
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("interval", [True, 0, -1, "1", [], {}])
async def test_empty_schema_invalid_tick_interval_rejected_before_mutation(db, control, interval):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request(engine="threat_intel"))
    active = registry._find_active("threat_intel")
    with pytest.raises(SensorControlError) as invalid:
        await send(request("engine.configure", engine="threat_intel",
            base=before["base_version"], updates={"tick_interval": interval}))
    assert invalid.value.code == "engine_configuration_invalid"
    assert registry._find_active("threat_intel") is active
    assert editor.get_engine_config("threat_intel") == before["engine"]["config"]
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log") == 0
    assert not stopped


@pytest.mark.asyncio
async def test_empty_schema_valid_tick_interval_saved_and_loaded(control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request(engine="threat_intel"))
    applied = await send(request("engine.configure", engine="threat_intel",
        base=before["base_version"], updates={"tick_interval": 2}))
    assert applied["status"] == "applied"
    assert editor.get_engine_config("threat_intel")["tick_interval"] == 2
    assert registry._find_active("threat_intel").tick_interval == 2
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("condition", ["viewer", "analyst", "disabled", "old_version"])
async def test_sensor_rechecks_actual_account_before_mutation(db, control, condition):
    service, registry, editor, request, send, stopped, accounts, _ = control
    before = await send(request())
    actor = None
    overrides = {}
    if condition in {"viewer", "analyst"}:
        actor = await accounts.create("reader", "a-strong-test-password-123", condition, "test")
        assert (await send(request(actor=actor)))["status"] == "read"
    elif condition == "disabled":
        await db.pool.execute("UPDATE user_accounts SET enabled=FALSE")
    else:
        overrides["actor_version"] = 999
    with pytest.raises(SensorControlError) as error:
        await send(request("engine.configure", actor=actor, base=before["base_version"],
                           updates={"threshold": 5}, **overrides))
    assert error.value.status == 403
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert editor.get_engine_config("port_scan")["threshold"] == 15
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("condition", ["expired", "replaced", "base", "schema"])
async def test_stale_generation_and_invalid_candidate_never_mutate(db, control, condition):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    base = before["base_version"]
    updates = {"threshold": 5}
    if condition in {"expired", "replaced"}:
        await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
        if condition == "replaced":
            await SensorStateRepository(db).claim("office", uuid4())
    elif condition == "base":
        editor.update_engine_config("port_scan", {"threshold": 60})
    else:
        updates = {"unknown_setting": 1}
    with pytest.raises(SensorControlError) as error:
        await send(request("engine.configure", base=base, updates=updates))
    assert error.value.status == (400 if condition == "schema" else 409)
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert registry._find_active("port_scan").config["threshold"] == 15
    assert not stopped


@pytest.mark.asyncio
async def test_failed_applied_audit_keeps_prepared_and_does_not_reexecute(db, control, monkeypatch):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    command = request("engine.configure", base=before["base_version"], updates={"threshold": 5})
    audit = service._audit
    async def fail_applied(conn, command, action, details):
        if action == "sensor_change_applied":
            raise OSError("injected completion storage failure")
        await audit(conn, command, action, details)
    monkeypatch.setattr(service, "_audit", fail_applied)
    with pytest.raises(SensorControlError) as error:
        await send(command)
    assert error.value.status == 503
    assert stopped == [True]
    assert editor.get_engine_config("port_scan")["threshold"] == 5
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
    engine = registry._find_active("port_scan")
    assert (await send(command))["status"] == "unknown"
    assert registry._find_active("port_scan") is engine


@pytest.mark.asyncio
async def test_lost_reply_after_commit_returns_receipt_without_reloading(db, control):
    service, registry, editor, request, send, stopped, accounts, server = control
    before = await send(request())
    command = request("engine.configure", base=before["base_version"], updates={"threshold": 5})
    async def lose_reply(command):
        await service(command)
        raise ConnectionError("injected reply loss after commit")
    server.handler = lose_reply
    with pytest.raises(SensorControlError) as error:
        await send(command)
    assert error.value.status == 503
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "completed"
    engine = registry._find_active("port_scan")
    server.handler = service
    assert (await send(command))["status"] == "applied"
    assert registry._find_active("port_scan") is engine
    assert not stopped


@pytest.mark.asyncio
async def test_prepared_audit_failure_does_not_change_engine_or_file(db, control, monkeypatch):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    async def fail(*args):
        raise OSError("injected prepared audit failure")
    monkeypatch.setattr(service, "_audit", fail)
    with pytest.raises(SensorControlError):
        await send(request("engine.configure", base=before["base_version"], updates={"threshold": 5}))
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
    assert editor.get_engine_config("port_scan")["threshold"] == 15
    assert registry._find_active("port_scan").config["threshold"] == 15
    assert not stopped


@pytest.mark.asyncio
async def test_late_account_change_after_prepare_is_rechecked(db, control, monkeypatch):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    original = service._finish
    async def change_role(command):
        await db.pool.execute("UPDATE user_accounts SET role='viewer',version=version+1")
        return await original(command)
    monkeypatch.setattr(service, "_finish", change_role)
    with pytest.raises(SensorControlError) as error:
        await send(request("engine.configure", base=before["base_version"], updates={"threshold": 5}))
    assert error.value.status == 403
    assert editor.get_engine_config("port_scan")["threshold"] == 15
    assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
    assert not stopped


@pytest.mark.asyncio
async def test_reused_request_id_with_different_update_is_refused(control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    command = request("engine.configure", base=before["base_version"], updates={"threshold": 5})
    await send(command)
    conflict = request("engine.configure", base=before["base_version"], updates={"threshold": 10},
                       request_id=command.request_id)
    with pytest.raises(SensorControlError) as error:
        await send(conflict)
    assert error.value.code == "sensor_request_conflict"
    assert editor.get_engine_config("port_scan")["threshold"] == 5


@pytest.mark.asyncio
async def test_return_to_same_configuration_does_not_revalidate_old_request(db, control):
    service, registry, editor, request, send, stopped, *_ = control
    before = await send(request())
    disabled = await send(request("engine.toggle", base=before["base_version"], updates={"enabled": False}))
    enabled = await send(request("engine.toggle", base=disabled["base_version"], updates={"enabled": True}))
    assert enabled["engine"]["config"] == before["engine"]["config"]
    assert enabled["base_version"] != before["base_version"]
    with pytest.raises(SensorControlError) as error:
        await send(request("engine.configure", base=before["base_version"], updates={"threshold": 5}))
    assert error.value.code == "engine_configuration_changed"
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 2
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("side", ["client", "server"])
async def test_wrong_socket_peer_cannot_read_or_mutate(control, side):
    service, registry, editor, request, send, stopped, accounts, server = control
    if side == "server":
        server.allowed_uid += 1
    with pytest.raises(SensorControlError):
        await send_sensor_control(server.path, request().to_bytes(),
                                  expected_uid=os.getuid() + (side == "client"))
    assert not stopped


def test_strict_control_request_rejects_duplicate_fields_nonfinite_and_extra_fields():
    with pytest.raises(ValueError):
        SensorControlRequest.from_bytes(b'{"request_id":"a","request_id":"b"}')
    with pytest.raises(ValueError):
        SensorControlRequest.from_bytes(b'{"updates":{"threshold":NaN}}')
    with pytest.raises(ValueError):
        SensorControlRequest.from_bytes(b'{"command":"rm"}')
