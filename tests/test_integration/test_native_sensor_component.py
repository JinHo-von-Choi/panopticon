"""독립 센서의 실제 탐지·저장 파이프라인. NIC 입력만 대체한다."""

import asyncio
import json
import os
import secrets
from pathlib import Path
import sys
from uuid import uuid4

import pytest
import yaml
from scapy.all import Ether, IP, TCP

from netwatcher.app import NetWatcher
from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.storage.sensor_state import SensorStateRepository, SensorLeaseLost


def configure(config, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.raw.update({"input": {"mode": "native"},
        "native": {"sensor_id": "native-test", "heartbeat_seconds": 1, "lease_seconds": 10},
        "response": {"enabled": False}, "web": {"host": "127.0.0.1"},
        "evidence": {"directory": str(tmp_path / "pcaps")},
        "threatfeeds": {"config_path": str(tmp_path / "feeds.yaml")}})
    (tmp_path / "feeds.yaml").write_text("feeds: []\n")
    config.raw["engines"]["port_scan"]["threshold"] = 5
    import netwatcher.app as module
    monkeypatch.setattr(module.AsyncDNSResolver, "_resolve_sync", staticmethod(lambda _: None))
    # 이 경로가 웹 서버를 로드하거나 실행기를 만들면 즉시 실패한다.
    monkeypatch.setitem(sys.modules, "netwatcher.web.server", None)
    import netwatcher.response.executor as executor
    def forbidden(*args, **kwargs):
        raise AssertionError("Sensor must not build a response executor")
    monkeypatch.setattr(executor, "build_executor", forbidden)
    return module


class SimulatedSniffer(PacketSniffer):
    running = False
    stopped = False

    @property
    def is_running(self):
        return self.running

    def start(self):
        self.running = True
        self._accepting = True
        for port in range(9911, 9918):
            self._on_packet(Ether(src="02:00:00:00:00:91", dst="02:00:00:00:00:92") /
                IP(src="192.0.2.55", dst="203.0.113.1") / TCP(sport=50000, dport=port, flags="S"))

    def stop(self, timeout=2):
        self.stop_accepting()
        self.running = False
        self.stopped = True
        self.flush_observation()


async def ready(app, task):
    async with asyncio.timeout(10):
        while not app._capture_started:
            if task.done():
                await task
                pytest.fail("Sensor stopped before capture started")
            await asyncio.sleep(.01)


@pytest.mark.asyncio
async def test_sensor_pipeline_persists_alert_without_loading_web_or_executor(db, config, tmp_path, monkeypatch):
    module = configure(config, tmp_path, monkeypatch)
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    try:
        await ready(app, task)
        async with asyncio.timeout(5):
            while await db.pool.fetchval("SELECT count(*) FROM events") == 0:
                await asyncio.sleep(.02)
        await app._sensor_publisher.publish_once()
        row = await SensorStateRepository(db).read("native-test")
        assert row["stale"] is False
        assert row["snapshot"]["runtime"]["capture_running"] is True
        assert row["snapshot"]["runtime"]["registered_engines"] > 0
        checks = row["snapshot"]["runtime"]["health_components"]
        assert checks["sniffer"]["status"] == "healthy"
        assert checks["engines"]["enabled"] > 0
        assert checks["alert_queue"]["max_size"] > 0
        assert checks["stats_flush"]["status"] == "healthy"
        assert await db.pool.fetchval("SELECT host(source_ip) FROM events LIMIT 1") == "192.0.2.55"
        app._sensor_sniffer.running = False
        await app._sensor_publisher.publish_once()
        stopped = (await SensorStateRepository(db).read("native-test"))["snapshot"]
        assert stopped["state"] == "unknown"
        assert stopped["no_traffic_observed"] is None
        assert stopped["runtime"]["capture_running"] is False
        assert stopped["runtime"]["health_components"]["sniffer"]["status"] == "unhealthy"
        assert stopped["reasons"]
        app._sensor_sniffer.running = True
    finally:
        app._request_sensor_stop()
        await asyncio.wait_for(task, 10)
    assert app._sensor_sniffer.stopped and not app._sensor_sniffer._accepting
    assert (await SensorStateRepository(db).read("native-test"))["stale"] is True
    assert app.db._pool is None


@pytest.mark.asyncio
async def test_running_sensor_stops_capture_when_another_owner_takes_over(db, config, tmp_path, monkeypatch):
    module = configure(config, tmp_path, monkeypatch)
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    repo = SensorStateRepository(db)
    owner = uuid4()
    try:
        await ready(app, task)
        await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
        await repo.claim("native-test", owner)
        with pytest.raises(SensorLeaseLost):
            await asyncio.wait_for(task, 10)
    finally:
        if not task.done():
            app._request_sensor_stop()
            await asyncio.gather(task, return_exceptions=True)
    assert app._sensor_sniffer.stopped and not app._sensor_sniffer._accepting
    assert app.db._pool is None
    assert await db.pool.fetchval("SELECT owner FROM sensor_runtime_state") == owner
    assert (await repo.read("native-test"))["stale"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["applied", "storage_failure"])
@pytest.mark.parametrize("workers", [1, 2])
async def test_sensor_runtime_serves_control_socket_and_cleans_it_on_exit(db, config, tmp_path, monkeypatch, outcome, workers):
    module = configure(config, tmp_path, monkeypatch)
    config.raw["support"] = {"profile": "full"}
    config.raw["workers"] = workers
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    from netwatcher.detection.engines.port_scan import PortScanEngine
    from netwatcher.detection.schema_utils import normalize_schema
    from netwatcher.services.sensor_control import SensorControlRequest, SensorControlError, SensorControlService
    from netwatcher.services.sensor_control_transport import send_sensor_control
    from netwatcher.storage.user_accounts import UserAccounts
    socket = tmp_path / "sensor.sock"
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32)})
    config.raw["native"]["control"] = {"enabled": True, "allowed_uid": os.getuid(), "socket_path": str(socket)}
    config.raw["netflow"] = {"enabled": True, "host": "127.0.0.1", "port": 0, "engines": {}}
    from netwatcher.netflow.collector import FlowCollector
    stop_flow = FlowCollector.stop
    stopped_inputs = []
    def checked_stop(collector):
        # 소켓 정리 함수에 들어오기 전에 수신이 이미 중단돼야 한다.
        stopped_inputs.append(not collector._protocol._accepting)
        stop_flow(collector)
    monkeypatch.setattr(FlowCollector, "stop", checked_stop)
    valid = {name: field["default"] for name, field in normalize_schema(PortScanEngine.config_schema).items()}
    valid.update({"enabled": True, "threshold": 5})
    config.raw["engines"]["port_scan"] = valid
    Path(config.config_path).write_text(yaml.safe_dump({"netwatcher": config.raw}))
    admin = await UserAccounts(db).create("sensor-admin", "a-strong-test-password-123", "admin", "test")
    if outcome == "storage_failure":
        original = SensorControlService._audit
        async def fail_applied(self, conn, command, action, details):
            if action == "sensor_change_applied":
                raise OSError("injected sensor completion failure")
            return await original(self, conn, command, action, details)
        monkeypatch.setattr(SensorControlService, "_audit", fail_applied)
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    def request(operation="engine.read", base="", updates=None):
        return SensorControlRequest.from_bytes(json.dumps({"request_id": str(uuid4()),
            "sensor_id": "native-test", "owner": str(app._sensor_publisher.owner),
            "actor_id": str(admin["id"]), "actor_version": admin["version"], "operation": operation,
            "engine": "port_scan", "base_version": base, "updates": updates or {}}).encode())
    try:
        await ready(app, task)
        async with asyncio.timeout(5):
            while app._sensor_control_server is None or app._sensor_control_server._server is None:
                if task.done():
                    await task
                await asyncio.sleep(.01)
        before = await send_sensor_control(socket, request().to_bytes(), expected_uid=os.getuid())
        command = request("engine.toggle", before["base_version"], {"enabled": False})
        if outcome == "applied":
            result = await send_sensor_control(socket, command.to_bytes(), expected_uid=os.getuid())
            assert result["status"] == "applied" and result["engine"]["enabled"] is False
            assert app.registry._find_active("port_scan") is None
            app._request_sensor_stop()
            await asyncio.wait_for(task, 10)
        else:
            with pytest.raises(SensorControlError) as error:
                await send_sensor_control(socket, command.to_bytes(), expected_uid=os.getuid())
            assert error.value.status == 503
            with pytest.raises(SensorControlError):
                await asyncio.wait_for(task, 10)
            assert app._sensor_control_unconfirmed
            assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
    finally:
        if not task.done():
            app._request_sensor_stop()
        await asyncio.gather(task, return_exceptions=True)
    assert not socket.exists()
    assert app.db._pool is None
    assert app._sensor_sniffer.stopped and not app._sensor_sniffer._accepting
    assert stopped_inputs and all(stopped_inputs)
    assert (await SensorStateRepository(db).read("native-test"))["stale"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ready", "invalid_custom", "applied_audit_failure"])
@pytest.mark.parametrize("workers", [1, 2])
async def test_sensor_startup_binds_real_blocklist_control_and_capture(db, config, tmp_path, monkeypatch, mode, workers):
    module = configure(config, tmp_path, monkeypatch)
    config.raw["support"] = {"profile": "full"}
    config.raw["workers"] = workers
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    from netwatcher.services.sensor_control import SensorControlRequest, SensorControlError
    from netwatcher.services.sensor_control_transport import send_sensor_control
    from netwatcher.storage.user_accounts import UserAccounts
    socket = tmp_path / "blocklist.sock"
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32)})
    config.raw["native"]["control"] = {"enabled": True, "allowed_uid": os.getuid(), "socket_path": str(socket)}
    Path(config.config_path).write_text(yaml.safe_dump({"netwatcher": config.raw}))
    admin = await UserAccounts(db).create("blocklist-admin", "a-strong-test-password-123", "admin", "test")
    if mode == "invalid_custom":
        await db.pool.execute("INSERT INTO custom_blocklist(entry_type,value) VALUES('ip','invalid/99')")
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    def request(operation, base="", updates=None):
        return SensorControlRequest.from_bytes(json.dumps({"request_id": str(uuid4()),
            "sensor_id": "native-test", "owner": str(app._sensor_publisher.owner),
            "actor_id": str(admin["id"]), "actor_version": admin["version"], "operation": operation,
            "engine": "blocklist", "base_version": base, "updates": updates or {}}).encode())
    try:
        await ready(app, task)
        read = request("blocklist.entry", updates={"type": "ip", "value": "198.51.100.7/24"})
        if mode == "invalid_custom":
            with pytest.raises(SensorControlError) as failure:
                await send_sensor_control(socket, read.to_bytes(), expected_uid=os.getuid())
            assert failure.value.status == 503
            assert app.registry._feed_manager is None
        else:
            before = await send_sensor_control(socket, read.to_bytes(), expected_uid=os.getuid())
            command = request("blocklist.set", before["base_version"],
                {"type": "ip", "value": "198.51.100.7/24", "present": True, "notes": "owned capture proof"})
            if mode == "applied_audit_failure":
                await db.pool.execute("""CREATE FUNCTION reject_owned_blocklist_outcome() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN IF NEW.action='sensor_change_applied' THEN RAISE EXCEPTION 'owned outcome rejection'; END IF; RETURN NEW; END $$""")
                await db.pool.execute("""CREATE TRIGGER reject_owned_blocklist_outcome BEFORE INSERT ON audit_log
                    FOR EACH ROW EXECUTE FUNCTION reject_owned_blocklist_outcome()""")
                with pytest.raises(SensorControlError) as failure:
                    await send_sensor_control(socket, command.to_bytes(), expected_uid=os.getuid())
                assert failure.value.status == 503
                with pytest.raises(SensorControlError):
                    await asyncio.wait_for(task, 10)
                assert app._sensor_control_unconfirmed
                assert not app._sensor_sniffer._accepting
                assert app._sensor_sniffer.stopped
                assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 0
                assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
            else:
                applied = await send_sensor_control(socket, command.to_bytes(), expected_uid=os.getuid())
                assert applied["status"] == "applied"
                app._sensor_sniffer._on_packet(Ether(src="02:00:00:00:00:91", dst="02:00:00:00:00:92") /
                    IP(src="192.0.2.55", dst="198.51.100.9") / TCP(sport=50000, dport=443, flags="S"))
                async with asyncio.timeout(5):
                    while await db.pool.fetchval("SELECT count(*) FROM events WHERE engine='threat_intel'") == 0:
                        await asyncio.sleep(.02)
                assert await db.pool.fetchval("SELECT value FROM custom_blocklist") == "198.51.100.0/24"
                assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "completed"
        if not task.done():
            app._request_sensor_stop()
            await asyncio.wait_for(task, 10)
    finally:
        if not task.done():
            app._request_sensor_stop()
        await asyncio.gather(task, return_exceptions=True)
    assert not socket.exists()
    assert app.db._pool is None
    assert (await SensorStateRepository(db).read("native-test"))["stale"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["signal", "lease"])
async def test_initialization_wait_stops_and_releases_resources(db, config, tmp_path, monkeypatch, reason):
    module = configure(config, tmp_path, monkeypatch)
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    from netwatcher.threatintel.feed_manager import FeedManager
    entered = asyncio.Event()
    async def blocked(_):
        entered.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(FeedManager, "update_all", blocked)
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    owner = uuid4()
    try:
        await asyncio.wait_for(entered.wait(), 5)
        assert not app._capture_started
        if reason == "signal":
            app._request_sensor_stop()
            await asyncio.wait_for(task, 5)
        else:
            await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
            await SensorStateRepository(db).claim("native-test", owner)
            with pytest.raises(SensorLeaseLost):
                await asyncio.wait_for(task, 5)
    finally:
        if not task.done():
            app._request_sensor_stop()
            await asyncio.gather(task, return_exceptions=True)
    assert not app._capture_started and app.db._pool is None
    assert not app._sensor_previous_signals
    row = await SensorStateRepository(db).read("native-test")
    assert row["stale"] is (reason == "signal")
    if reason == "lease":
        assert await db.pool.fetchval("SELECT owner FROM sensor_runtime_state") == owner


@pytest.mark.asyncio
async def test_failed_capture_start_cleans_services_database_and_sensor_lease(db, config, tmp_path, monkeypatch):
    module = configure(config, tmp_path, monkeypatch)
    class BrokenSniffer(SimulatedSniffer):
        def start(self):
            raise OSError("Injected capture initialization failure")
    monkeypatch.setattr(module, "PacketSniffer", BrokenSniffer)
    app = NetWatcher(config, sensor_only=True)
    with pytest.raises(OSError, match="initialization failure"):
        await asyncio.wait_for(app.run(), 10)
    assert app._sensor_sniffer.stopped
    assert app.db._pool is None
    assert (await SensorStateRepository(db).read("native-test"))["stale"] is True
    assert not app._sensor_previous_signals


@pytest.mark.parametrize("path", ["response.enabled", "response_execution.enabled"])
def test_sensor_rejects_local_execution_config(config, path):
    section, key = path.split('.')
    config.raw[section] = {key: True}
    with pytest.raises(ValueError, match=path):
        NetWatcher(config, sensor_only=True)


def test_sensor_requires_native_input_and_explicit_sensor_identity(config):
    config.raw["input"] = {"mode": "eve"}
    with pytest.raises(ValueError, match="input.mode"):
        NetWatcher(config, sensor_only=True)
    config.raw["input"]["mode"] = "native"
    with pytest.raises(ValueError, match="식별자"):
        NetWatcher(config, sensor_only=True)
