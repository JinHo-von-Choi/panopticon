"""실제 센서·두 워커·Unix 제어·DB 저장을 함께 검증한다."""

import asyncio
import json
import os
import secrets
import signal
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from scapy.all import Ether, IP, TCP, Raw

from netwatcher.app import NetWatcher
from netwatcher.services.sensor_control import SensorControlRequest, SensorControlError
from netwatcher.services.sensor_control_transport import send_sensor_control
from netwatcher.storage.user_accounts import UserAccounts
from tests.test_integration.test_native_sensor_component import configure, ready, SimulatedSniffer
from tests.test_capture.test_worker_control import hosts_for_workers


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_native_rules_and_whitelist_reach_both_workers_or_stop_input(db, config, tmp_path, monkeypatch, failure):
    module = configure(config, tmp_path, monkeypatch)
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    config.raw["support"] = {"profile": "full"}
    config.raw["workers"] = 2
    socket = tmp_path / "workers.sock"
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32)})
    config.raw["native"]["control"] = {"enabled": True, "allowed_uid": os.getuid(), "socket_path": str(socket)}
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "rules.yaml").write_text(yaml.safe_dump({"rules": [{
        "id": "native-worker-rule", "name": "Native worker rule", "severity": "WARNING",
        "protocol": "tcp", "dst_port": 9443, "content": ["owned-worker-marker"]}]}))
    config.raw["engines"]["signature"] = {"enabled": True, "rules_dir": str(directory), "hot_reload": False}
    Path(config.config_path).write_text(yaml.safe_dump({"netwatcher": config.raw}))
    admin = await UserAccounts(db).create("worker-admin", "a-strong-test-password-123", "admin", "test")
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    stopped_worker = None

    async def send(operation, resource, updates=None, base=""):
        command = SensorControlRequest.from_bytes(json.dumps({"request_id": str(uuid4()),
            "sensor_id": "native-test", "owner": str(app._sensor_publisher.owner),
            "actor_id": str(admin["id"]), "actor_version": admin["version"], "operation": operation,
            "engine": resource, "base_version": base, "updates": updates or {}}).encode())
        return await send_sensor_control(socket, command.to_bytes(), expected_uid=os.getuid())

    def emit():
        for source in hosts_for_workers():
            app._sensor_sniffer._on_packet(Ether(src="02:00:00:00:00:91", dst="02:00:00:00:00:92") /
                IP(src=source, dst="198.51.100.9") / TCP(sport=50000, dport=9443, flags="PA") /
                Raw(b"owned-worker-marker"))

    async def sources():
        rows = await db.pool.fetch("SELECT DISTINCT host(source_ip) AS ip FROM events WHERE engine='signature'")
        return {row["ip"] for row in rows}

    try:
        await ready(app, task)
        before = await send("rules.entry", "rules", {"rule_id": "native-worker-rule"})
        if failure:
            pool = app._sensor_control_server.handler.worker_pool
            stopped_worker = pool._workers[0]
            os.kill(stopped_worker.pid, signal.SIGSTOP)
            with pytest.raises(SensorControlError) as error:
                await send("rules.set", "rules", {"rule_id": "native-worker-rule", "enabled": False}, before["base_version"])
            assert error.value.status == 503
            os.kill(stopped_worker.pid, signal.SIGCONT)
            stopped_worker = None
            with pytest.raises(SensorControlError):
                await asyncio.wait_for(task, 10)
            assert app._sensor_control_unconfirmed
            assert not app._sensor_sniffer._accepting and app._sensor_sniffer.stopped
            assert await db.pool.fetchval("SELECT status FROM sensor_control_claims") == "prepared"
            assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 0
            return
        disabled = await send("rules.set", "rules", {"rule_id": "native-worker-rule", "enabled": False}, before["base_version"])
        emit()
        await asyncio.sleep(1.2)
        assert await sources() == set()
        await send("rules.set", "rules", {"rule_id": "native-worker-rule", "enabled": True}, disabled["base_version"])
        whitelist = await send("whitelist.read", "whitelist")
        added = await send("whitelist.set", "whitelist", {"type": "ip_range", "value": "192.0.2.0/24", "present": True}, whitelist["base_version"])
        emit()
        await asyncio.sleep(1.2)
        assert await sources() == set()
        await send("whitelist.set", "whitelist", {"type": "ip_range", "value": "192.0.2.0/24", "present": False}, added["base_version"])
        emit()
        async with asyncio.timeout(5):
            while await sources() != set(hosts_for_workers()):
                await asyncio.sleep(.02)
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 4
        assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 4
    finally:
        if stopped_worker is not None:
            os.kill(stopped_worker.pid, signal.SIGCONT)
        if not task.done():
            app._request_sensor_stop()
        await asyncio.gather(task, return_exceptions=True)
    assert not socket.exists() and app.db._pool is None
