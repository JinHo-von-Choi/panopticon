"""분리 센서의 실제 UDP 입력과 제어 소켓을 함께 검증한다."""

import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
from uuid import uuid4

import pytest
import yaml

from netwatcher.app import NetWatcher
from netwatcher.netflow.collector import FlowCollector
from netwatcher.services.sensor_control import SensorControlRequest
from netwatcher.services.sensor_control_transport import send_sensor_control
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.utils.config import Config
from tests.test_integration.test_native_sensor_component import configure, ready, SimulatedSniffer
from tests.test_netflow.test_parser import _make_v5_packet


@pytest.mark.asyncio
async def test_sensor_netflow_udp_uses_socket_approved_threshold(db, config, tmp_path, monkeypatch):
    module = configure(config, tmp_path, monkeypatch)
    monkeypatch.setattr(module, "PacketSniffer", SimulatedSniffer)
    path = tmp_path / "flow-control.sock"
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32)})
    config.raw["native"]["control"] = {"enabled": True, "allowed_uid": os.getuid(), "socket_path": str(path)}
    config.raw["netflow"] = {"enabled": True, "host": "127.0.0.1", "port": 0, "engines": {
        "flow_port_scan": {"enabled": True, "threshold": 20, "window_seconds": 60},
        "flow_data_exfil": {"enabled": False},
    }}
    Path(config.config_path).write_text(yaml.safe_dump({"netwatcher": config.raw}))
    collectors = []
    start = FlowCollector.start
    async def observe_start(collector):
        await start(collector)
        collectors.append(collector)
    monkeypatch.setattr(FlowCollector, "start", observe_start)
    admin = await UserAccounts(db).create("flow-admin", "a-strong-test-password-123", "admin", "test")
    app = NetWatcher(config, sensor_only=True)
    task = asyncio.create_task(app.run())
    def request(operation="engine.read", base="", updates=None, engine="flow_port_scan"):
        return SensorControlRequest.from_bytes(json.dumps({"request_id": str(uuid4()),
            "sensor_id": "native-test", "owner": str(app._sensor_publisher.owner),
            "actor_id": str(admin["id"]), "actor_version": admin["version"], "operation": operation,
            "engine": engine, "base_version": base, "updates": updates or {}}).encode())
    async def send(command):
        return await send_sensor_control(path, command.to_bytes(), expected_uid=os.getuid())
    async def emit(collector, source="192.0.2.83"):
        address = collector._transport.get_extra_info("sockname")
        total = collector._processor.total_flows
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(_make_v5_packet([{"src_ip": source, "dst_ip": "203.0.113.9", "dst_port": p}
                                         for p in range(100, 105)]), address)
        async with asyncio.timeout(3):
            while collector._processor.total_flows < total + 5:
                await asyncio.sleep(.01)
    try:
        await ready(app, task)
        async with asyncio.timeout(5):
            while app._sensor_control_server is None or app._sensor_control_server._server is None:
                if task.done():
                    await task
                await asyncio.sleep(.01)
        collector = collectors[0]
        catalog = await send(request("engine.catalog", engine="catalog"))
        assert {"flow_port_scan", "flow_data_exfil"}.issubset(catalog["engines"])
        assert (await send(request(engine="flow_data_exfil")))["engine"]["enabled"] is False
        await emit(collector)
        collector._processor.on_tick(0)
        assert await db.pool.fetchval("SELECT count(*) FROM events WHERE engine='flow_port_scan'") == 0
        before = await send(request())
        changed = await send(request("engine.configure", before["base_version"], {"threshold": 5}))
        assert changed["status"] == "applied"
        await emit(collector)
        async with asyncio.timeout(5):
            while await db.pool.fetchval("SELECT count(*) FROM events WHERE engine='flow_port_scan'") == 0:
                await asyncio.sleep(.02)
        assert await db.pool.fetchval("SELECT host(source_ip) FROM events WHERE engine='flow_port_scan' LIMIT 1") == "192.0.2.83"
        assert app.registry.get_engine_info("flow_port_scan") is None
        assert yaml.safe_load(Path(config.config_path).read_text())["netwatcher"]["netflow"]["engines"]["flow_port_scan"]["threshold"] == 5
        assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 1
    finally:
        app._request_sensor_stop()
        await asyncio.wait_for(task, 10)
    assert collector._transport is None
    assert not path.exists()
    assert app.db._pool is None
    saved = yaml.safe_load(Path(config.config_path).read_text())["netwatcher"]
    app = NetWatcher(Config(saved, config.config_path), sensor_only=True)
    task = asyncio.create_task(app.run())
    try:
        await ready(app, task)
        async with asyncio.timeout(5):
            while app._sensor_control_server is None or app._sensor_control_server._server is None:
                if task.done():
                    await task
                await asyncio.sleep(.01)
        assert (await send(request()))["engine"]["config"]["threshold"] == 5
        await emit(collectors[-1], source="192.0.2.84")
        async with asyncio.timeout(5):
            while await db.pool.fetchval("SELECT count(*) FROM events WHERE engine='flow_port_scan' AND source_ip='192.0.2.84'") == 0:
                await asyncio.sleep(.02)
        assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 1
    finally:
        app._request_sensor_stop()
        await asyncio.wait_for(task, 10)
    assert collectors[-1]._transport is None
    assert not path.exists()
    assert app.db._pool is None
