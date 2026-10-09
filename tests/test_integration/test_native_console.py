"""실제 일반 사용자 CLI·DB·센서 소켓의 독립 Native 콘솔 실행."""

import asyncio
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
from uuid import uuid4

import httpx
import pytest
import yaml
import websockets

from netwatcher.native_console import NativeConsole
from netwatcher.storage.repositories import EventRepository, IncidentRepository
from netwatcher.storage.sensor_state import SensorStateRepository
from tests.test_services.test_sensor_control import control


@pytest.mark.asyncio
async def test_actual_rootless_cli_uses_sensor_control_and_read_services(db, config, control, tmp_path, monkeypatch):
    service, registry, editor, request, send, stopped, accounts, server = control
    monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "true")
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32)})
    config.raw["input"] = {"mode": "native"}
    config.raw["native"] = {"sensor_id": "office", "console": {"refresh_seconds": 1},
        "control": {"enabled": True, "socket_path": str(server.path), "expected_uid": os.getuid(), "allowed_uid": os.getuid()}}
    config.raw["response"] = {"enabled": False}
    config.raw["response_execution"] = {"enabled": False}
    config.raw["logging"] = {"directory": str(tmp_path / "logs")}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    config.raw["web"] = {"host": "127.0.0.1", "port": port}
    await SensorStateRepository(db).publish("office", service.owner,
        {"state": "partial", "reasons": ["시험 센서는 실제 패킷 입력을 받지 않습니다."], "no_traffic_observed": None}, lease_seconds=120)
    identifier = await IncidentRepository(db).insert("WARNING", "Console integration")
    path = tmp_path / "console.yaml"
    path.write_text(yaml.safe_dump({"netwatcher": config.raw}))
    path.chmod(0o600)
    env = {key: value for key, value in os.environ.items() if not key.startswith("NETWATCHER_DB_")}
    env.pop("NETWATCHER_JWT_SECRET", None)
    env["NETWATCHER_SKIP_DOTENV"] = "1"
    root = Path(__file__).resolve().parents[2]
    code = """
import importlib.abc,runpy,sys
config,root=sys.argv[1:]
sys.path.insert(0,root)
class RejectCapture(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path,target=None):
  if fullname in ('scapy','netwatcher.capture','netwatcher.app','netwatcher.response.blocker') or fullname.startswith(('scapy.','netwatcher.capture.')):
   raise AssertionError('Rootless console imported capture or local blocking: '+fullname)
sys.meta_path.insert(0,RejectCapture())
sys.argv=['netwatcher','-c',config]
runpy.run_module('netwatcher',run_name='__main__')
"""
    child = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", code, str(path), str(root),
        cwd=root, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            async with asyncio.timeout(15):
                while True:
                    assert child.returncode is None, "Inspect private test log for console startup failure"
                    try:
                        if (await client.get("/health")).status_code == 200:
                            break
                    except httpx.ConnectError:
                        pass
                    await asyncio.sleep(.05)
            status = dict(line.split(":", 1) for line in Path(f"/proc/{child.pid}/status").read_text().splitlines() if ":" in line)
            assert int(status["Uid"].split()[1]) == os.getuid() != 0
            assert all(int(status[name].strip(), 16) == 0 for name in ("CapEff", "CapPrm", "CapAmb"))
            assert int(status["NoNewPrivs"].strip()) == 1
            login = await client.post("/api/auth/login", json={"username": "control-admin", "password": "a-strong-test-password-123"})
            assert login.status_code == 200
            header = {"Authorization": "Bearer " + login.json()["token"]}
            assert (await client.get("/api/incidents")).status_code == 401
            capabilities = (await client.get("/api/capabilities", headers=header)).json()["features"]
            assert capabilities["engines"] and capabilities["engine_control_remote"] and capabilities["incidents"] and capabilities["replay"]
            assert capabilities["direct_blocks"] is False
            listing = await client.get("/api/incidents", headers=header)
            assert listing.status_code == 200 and listing.json()["incidents"][0]["id"] == identifier
            assert (await client.get("/api/observation", headers=header)).json()["state"] == "partial"
            ready = await client.get("/ready")
            assert ready.status_code == 503
            assert ready.json() == {"status": "not_ready"}
            detailed = await client.get("/api/health", headers=header)
            assert detailed.status_code == 200 and detailed.json()["ready"] is False
            assert detailed.json()["components"]["database"]["status"] == "healthy"
            assert detailed.json()["components"]["event_stream"]["status"] == "healthy"
            assert detailed.json()["components"]["observation_reader"]["status"] == "healthy"
            assert detailed.json()["components"]["sniffer"]["status"] == "unknown"
            async with websockets.connect(f"ws://127.0.0.1:{port}/api/ws/events?token={login.json()['token']}") as websocket:
                event_id = await EventRepository(db).insert("port_scan", "WARNING", "Committed relay test", source_ip="192.0.2.10")
                async with asyncio.timeout(5):
                    while True:
                        event = json.loads(await websocket.recv())
                        if event.get("type") == "alert":
                            break
                assert event["id"] == event_id and event["title"] == "Committed relay test"
            assert (await client.get("/api/events", headers=header)).status_code == 200
            from tests.test_web.test_replay_api import _payload
            replay_capabilities = (await client.get("/api/replay-capabilities", headers=header)).json()
            assert replay_capabilities["runtime_equivalent"] is False
            assert replay_capabilities["input_type"] == "features"
            before_events = await db.pool.fetchval("SELECT count(*) FROM events")
            before_config = path.read_bytes()
            replay = await client.post("/api/replay-runs", headers=header, json=_payload())
            assert replay.status_code == 202, replay.text
            run_id = replay.json()["run_id"]
            async with asyncio.timeout(15):
                while True:
                    run = (await client.get(f"/api/replay-runs/{run_id}", headers=header)).json()["run"]
                    if run["status"] in ("completed", "failed", "aborted"):
                        break
                    await asyncio.sleep(.05)
            assert run["status"] == "completed"
            assert (await client.get(f"/api/replay-runs/{run_id}/diff", headers=header)).status_code == 200
            assert await db.pool.fetchval("SELECT count(*) FROM events") == before_events
            assert path.read_bytes() == before_config
            assert registry._find_active("port_scan") is not None
            await accounts.create("replay-viewer", "a-strong-test-password-123", "viewer", "test")
            viewer_login = await client.post("/api/auth/login", json={"username":"replay-viewer", "password":"a-strong-test-password-123"})
            assert viewer_login.status_code == 200
            viewer = {"Authorization":"Bearer " + viewer_login.json()["token"]}
            assert (await client.get(f"/api/replay-runs/{run_id}/diff", headers=viewer)).status_code == 200
            assert (await client.post("/api/replay-runs", headers=viewer, json=_payload())).status_code == 403
            current = (await client.get("/api/engines/port_scan", headers=header)).json()
            changed = await client.patch("/api/engines/port_scan/toggle", headers=header,
                json={"request_id": str(uuid4()), "base_version": current["base_version"], "enabled": False})
            assert changed.status_code == 200, changed.text
            assert changed.json()["engine"]["enabled"] is False
            assert editor.get_engine_config("port_scan")["enabled"] is False
            assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 1
            whitelist = await client.get("/api/whitelist", headers=header)
            assert whitelist.status_code == 200, whitelist.text
            change = await client.put("/api/whitelist/entry", headers=header,
                json={"request_id": str(uuid4()), "base_version": whitelist.json()["base_version"],
                      "type": "ip", "value": "192.0.2.10", "present": True})
            assert change.status_code == 200, change.text
            assert registry.whitelist.is_ip_whitelisted("192.0.2.10")
            assert "192.0.2.10" in editor.get_whitelist_config()["ips"]
            assert "192.0.2.10" in (await client.get("/api/whitelist", headers=header)).json()["ips"]
            assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2
            history = await client.get("/api/audit/changes/" + change.json()["request_id"], headers=header)
            assert history.status_code == 200, history.text
            assert history.json()["outcome"] == "applied"
            assert history.json()["requires_reconciliation"] is False
            child.send_signal(signal.SIGTERM)
            async with asyncio.timeout(10):
                stdout, stderr = await child.communicate()
            assert child.returncode == 0, "Console did not stop gracefully"
            assert b"PostgreSQL pool closed" in stdout + stderr
            assert (await SensorStateRepository(db).read("office"))["stale"] is False
            assert server.path.exists() and not stopped
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()


@pytest.mark.parametrize("field,value", [("enabled", False), ("multi_user", False)])
def test_native_console_requires_managed_login(config, monkeypatch, field, value):
    monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "true" if field != "enabled" else "false")
    config.raw["input"] = {"mode": "native"}
    config.raw["native"] = {"sensor_id": "office", "control": {"enabled": True,
        "socket_path": "/tmp/unused-sensor.sock", "expected_uid": 0}}
    config.raw["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32), field: value})
    with pytest.raises(ValueError, match="인증과 개인 계정"):
        NativeConsole(config)
