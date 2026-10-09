"""격리 컨테이너의 실제 RAW 캡처·소유권 상실·센서 전용 CLI 검증."""

import asyncio
import hashlib
from copy import deepcopy
import json
import os
import secrets
from pathlib import Path
import shutil
from uuid import uuid4

import pytest
import yaml

from netwatcher.storage.sensor_state import SensorStateRepository


async def docker(*args, payload=None, timeout=30, check=True):
    process = await asyncio.create_subprocess_exec("docker", *args,
        stdin=asyncio.subprocess.PIPE if payload is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await process.communicate(payload)
        if check:
            assert process.returncode == 0, stderr.decode()[-1000:]
        return stdout + stderr if args and args[0] == "logs" else stdout
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_reason,workers", [("signal", 1), ("lease", 1), ("control", 1), ("control", 2)])
async def test_real_sensor_cli_captures_private_loopback_without_web_or_net_admin(db, config, tmp_path, stop_reason, workers):
    image = os.environ.get("PANOPTICON_NATIVE_SENSOR_IMAGE")
    postgres = os.environ.get("PANOPTICON_TEST_PG_CONTAINER")
    if not image or not postgres or not shutil.which("docker"):
        pytest.skip("Provide an owned PostgreSQL container and PANOPTICON_NATIVE_SENSOR_IMAGE for isolated RAW capture")
    prefix = "panopticon-sensor-" + uuid4().hex[:12]
    network, volume, container = prefix + "-net", prefix + "-data", prefix + "-app"
    created_network = created_volume = attached = False
    sensor_id = "docker-native"
    settings = deepcopy(config.raw)
    settings["workers"] = workers
    if workers > 1:
        settings["support"] = {"profile": "full"}
    settings.update({"input": {"mode": "native"},
        "native": {"sensor_id": sensor_id, "heartbeat_seconds": 1, "lease_seconds": 10},
        "interface": "lo", "promiscuous": False,
        "bpf_filter": "tcp and src host 192.0.2.55", "response": {"enabled": False},
        "web": {"host": "127.0.0.1", "port": 38585},
        "logging": {"level": "INFO", "directory": "/app/data/logs"},
        "evidence": {"directory": "/app/data/pcaps"},
        "threatfeeds": {"config_path": "/app/data/feeds.yaml"}})
    settings["postgresql"]["host"] = "sensor-test-db"
    settings["postgresql"]["port"] = 5432
    settings["engines"]["port_scan"]["threshold"] = 5
    control_mode = stop_reason == "control"
    if control_mode:
        from netwatcher.detection.engines.port_scan import PortScanEngine
        from netwatcher.detection.schema_utils import normalize_schema
        from netwatcher.storage.user_accounts import UserAccounts
        settings["engines"]["port_scan"] = {
            name: field["default"] for name, field in normalize_schema(PortScanEngine.config_schema).items()}
        settings["engines"]["port_scan"].update({"enabled": True, "threshold": 5})
        settings["auth"].update({"enabled": True, "multi_user": True, "jwt_secret": secrets.token_hex(32)})
        settings["native"]["control"] = {"enabled": True, "allowed_uid": 1000, "socket_gid": 1000,
                                         "socket_path": "/app/data/control/sensor.sock"}
        admin = await UserAccounts(db).create("docker-admin", "a-strong-test-password-123", "admin", "test")
    sensor_started = False
    try:
        created_network = True
        await docker("network", "create", "--internal", "--label", "panopticon.test=native-sensor", network)
        attached = True
        await docker("network", "connect", "--alias", "sensor-test-db", network, postgres)
        created_volume = True
        await docker("volume", "create", "--label", "panopticon.test=native-sensor", volume)
        initialize = """import os,sys
os.chmod('/data',0o700)
for name in ('logs','pcaps','threatfeeds'):
 os.makedirs('/data/'+name,mode=0o700,exist_ok=True)
with open('/data/sensor.yaml','w') as target: target.write(sys.stdin.read())
os.chmod('/data/sensor.yaml',0o600)
with open('/data/feeds.yaml','w') as target: target.write('feeds: []\\n')
"""
        if control_mode:
            initialize += "\nos.chmod('/data',0o710)\nos.chown('/data',-1,1000)\nos.mkdir('/data/control',0o710)\nos.chown('/data/control',-1,1000)\n"
        await docker("run", "--rm", "-i", "--network", "none", "--mount", f"type=volume,src={volume},dst=/data",
            "--entrypoint", "python", image, "-c", initialize,
            payload=yaml.safe_dump({"netwatcher": settings}).encode())
        sensor_started = True
        await docker("run", "-d", "--name", container, "--label", "panopticon.test=native-sensor",
            "--network", network, "--dns", "127.0.0.1", "--cap-drop", "ALL", "--cap-add", "NET_RAW",
            "--security-opt", "no-new-privileges:true", "--group-add", "1000", "--read-only", "--cpus", "1", "--memory", "512m",
            "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--no-healthcheck",
            "--mount", f"type=volume,src={volume},dst=/app/data", "-e", "NETWATCHER_SKIP_DOTENV=1",
            image, "--component", "sensor", "-c", "/app/data/sensor.yaml")
        repo = SensorStateRepository(db)
        async with asyncio.timeout(25):
            while True:
                row = await repo.read(sensor_id)
                if row and row["snapshot"].get("runtime", {}).get("capture_running") is True:
                    break
                state = json.loads(await docker("inspect", "--format", "{{json .State}}", container))
                assert state["Running"], "Inspect private sensor.log for startup failure"
                await asyncio.sleep(.1)
        inspection = """import json,socket,hashlib,errno
from pathlib import Path
fields=dict(line.split(':',1) for line in Path('/proc/1/status').read_text().splitlines() if ':' in line)
sock=socket.socket();sock.settimeout(1)
web=sock.connect_ex(('127.0.0.1',38585))==0
sock.close()
try:
 Path('/app/root-write-probe').write_text('probe')
 readonly=False
except OSError as exc:
 readonly=exc.errno==errno.EROFS
files=['netwatcher/app.py','netwatcher/__main__.py','netwatcher/services/sensor_state.py','netwatcher/storage/sensor_state.py','netwatcher/capture/sniffer.py','netwatcher/services/sensor_control.py','netwatcher/services/sensor_control_transport.py','netwatcher/response/transport.py','netwatcher/capture/pool.py','netwatcher/capture/worker.py','netwatcher/capture/worker_feeds.py','netwatcher/capture/worker_rules.py']
print(json.dumps({'cap_eff':int(fields['CapEff'].strip(),16),'nnp':int(fields['NoNewPrivs'].strip()),'web_listening':web,'root_readonly':readonly,
 'source_hashes':{name:hashlib.sha256(Path('/app',name).read_bytes()).hexdigest() for name in files}}))
"""
        observed = json.loads(await docker("exec", container, "python", "-c", inspection))
        root = Path(__file__).resolve().parents[2]
        expected_hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in observed["source_hashes"]}
        assert observed == {"cap_eff": 1 << 13, "nnp": 1, "web_listening": False,
                            "root_readonly": True, "source_hashes": expected_hashes}
        traffic = """from scapy.all import Ether,IP,TCP,sendp
packets=[Ether(src='02:00:00:00:00:91',dst='02:00:00:00:00:92')/IP(src='192.0.2.55',dst='127.0.0.1')/TCP(sport=50000,dport=port,flags='S') for port in range(9911,9918)]
sendp(packets,iface='lo',inter=.05,verbose=False)
"""
        if control_mode:
            from netwatcher.services.sensor_control import SensorControlRequest
            owner = await db.pool.fetchval("SELECT owner FROM sensor_runtime_state WHERE sensor_id=$1", sensor_id)
            client = """import asyncio,sys,json
from pathlib import Path
from netwatcher.services.sensor_control_transport import send_sensor_control
print(json.dumps(asyncio.run(send_sensor_control(Path('/app/data/control/sensor.sock'),sys.stdin.buffer.read(),expected_uid=0))))
"""
            async def control_request(operation="engine.read", base="", updates=None):
                command = SensorControlRequest.from_bytes(json.dumps({"request_id": str(uuid4()),
                    "sensor_id": sensor_id, "owner": str(owner), "actor_id": str(admin["id"]),
                    "actor_version": admin["version"], "operation": operation,
                    "engine": "catalog" if operation == "engine.catalog" else "port_scan",
                    "base_version": base, "updates": updates or {}}).encode())
                reply = await docker("exec", "-i", "--user", "1000:1000", container, "python", "-c", client,
                                     payload=command.to_bytes())
                return json.loads(reply)
            catalog = await control_request("engine.catalog")
            assert catalog["status"] == "catalog" and "port_scan" in catalog["engines"] and len(catalog["engines"]) <= 64
            before = await control_request()
            disabled = await control_request("engine.toggle", before["base_version"], {"enabled": False})
            assert disabled["status"] == "applied" and disabled["engine"]["enabled"] is False
            await docker("exec", container, "python", "-c", traffic)
            async with asyncio.timeout(5):
                while (await repo.read(sensor_id))["snapshot"].get("stages", {}).get("capture", {}).get("received", 0) < 7:
                    await asyncio.sleep(.05)
            await asyncio.sleep(1.2)
            assert await db.pool.fetchval("SELECT count(*) FROM events WHERE engine='port_scan'") == 0
            enabled = await control_request("engine.toggle", disabled["base_version"], {"enabled": True})
            assert enabled["status"] == "applied" and enabled["engine"]["enabled"] is True
            assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 2
        await docker("exec", container, "python", "-c", traffic)
        async with asyncio.timeout(10):
            while await db.pool.fetchval("SELECT count(*) FROM events WHERE host(source_ip)='192.0.2.55'") == 0:
                await asyncio.sleep(.05)
        row = await repo.read(sensor_id)
        assert row["stale"] is False and row["snapshot"]["runtime"]["registered_engines"] > 0
        checks = row["snapshot"]["runtime"]["health_components"]
        assert checks["sniffer"]["status"] == "healthy"
        assert checks["engines"]["enabled"] > 0
        assert checks["alert_queue"]["max_size"] > 0
        assert checks["stats_flush"]["status"] == "healthy"
        assert row["snapshot"]["sensor_id"] == sensor_id
        if stop_reason == "lease":
            await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
            owner = uuid4()
            await repo.claim(sensor_id, owner)
            result = await docker("wait", container, timeout=15)
            assert result.strip() == b"1"
            assert await db.pool.fetchval("SELECT owner FROM sensor_runtime_state") == owner
            assert (await repo.read(sensor_id))["stale"] is False
        else:
            await docker("stop", "--time", "12", container, timeout=15)
            state = json.loads(await docker("inspect", "--format", "{{json .State}}", container))
            assert state["ExitCode"] == 0
            assert (await repo.read(sensor_id))["stale"] is True
        completed_log = (await docker("logs", container)).decode()
        assert "Sniffer stopped" in completed_log
        assert "Shutdown unconfirmed stages: []" in completed_log
        assert "PostgreSQL pool closed" in completed_log
    finally:
        if sensor_started:
            log = tmp_path / "sensor.log"
            log.write_bytes(await docker("logs", container, check=False))
            log.chmod(0o600)
            await docker("rm", "-f", container, check=False)
        if attached:
            await docker("network", "disconnect", network, postgres, check=False)
        if created_network:
            await docker("network", "rm", network, check=False)
        if created_volume:
            await docker("volume", "rm", volume, check=False)
