"""EVE 콘솔의 사건 조회·준비 상태·실시간 경보를 검증한다."""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from netwatcher.ingest.runtime import EveConsole


@pytest.mark.asyncio
@pytest.mark.parametrize("observed_mac,expected", [(None, "unknown"),
    ("02:00:00:00:00:10", "confirmed"), ("02:00:00:00:00:99", "unknown")])
async def test_external_alert_requires_matching_identity_for_context(db, config, device_repo, tmp_path, observed_mac, expected):
    from netwatcher.ingest.repository import EveRepository
    from netwatcher.ingest.tailer import EveTailer

    mac, ip = "02:00:00:00:00:10", "192.0.2.10"
    await device_repo.upsert(mac, ip)
    now = datetime.now(timezone.utc)
    assert await device_repo.confirm_context(mac, ip, 0, {"role": "backup",
        "confirmed_by": "operator", "confirmed_at": now.isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat()})
    record = {"timestamp": now.isoformat(), "event_type": "alert", "src_ip": ip,
              "alert": {"signature_id": 100, "severity": 1, "signature": "External attack alert"}}
    if observed_mac:
        record["ether"] = {"src_mac": observed_mac}
    (tmp_path / "eve.json").write_text(json.dumps(record) + "\n")
    from netwatcher.alerts.stream import EventStream
    stream = EventStream()
    queue = stream.subscribe_ws()
    reader = EveTailer(EveRepository(db, stream), directory=tmp_path, sensor_id="test", source_id="office")
    try:
        assert await reader.poll_once() == 1
    finally:
        reader.close()
    published = json.loads(queue.get_nowait())
    assert published["source_mac"] == observed_mac
    event_id = await db.pool.fetchval("SELECT id FROM events")
    config.raw.update({"input": {"mode": "eve", "eve": {"sources": [{
        "directory": tmp_path, "sensor_id": "test", "source_id": "office"}]}},
        "web": {"host": "127.0.0.1"}})
    app = EveConsole(config, database=db).build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/events/{event_id}")
        assert response.status_code == 200
        event = response.json()["event"]
    assert event["asset_context"]["status"] == expected
    assert event["source_mac"] == observed_mac
    assert event["severity"] == "CRITICAL"
    assert event["metadata"]["external_eve"]["details"]["severity"] == 1
    if not observed_mac:
        assert event["asset_context"]["reason"] == "source_mac_missing"


@pytest.mark.asyncio
async def test_eve_console_reads_alert_without_capture_or_firewall(db, config, tmp_path, monkeypatch):
    config.raw.update({"input": {"mode": "eve", "eve": {"sources": [{
        "directory": tmp_path, "sensor_id": "sensor-1", "source_id": "office"}]}},
                       "web": {"host": "127.0.0.1"}})
    def forbidden(*args, **kwargs):
        raise AssertionError("Native capture or firewall must not start")
    from netwatcher.capture.sniffer import PacketSniffer
    from netwatcher.response.blocker import BlockManager
    monkeypatch.setattr(PacketSniffer, "start", forbidden)
    monkeypatch.setattr(BlockManager, "init_chain", forbidden)
    (tmp_path / "eve.json").write_text(json.dumps({"timestamp": "2026-10-08T01:00:00Z",
        "event_type": "alert", "alert": {"signature_id": 100, "severity": 2, "signature": "Test alert"}}) + "\n")
    console = EveConsole(config, database=db)
    app = console.build_app()
    queue = console.stream.subscribe_ws()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/ready")).status_code == 503
        await console.service.start()
        try:
            async with asyncio.timeout(5):
                message = json.loads(await queue.get())
                while console.service.status()["status"] != "healthy":
                    await asyncio.sleep(0.01)
            assert message["type"] == "alert"
            assert message["severity"] == "WARNING"
            assert (await client.get("/ready")).status_code == 200
            observation = (await client.get("/api/observation")).json()
            assert observation["input_mode"] == "eve"
            capabilities = (await client.get("/api/capabilities")).json()
            assert capabilities["input_mode"] == "eve"
            assert capabilities["features"]["business_reviews"]
            assert not any(value for key, value in capabilities["features"].items() if key not in ("business_reviews", "case_workflows", "work_schedules", "event_groups", "investigation_priorities", "eve_observations"))
            assert observation["loss"]["link_loss"]["status"] == "unknown"
            events = (await client.get("/api/events")).json()
            assert "Test alert" in str(events)
            assert (await client.get("/api/input/status")).json()["packet_capture"] is False
            summary = (await client.get("/api/stats/summary")).json()
            assert summary["total_packets"] is None
            assert summary["protocol_counts"] is None
            assert summary["severity_counts"]["WARNING"] == 1
            onboarding = (await client.get("/api/onboarding")).json()
            assert any(check["name"] == "eve" and check["status"] == "pass" for check in onboarding["checks"])
            assert all(check["name"] not in ("capture", "coverage") for check in onboarding["checks"])
            assert onboarding["input_mode"] == "eve"
            assert any(check["name"] == "eve_coverage" and check["status"] == "unknown"
                       for check in onboarding["checks"])
            assert (await client.get("/api/support-profile")).json()["enforcement_backends"] == []
            assert (await client.post("/api/blocks", json={"ip": "192.0.2.10"})).status_code == 404
        finally:
            await console.service.stop()
        assert (await client.get("/ready")).status_code == 503


def test_eve_rejects_os_execution_configuration(config, tmp_path):
    config.raw.update({"web": {"host": "127.0.0.1"}, "response": {"enabled": True}})
    with pytest.raises(ValueError, match="response.enabled"):
        EveConsole(config)


@pytest.mark.asyncio
async def test_real_cli_serves_eve_alert_as_unprivileged_process(db, config, tmp_path):
    import os
    import socket
    import subprocess
    import sys
    import yaml
    from httpx import ConnectError, ReadError

    if os.geteuid() == 0:
        pytest.skip("This deployment check requires an unprivileged test user")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config.raw.update({"input": {"mode": "eve", "eve": {"sources": [{
        "directory": str(tmp_path), "sensor_id": "sensor-cli", "source_id": "office"}]}},
                       "web": {"host": "127.0.0.1", "port": port}})
    path = tmp_path / "cli.yaml"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        yaml.safe_dump({"netwatcher": config.raw}, stream)
    (tmp_path / "eve.json").write_text(json.dumps({"timestamp": "2026-10-08T01:00:00Z",
        "event_type": "alert", "alert": {"signature_id": 101, "severity": 1, "signature": "CLI alert"}}) + "\n")
    with (tmp_path / "cli.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "netwatcher", "-c", str(path)],
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            async with AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=2) as client:
                async with asyncio.timeout(15):
                    while True:
                        assert process.poll() is None, "EVE CLI terminated before readiness"
                        try:
                            response = await client.get("/ready")
                            if response.status_code == 200:
                                break
                        except (ConnectError, ReadError):
                            pass
                        await asyncio.sleep(0.05)
                assert "CLI alert" in (await client.get("/api/events")).text
                assert (await client.get("/api/input/status")).json()["packet_capture"] is False
                from pathlib import Path
                status = Path(f"/proc/{process.pid}/status").read_text()
                capabilities = next(row for row in status.splitlines() if row.startswith("CapEff:"))
                assert int(capabilities.split()[1], 16) == 0
        finally:
            process.terminate()
            try:
                await asyncio.to_thread(process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait)
    assert process.returncode == 0
    assert "PostgreSQL pool closed" in (tmp_path / "cli.log").read_text()
