"""실제 센서 소켓의 NetFlow 설정 변경·감사·재기동 설정 경계."""

from pathlib import Path
import time

import pytest
import yaml

from netwatcher.netflow.engines.port_scan import FlowPortScanEngine
from netwatcher.netflow.processor import FlowProcessor
from netwatcher.services.sensor_control import SensorControlError
from tests.test_netflow.test_processor import _make_flow
from tests.test_services.test_sensor_control import control


def bind_flow(control):
    service, registry, editor, *_ = control
    path = Path(editor._path)
    document = yaml.safe_load(path.read_text())
    config = {"enabled": True, "threshold": 20, "window_seconds": 60}
    document["netwatcher"]["netflow"] = {"enabled": True, "engines": {"flow_port_scan": config}}
    # 같은 이름의 패킷 설정이 있어도 저장 위치를 혼동하지 않는다.
    document["netwatcher"]["engines"]["flow_port_scan"] = {"threshold": 199}
    path.write_text(yaml.safe_dump(document))
    processor = FlowProcessor()
    processor.configure_engine(FlowPortScanEngine, config)
    service.flow_processor = processor
    return processor


@pytest.mark.asyncio
async def test_flow_engine_states_cover_packet_and_flow_engines(db, control, monkeypatch):
    """패킷·흐름 엔진이 섞인 구성에서도 일괄 조회가 정확해야 한다.

    흐름 엔진의 설정은 netflow 섹션에서, 패킷 엔진의 설정은 engines 섹션에서
    읽어야 한다. 같은 이름이 두 섹션에 있어도 섹션을 혼동하지 않고, 일괄
    조회가 단건 조회와 같은 상태·버전을 내야 한다.
    """
    bind_flow(control)
    service, registry, editor, request, send, stopped, *_ = control
    loads = []
    original = editor._load
    monkeypatch.setattr(editor, "_load", lambda: (loads.append(1), original())[1])

    bulk = await send(request("engine.states", engine="states"))
    assert len(loads) == 1, "패킷·흐름 섹션을 함께 읽어도 파싱은 1회여야 한다"
    names = [entry["engine"]["name"] for entry in bulk["engines"]]
    assert "flow_port_scan" in names and "port_scan" in names
    assert len(names) == len(set(names)), "같은 엔진이 두 번 들어왔다"

    by_name = {entry["engine"]["name"]: entry for entry in bulk["engines"]}
    for name in names:
        single = await send(request(engine=name))
        assert by_name[name] == {"engine": single["engine"],
                                 "base_version": single["base_version"]}, name
    # 흐름 엔진은 netflow 섹션 설정을, 패킷 엔진은 engines 섹션 설정을 쓴다.
    flow = by_name["flow_port_scan"]["engine"]
    assert flow["config"]["threshold"] == 20
    assert by_name["port_scan"]["engine"]["config"]["threshold"] == 15


@pytest.mark.asyncio
async def test_flow_socket_changes_real_detection_and_persists_only_netflow(db, control):
    processor = bind_flow(control)
    service, registry, editor, request, send, stopped, *_ = control
    name = "flow_port_scan"
    catalog = await send(request("engine.catalog", engine="catalog"))
    assert name in catalog["engines"]
    before = await send(request(engine=name))
    processor.on_flows([_make_flow(dst_port=port) for port in range(10, 15)])
    assert processor.engines[0].on_tick(time.time()) == []
    command = request("engine.configure", engine=name, base=before["base_version"], updates={"threshold": 5})
    result = await send(command)
    assert result["status"] == "applied" and result["engine"]["config"]["threshold"] == 5
    processor.on_flows([_make_flow(dst_port=port) for port in range(10, 15)])
    engine = processor.engines[0]
    assert len(engine.on_tick(time.time())) == 1
    assert await send(command) == result
    assert processor.engines[0] is engine
    assert engine.on_tick(time.time()) == []
    assert editor.get_engine_config(name) == {"threshold": 199}
    saved = editor.get_flow_engine_config(name)
    assert saved["threshold"] == 5
    restarted = FlowProcessor()
    restarted.configure_engine(FlowPortScanEngine, saved)
    restarted.on_flows([_make_flow(dst_port=port) for port in range(10, 15)])
    assert len(restarted.engines[0].on_tick(time.time())) == 1
    for enabled in (False, True):
        before = await send(request(engine=name))
        applied = await send(request("engine.toggle", engine=name, base=before["base_version"], updates={"enabled": enabled}))
        assert applied["engine"]["enabled"] is enabled
        assert bool(processor.engines) is enabled
        assert editor.get_flow_engine_config(name)["enabled"] is enabled
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 3
    assert stopped == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["invalid", "viewer", "stale", "save"])
async def test_flow_change_failure_never_reports_applied(db, control, monkeypatch, failure):
    processor = bind_flow(control)
    service, registry, editor, request, send, stopped, accounts, *_ = control
    before = await send(request(engine="flow_port_scan"))
    kwargs = {"engine": "flow_port_scan", "base": before["base_version"], "updates": {"threshold": 5}}
    if failure == "invalid":
        kwargs["updates"] = {"threshold": True}
    elif failure == "viewer":
        kwargs["actor"] = await accounts.create("flow-viewer", "a-strong-test-password-123", "viewer", "test")
    elif failure == "stale":
        kwargs["base"] = "0" * 64
    else:
        def fail(*args):
            raise OSError("simulated write failure")
        monkeypatch.setattr(editor, "update_flow_engine_config", fail)
    with pytest.raises(SensorControlError):
        await send(request("engine.configure", **kwargs))
    assert editor.get_flow_engine_config("flow_port_scan")["threshold"] == 20
    assert processor.get_engine_info("flow_port_scan")["config"]["threshold"] == 20
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_applied'") == 0
    assert bool(stopped) is (failure == "save")
