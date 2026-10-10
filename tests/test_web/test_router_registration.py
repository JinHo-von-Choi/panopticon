"""라우터 정의와 등록의 정합성 검증.

라우터 팩토리를 추가하고 create_app에 등록하지 않거나, 등록 호출의 인자 수가
팩토리 시그니처와 어긋나는 회귀를 막는다.

작성자: 최진호
작성일: 2026-07-27
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import netwatcher.web.routes as routes_pkg
from netwatcher.web.server import create_app
from netwatcher.utils.config import Config


# UI 로드맵에서 의도적으로 제외된 라우터.
# 노출 결정이 바뀌면 이 집합에서 제거하고 create_app에 등록한다.
INTENTIONALLY_UNREGISTERED: set[str] = set()


def _router_factories() -> dict[str, inspect.Signature]:
    """routes 패키지에 정의된 create_*_router 팩토리와 시그니처를 수집한다."""
    factories: dict[str, inspect.Signature] = {}
    for _, module_name, _ in pkgutil.iter_modules(routes_pkg.__path__):
        module = importlib.import_module(f"netwatcher.web.routes.{module_name}")
        for attr, obj in vars(module).items():
            if (
                attr.startswith("create_")
                and attr.endswith("_router")
                and inspect.isfunction(obj)
                and obj.__module__ == module.__name__
            ):
                factories[attr] = inspect.signature(obj)
    return factories


def _server_source() -> str:
    import netwatcher.web.server as server_module

    return inspect.getsource(server_module)


def test_every_factory_is_registered_or_declared_unregistered():
    """정의된 모든 라우터 팩토리는 등록되거나 제외 목록에 명시되어야 한다."""
    source = _server_source()
    missing = [
        name
        for name in _router_factories()
        if name not in source and name not in INTENTIONALLY_UNREGISTERED
    ]
    assert missing == [], f"create_app에 등록되지 않은 라우터 팩토리: {missing}"


def test_unregistered_declarations_still_exist():
    """제외 목록의 항목이 실제 팩토리와 대응하는지 확인한다."""
    factories = _router_factories()
    stale = [name for name in INTENTIONALLY_UNREGISTERED if name not in factories]
    assert stale == [], f"존재하지 않는 팩토리가 제외 목록에 남아 있음: {stale}"


def test_unregistered_factories_are_absent_from_server():
    """제외 목록의 라우터가 실수로 등록되면 목록을 갱신하도록 강제한다."""
    source = _server_source()
    registered = [name for name in INTENTIONALLY_UNREGISTERED if name in source]
    assert registered == [], (
        f"제외 목록에 있으나 create_app에 등록됨: {registered}. "
        "INTENTIONALLY_UNREGISTERED를 갱신하라."
    )


@pytest.fixture
def wiring_config():
    return Config({'web': {'cors': {'allowed_origins': ['http://localhost:38585']}}})


def test_create_app_wires_every_optional_component(wiring_config):
    """모든 선택적 컴포넌트를 주입해도 인자 불일치 없이 앱이 구성된다."""
    topology_mapper = MagicMock()
    topology_mapper.get_graph.return_value = {"nodes": [{"id": "10.0.0.1"}], "links": []}
    topology_mapper.node_count = 1
    topology_mapper.edge_count = 0
    topology_mapper.get_node.return_value = {"ip": "10.0.0.1"}
    topology_mapper.get_neighbors.return_value = []
    risk_scorer = MagicMock()
    risk_scorer.get_risk_summary.return_value = {"score": 8.0}
    risk_scorer.get_high_risk.return_value = [{"ip": "10.0.0.1", "score": 8.0}]
    compliance_mapper = MagicMock()
    compliance_mapper.get_coverage.return_value = {"control-1": {"status": "covered"}}
    compliance_mapper.get_coverage_score.return_value = 1.0
    kpi_calc = MagicMock(calculate=AsyncMock(return_value={"alert_volume": 7}))
    report_gen = MagicMock(generate=AsyncMock(return_value={"framework": "nist"}))
    registry = MagicMock()
    engine = MagicMock()
    engine.name = "test-engine"
    registry.engines = [engine]
    app = create_app(
        wiring_config,
        event_repo=MagicMock(),
        device_repo=MagicMock(),
        stats_repo=MagicMock(),
        dispatcher=MagicMock(),
        auth_manager=None,
        sniffer=MagicMock(),
        correlator=MagicMock(),
        whitelist=MagicMock(),
        blocklist_repo=MagicMock(),
        feed_manager=MagicMock(),
        block_manager=MagicMock(),
        signature_engine=MagicMock(),
        registry=registry,
        yaml_editor=MagicMock(),
        flow_processor=MagicMock(),
        ai_analyzer=MagicMock(),
        topology_mapper=topology_mapper,
        risk_scorer=risk_scorer,
        compliance_mapper=compliance_mapper,
        kpi_calc=kpi_calc,
        report_gen=report_gen,
    )
    paths = {route.path for route in app.routes}
    for expected in ("/api/blocks", "/api/incidents", "/api/rules", "/api/engines"):
        assert expected in paths, f"{expected} 경로가 등록되지 않음"
    client = TestClient(app)
    graph = client.get("/api/topology/graph")
    assert graph.status_code == 200
    assert graph.json() == {
        "graph": topology_mapper.get_graph.return_value, "node_count": 1, "edge_count": 0,
    }
    device = client.get("/api/topology/device/10.0.0.1")
    assert device.status_code == 200
    assert device.json()["risk"] == {"score": 8.0}
    risk_scorer.get_risk_summary.assert_called_once_with("10.0.0.1")
    high_risk = client.get("/api/topology/high-risk?threshold=8")
    assert high_risk.status_code == 200
    assert high_risk.json()["devices"] == risk_scorer.get_high_risk.return_value
    risk_scorer.get_high_risk.assert_called_once_with(threshold=8.0)
    coverage = client.get("/api/compliance/coverage/nist")
    assert coverage.status_code == 200
    assert coverage.json()["active_engines"] == ["test-engine"]
    compliance_mapper.get_coverage.assert_called_once_with("nist", ["test-engine"])
    kpis = client.get("/api/compliance/kpis?days=7")
    assert kpis.status_code == 200
    assert kpis.json() == {"alert_volume": 7}
    kpi_calc.calculate.assert_awaited_once_with(days=7)
    report = client.get("/api/compliance/report/nist?days=7")
    assert report.status_code == 200
    assert report.json() == {"framework": "nist"}
    report_gen.generate.assert_awaited_once_with(
        framework="nist", active_engines=["test-engine"], fmt="json", days=7,
    )


def test_create_app_without_optional_components(wiring_config):
    """선택적 컴포넌트가 없어도 핵심 경로는 구성된다."""
    event_repo = MagicMock()
    event_repo.count = AsyncMock(return_value=3)
    event_repo.count_by_severity_since = AsyncMock(return_value={"high": 3})
    event_repo.count_by_engine_since = AsyncMock(return_value={"test-engine": 3})
    event_repo.list_recent = AsyncMock(return_value=[])
    event_repo.top_sources_since = AsyncMock(return_value=[])
    event_repo.count_by_day_since = AsyncMock(return_value={})
    app = create_app(
        wiring_config,
        event_repo=event_repo,
        device_repo=MagicMock(),
        stats_repo=MagicMock(),
        dispatcher=MagicMock(),
    )
    paths = {route.path for route in app.routes}
    assert "/api/events" in paths
    assert "/api/devices" in paths
    assert "/api/blocks" not in paths
    for expected in ("/api/topology/graph", "/api/topology/high-risk",
                     "/api/compliance/frameworks", "/api/compliance/kpis",
                     "/api/compliance/report/{framework}"):
        assert expected in paths
    client = TestClient(app)
    graph = client.get("/api/topology/graph")
    assert graph.status_code == 200
    assert graph.json() == {"graph": {"nodes": [], "links": []}, "node_count": 0, "edge_count": 0}
    high_risk = client.get("/api/topology/high-risk")
    assert high_risk.status_code == 200
    assert high_risk.json() == {"devices": [], "threshold": 7.0}
    kpis = client.get("/api/compliance/kpis?days=7")
    assert kpis.status_code == 200
    assert kpis.json()["alert_volume"] == 3
    assert kpis.json()["period_days"] == 7
    event_repo.count.assert_awaited_once()
    report = client.get("/api/compliance/report/nist_csf?days=7")
    assert report.status_code == 200
    assert report.json()["active_engines"] == []
    assert report.json()["kpis"]["alert_volume"] == 3
