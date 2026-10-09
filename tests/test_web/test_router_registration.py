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
from unittest.mock import MagicMock

import pytest

import netwatcher.web.routes as routes_pkg
from netwatcher.web.server import create_app
from netwatcher.utils.config import Config


# UI 로드맵에서 의도적으로 제외된 라우터.
# 노출 결정이 바뀌면 이 집합에서 제거하고 create_app에 등록한다.
INTENTIONALLY_UNREGISTERED = {
    "create_compliance_router",
    "create_topology_router",
}


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
        registry=MagicMock(),
        yaml_editor=MagicMock(),
        flow_processor=MagicMock(),
        ai_analyzer=MagicMock(),
    )
    paths = {route.path for route in app.routes}
    for expected in ("/api/blocks", "/api/incidents", "/api/rules", "/api/engines"):
        assert expected in paths, f"{expected} 경로가 등록되지 않음"


def test_create_app_without_optional_components(wiring_config):
    """선택적 컴포넌트가 없어도 핵심 경로는 구성된다."""
    app = create_app(
        wiring_config,
        event_repo=MagicMock(),
        device_repo=MagicMock(),
        stats_repo=MagicMock(),
        dispatcher=MagicMock(),
    )
    paths = {route.path for route in app.routes}
    assert "/api/events" in paths
    assert "/api/devices" in paths
    assert "/api/blocks" not in paths
