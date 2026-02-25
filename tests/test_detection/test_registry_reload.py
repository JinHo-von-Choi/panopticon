"""EngineRegistry 핫리로드/토글 메서드 테스트.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from scapy.all import Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert
from netwatcher.detection.registry import EngineRegistry
from netwatcher.detection.whitelist import Whitelist
from netwatcher.utils.config import Config


# ---------------------------------------------------------------------------
# DummyEngine: 테스트용 최소 엔진
# ---------------------------------------------------------------------------


class DummyEngine(DetectionEngine):
    """테스트 전용 탐지 엔진."""

    name = "dummy"
    config_schema: dict[str, tuple[type, Any]] = {
        "threshold": (int, 10),
        "enabled":   (bool, True),
    }

    def analyze(self, packet: Packet) -> Alert | None:
        return None


class DummyEngine2(DetectionEngine):
    """두 번째 테스트 전용 엔진."""

    name = "dummy2"
    config_schema: dict[str, tuple[type, Any]] = {
        "window_seconds": (int, 60),
        "enabled":        (bool, True),
    }

    def analyze(self, packet: Packet) -> Alert | None:
        return None


class FailingEngine(DetectionEngine):
    """생성 시 예외를 발생시키는 엔진."""

    name = "failing"
    config_schema: dict[str, tuple[type, Any]] = {}

    def __init__(self, config: dict[str, Any]) -> None:
        raise RuntimeError("Intentional init failure")

    def analyze(self, packet: Packet) -> Alert | None:
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config(engines_section: dict | None = None) -> Config:
    """최소 Config 객체를 생성한다."""
    data: dict[str, Any] = {
        "whitelist": {"ips": [], "macs": [], "domains": [], "domain_suffixes": []},
        "engines": engines_section or {},
    }
    return Config(data)


def _make_registry_with_classes(
    config: Config | None = None,
    classes: dict[str, type[DetectionEngine]] | None = None,
    active: list[str] | None = None,
) -> EngineRegistry:
    """수동으로 _engine_classes와 _engines를 설정한 레지스트리를 반환한다.

    discover_and_register()를 호출하지 않고 직접 제어한다.
    """
    if config is None:
        config = _make_config()
    reg = EngineRegistry(config)
    reg._whitelist = Whitelist()
    if classes is None:
        classes = {"dummy": DummyEngine, "dummy2": DummyEngine2}
    reg._engine_classes = dict(classes)

    active = active or []
    for name in active:
        cls = classes[name]
        engine_config = config.get(f"engines.{name}", {})
        if not isinstance(engine_config, dict):
            engine_config = {}
        engine_config.setdefault("enabled", True)
        inst = cls(engine_config)
        inst.set_whitelist(reg._whitelist)
        reg._engines.append(inst)
        reg._last_tick[inst.name] = 0.0
    return reg


# ---------------------------------------------------------------------------
# _engine_classes 추적 테스트
# ---------------------------------------------------------------------------


class TestEngineClassesTracking:
    """discover_and_register() 후 _engine_classes가 올바르게 채워지는지 검증."""

    def test_engine_classes_populated_after_discover(self):
        """discover_and_register() 호출 후 _engine_classes에 모든 엔진이 포함된다."""
        config = _make_config()
        reg = EngineRegistry(config)
        reg.discover_and_register()
        # 실제 엔진 패키지에서 발견된 클래스가 있어야 한다
        assert len(reg._engine_classes) > 0
        # 모든 값이 DetectionEngine 서브클래스인지 확인
        for name, cls in reg._engine_classes.items():
            assert issubclass(cls, DetectionEngine)
            assert cls.name == name

    def test_disabled_engines_still_in_engine_classes(self):
        """disabled 엔진도 _engine_classes에는 포함된다."""
        config = _make_config({"arp_spoof": {"enabled": False}})
        reg = EngineRegistry(config)
        reg.discover_and_register()
        # arp_spoof가 _engine_classes에 존재
        assert "arp_spoof" in reg._engine_classes
        # 하지만 활성 엔진 목록에는 없어야 함
        active_names = [e.name for e in reg._engines]
        assert "arp_spoof" not in active_names


# ---------------------------------------------------------------------------
# get_engine_info 테스트
# ---------------------------------------------------------------------------


class TestGetEngineInfo:
    """get_engine_info() 단위 테스트."""

    def test_active_engine_info(self):
        """활성 엔진의 정보를 올바르게 반환한다."""
        config = _make_config({"dummy": {"enabled": True, "threshold": 20}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, ["dummy"])

        info = reg.get_engine_info("dummy")

        assert info is not None
        assert info["name"] == "dummy"
        assert info["enabled"] is True
        assert info["config"]["threshold"] == 20
        assert "schema" in info

    def test_inactive_engine_info(self):
        """비활성 엔진의 정보를 올바르게 반환한다."""
        config = _make_config({"dummy": {"enabled": False, "threshold": 5}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, [])

        info = reg.get_engine_info("dummy")

        assert info is not None
        assert info["name"] == "dummy"
        assert info["enabled"] is False
        assert info["config"]["threshold"] == 5

    def test_unknown_engine_returns_none(self):
        """알 수 없는 엔진 이름은 None을 반환한다."""
        reg = _make_registry_with_classes()
        info = reg.get_engine_info("nonexistent_engine")
        assert info is None


# ---------------------------------------------------------------------------
# get_all_engine_info 테스트
# ---------------------------------------------------------------------------


class TestGetAllEngineInfo:
    """get_all_engine_info() 단위 테스트."""

    def test_returns_all_engines(self):
        """활성 + 비활성 엔진 모두 반환한다."""
        config = _make_config({
            "dummy":  {"enabled": True, "threshold": 10},
            "dummy2": {"enabled": False},
        })
        reg = _make_registry_with_classes(
            config, {"dummy": DummyEngine, "dummy2": DummyEngine2}, ["dummy"]
        )

        infos = reg.get_all_engine_info()

        assert len(infos) == 2
        names = [i["name"] for i in infos]
        assert "dummy" in names
        assert "dummy2" in names

    def test_active_engines_first(self):
        """활성 엔진이 비활성 엔진보다 앞에 온다."""
        config = _make_config({
            "dummy":  {"enabled": True},
            "dummy2": {"enabled": False},
        })
        reg = _make_registry_with_classes(
            config, {"dummy": DummyEngine, "dummy2": DummyEngine2}, ["dummy"]
        )

        infos = reg.get_all_engine_info()

        # 첫 번째는 활성, 두 번째는 비활성
        assert infos[0]["enabled"] is True
        assert infos[1]["enabled"] is False


# ---------------------------------------------------------------------------
# reload_engine 테스트
# ---------------------------------------------------------------------------


class TestReloadEngine:
    """reload_engine() 단위 테스트."""

    def test_reload_active_engine(self):
        """활성 엔진을 새 설정으로 리로드한다."""
        config = _make_config({"dummy": {"enabled": True, "threshold": 10}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, ["dummy"])

        ok, err, _ = reg.reload_engine("dummy", {"enabled": True, "threshold": 99})

        assert ok is True
        assert err is None
        # 엔진이 교체되었는지 확인
        engine = next(e for e in reg._engines if e.name == "dummy")
        assert engine.config["threshold"] == 99

    def test_reload_inactive_engine_appends(self):
        """비활성 엔진을 리로드하면 _engines에 추가된다."""
        config = _make_config({"dummy2": {"enabled": False}})
        reg = _make_registry_with_classes(
            config, {"dummy": DummyEngine, "dummy2": DummyEngine2}, []
        )
        assert len(reg._engines) == 0

        ok, err, _ = reg.reload_engine("dummy2", {"enabled": True, "window_seconds": 30})

        assert ok is True
        assert err is None
        assert len(reg._engines) == 1
        assert reg._engines[0].name == "dummy2"

    def test_reload_unknown_engine(self):
        """알 수 없는 엔진 리로드 시 실패한다."""
        reg = _make_registry_with_classes()

        ok, err, _ = reg.reload_engine("nonexistent", {"enabled": True})

        assert ok is False
        assert err is not None
        assert "nonexistent" in err

    def test_reload_preserves_index(self):
        """리로드 시 _engines 리스트에서 같은 인덱스를 유지한다."""
        config = _make_config({
            "dummy":  {"enabled": True, "threshold": 10},
            "dummy2": {"enabled": True, "window_seconds": 60},
        })
        reg = _make_registry_with_classes(
            config,
            {"dummy": DummyEngine, "dummy2": DummyEngine2},
            ["dummy", "dummy2"],
        )
        assert reg._engines[0].name == "dummy"
        assert reg._engines[1].name == "dummy2"

        ok, err, _ = reg.reload_engine("dummy", {"enabled": True, "threshold": 42})

        assert ok is True
        # dummy는 여전히 인덱스 0
        assert reg._engines[0].name == "dummy"
        assert reg._engines[0].config["threshold"] == 42
        assert len(reg._engines) == 2

    def test_reload_with_failing_init(self):
        """엔진 초기화 실패 시 (False, 에러메시지)를 반환한다."""
        config = _make_config()
        reg = _make_registry_with_classes(
            config, {"failing": FailingEngine}, []
        )

        ok, err, _ = reg.reload_engine("failing", {"enabled": True})

        assert ok is False
        assert err is not None
        assert "Intentional init failure" in err

    def test_reload_injects_whitelist(self):
        """리로드된 엔진에 whitelist가 주입된다."""
        config = _make_config({"dummy": {"enabled": True}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, [])
        reg._whitelist = Whitelist({"ips": ["10.0.0.1"]})

        ok, _, _ = reg.reload_engine("dummy", {"enabled": True, "threshold": 5})

        assert ok is True
        engine = reg._engines[0]
        assert engine._whitelist is not None
        assert engine._whitelist.is_ip_whitelisted("10.0.0.1")


# ---------------------------------------------------------------------------
# disable_engine 테스트
# ---------------------------------------------------------------------------


class TestDisableEngine:
    """disable_engine() 단위 테스트."""

    def test_disable_active_engine(self):
        """활성 엔진을 비활성화한다."""
        config = _make_config({"dummy": {"enabled": True}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, ["dummy"])
        assert len(reg._engines) == 1

        ok, err, _ = reg.disable_engine("dummy")

        assert ok is True
        assert err is None
        assert len(reg._engines) == 0

    def test_disable_already_disabled(self):
        """이미 비활성인 엔진을 비활성화해도 성공한다 (멱등성)."""
        reg = _make_registry_with_classes(
            classes={"dummy": DummyEngine}, active=[]
        )

        ok, err, _ = reg.disable_engine("dummy")

        assert ok is True
        assert err is None

    def test_disable_unknown_engine(self):
        """알 수 없는 엔진 비활성화 시 실패한다."""
        reg = _make_registry_with_classes()

        ok, err, _ = reg.disable_engine("nonexistent")

        assert ok is False
        assert err is not None

    def test_disable_removes_from_last_tick(self):
        """비활성화 시 _last_tick에서도 제거된다."""
        config = _make_config({"dummy": {"enabled": True}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, ["dummy"])
        assert "dummy" in reg._last_tick

        reg.disable_engine("dummy")

        assert "dummy" not in reg._last_tick


# ---------------------------------------------------------------------------
# enable_engine 테스트
# ---------------------------------------------------------------------------


class TestEnableEngine:
    """enable_engine() 단위 테스트."""

    def test_enable_inactive_engine(self):
        """비활성 엔진을 활성화한다."""
        config = _make_config({"dummy": {"enabled": False}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, [])
        assert len(reg._engines) == 0

        ok, err, _ = reg.enable_engine("dummy", {"enabled": True, "threshold": 15})

        assert ok is True
        assert err is None
        assert len(reg._engines) == 1
        assert reg._engines[0].name == "dummy"
        assert reg._engines[0].config["threshold"] == 15

    def test_enable_already_active_delegates_to_reload(self):
        """이미 활성인 엔진을 enable하면 reload로 위임한다."""
        config = _make_config({"dummy": {"enabled": True, "threshold": 10}})
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, ["dummy"])
        assert reg._engines[0].config["threshold"] == 10

        ok, err, _ = reg.enable_engine("dummy", {"enabled": True, "threshold": 50})

        assert ok is True
        assert err is None
        # 설정이 업데이트되었는지 확인
        assert reg._engines[0].config["threshold"] == 50

    def test_enable_unknown_engine(self):
        """알 수 없는 엔진 활성화 시 실패한다."""
        reg = _make_registry_with_classes()

        ok, err, _ = reg.enable_engine("nonexistent", {"enabled": True})

        assert ok is False
        assert err is not None

    def test_enable_injects_whitelist(self):
        """활성화된 엔진에 whitelist가 주입된다."""
        config = _make_config()
        reg = _make_registry_with_classes(config, {"dummy": DummyEngine}, [])
        reg._whitelist = Whitelist({"domains": ["safe.local"]})

        ok, _, _ = reg.enable_engine("dummy", {"enabled": True})

        assert ok is True
        engine = reg._engines[0]
        assert engine._whitelist is not None
        assert engine._whitelist.is_domain_whitelisted("safe.local")
