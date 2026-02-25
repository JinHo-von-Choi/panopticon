"""탐지 엔진 자동 발견 및 등록.

런타임 핫리로드, 개별 엔진 활성화/비활성화 기능을 포함한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import time
from typing import Any

from scapy.all import Packet

from netwatcher.detection.base import DetectionEngine

try:
    from netwatcher.web.metrics import engine_analyze_duration as _engine_analyze_duration
except ImportError:
    _engine_analyze_duration = None
from netwatcher.detection.models import Alert, downgrade_severity
from netwatcher.detection.schema_utils import schema_to_api
from netwatcher.detection.whitelist import Whitelist
from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.detection.registry")


class EngineRegistry:
    """탐지 엔진을 발견, 등록하고 패킷을 분배한다."""

    def __init__(self, config: Config) -> None:
        """엔진 레지스트리를 초기화한다. 설정을 저장하고 엔진 목록을 비운다."""
        self._config  = config
        self._engines: list[DetectionEngine] = []
        self._whitelist: Whitelist | None = None
        # tick_interval 지원을 위한 엔진별 마지막 틱 타임스탬프
        self._last_tick: dict[str, float] = {}
        # 발견된 모든 엔진 클래스 매핑 (disabled 포함)
        self._engine_classes: dict[str, type[DetectionEngine]] = {}

    def discover_and_register(self) -> None:
        """engines/ 패키지에서 엔진을 자동 발견한다."""
        import netwatcher.detection.engines as engines_pkg

        # 설정에서 화이트리스트 초기화
        wl_config = self._config.get("whitelist", {})
        if isinstance(wl_config, dict):
            self._whitelist = Whitelist(wl_config)
        else:
            self._whitelist = Whitelist()

        for finder, module_name, _ in pkgutil.iter_modules(engines_pkg.__path__):
            full_name = f"netwatcher.detection.engines.{module_name}"
            try:
                module = importlib.import_module(full_name)
            except Exception:
                logger.exception("Failed to import engine module: %s", full_name)
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, DetectionEngine)
                    and obj is not DetectionEngine
                    and hasattr(obj, "name")
                    and obj.name
                ):
                    # 모든 엔진 클래스를 저장 (disabled 포함)
                    self._engine_classes[obj.name] = obj

                    engine_config = self._config.get(f"engines.{obj.name}", {})
                    if not isinstance(engine_config, dict):
                        engine_config = {}
                    if not engine_config.get("enabled", True):
                        logger.info("Engine %s is disabled", obj.name)
                        continue
                    try:
                        engine = obj(engine_config)
                        # 설정 스키마 검증
                        warnings = engine.validate_config()
                        for w in warnings:
                            logger.warning("Config validation: %s", w)
                        # 화이트리스트 주입
                        engine.set_whitelist(self._whitelist)
                        self._engines.append(engine)
                        self._last_tick[engine.name] = 0.0
                        logger.info("Registered engine: %s", engine)
                    except Exception:
                        logger.exception("Failed to instantiate engine: %s", obj.name)

    def process_packet(self, packet: Packet) -> list[Alert]:
        """패킷을 모든 엔진에 분배한다. 알림 목록을 반환한다."""
        alerts: list[Alert] = []
        for engine in self._engines:
            if not engine.enabled:
                continue
            try:
                start = time.monotonic()
                alert = engine.analyze(packet)
                elapsed = time.monotonic() - start

                # Prometheus 메트릭
                if _engine_analyze_duration is not None:
                    _engine_analyze_duration.labels(engine=engine.name).observe(elapsed)

                if alert is not None:
                    # 신뢰도 기반 심각도 조정 적용
                    if alert.confidence < 0.3:
                        alert.severity = downgrade_severity(alert.severity)
                    alerts.append(alert)
            except Exception:
                logger.exception("Engine %s raised exception", engine.name)
        return alerts

    def tick(self) -> list[Alert]:
        """tick_interval을 준수하며 엔진의 on_tick을 호출한다."""
        now = time.time()
        alerts: list[Alert] = []
        for engine in self._engines:
            if not engine.enabled:
                continue
            # 마지막 틱 이후 충분한 시간이 경과했는지 확인
            last = self._last_tick.get(engine.name, 0.0)
            if now - last < engine.tick_interval:
                continue
            self._last_tick[engine.name] = now
            try:
                engine_alerts = engine.on_tick(now)
                for alert in engine_alerts:
                    # 신뢰도 기반 심각도 조정 적용
                    if alert.confidence < 0.3:
                        alert.severity = downgrade_severity(alert.severity)
                alerts.extend(engine_alerts)
            except Exception:
                logger.exception("Engine %s on_tick raised exception", engine.name)
        return alerts

    def shutdown(self) -> None:
        """모든 엔진의 shutdown() 호출."""
        for engine in self._engines:
            try:
                engine.shutdown()
            except Exception:
                logger.exception("Engine %s shutdown failed", engine.name)

    # ------------------------------------------------------------------
    # 엔진 정보 조회
    # ------------------------------------------------------------------

    def get_engine_info(self, name: str) -> dict[str, Any] | None:
        """단일 엔진의 상세 정보를 반환한다.

        Args:
            name: 엔진 이름.

        Returns:
            엔진 정보 dict (name, enabled, config, schema) 또는
            _engine_classes에 없는 이름이면 None.
        """
        if name not in self._engine_classes:
            return None

        engine_cls = self._engine_classes[name]

        # 활성 엔진 탐색
        active = self._find_active(name)
        if active is not None:
            return {
                "name":          name,
                "description":   engine_cls.description,
                "enabled":       True,
                "requires_span": getattr(engine_cls, "requires_span", False),
                "config":        dict(active.config),
                "schema":        schema_to_api(engine_cls.config_schema),
            }

        # 비활성 엔진: YAML 설정에서 config 가져오기
        yaml_config = self._config.get(f"engines.{name}", {})
        if not isinstance(yaml_config, dict):
            yaml_config = {}
        return {
            "name":          name,
            "description":   engine_cls.description,
            "enabled":       False,
            "requires_span": getattr(engine_cls, "requires_span", False),
            "config":        dict(yaml_config),
            "schema":        schema_to_api(engine_cls.config_schema),
        }

    def get_all_engine_info(self) -> list[dict[str, Any]]:
        """모든 엔진(활성 + 비활성)의 정보를 반환한다.

        활성 엔진이 먼저, 비활성 엔진이 뒤에 오도록 정렬한다.
        """
        active_names = {e.name for e in self._engines}
        active_infos:   list[dict[str, Any]] = []
        inactive_infos: list[dict[str, Any]] = []

        for name in self._engine_classes:
            info = self.get_engine_info(name)
            if info is None:
                continue
            if name in active_names:
                active_infos.append(info)
            else:
                inactive_infos.append(info)

        return active_infos + inactive_infos

    # ------------------------------------------------------------------
    # 런타임 엔진 관리 (핫리로드 / 활성화 / 비활성화)
    # ------------------------------------------------------------------

    def reload_engine(
        self, name: str, new_config: dict[str, Any],
    ) -> tuple[bool, str | None, list[str]]:
        """엔진을 새 설정으로 핫리로드한다.

        기존 인스턴스가 있으면 shutdown 후 동일 인덱스에 교체하고,
        없으면 새로 추가한다.

        Args:
            name: 엔진 이름.
            new_config: 새 설정 dict.

        Returns:
            (True, None, warnings) 성공 시,
            (False, 에러 메시지, []) 실패 시.
        """
        if name not in self._engine_classes:
            return False, f"Unknown engine: {name}", []

        engine_cls = self._engine_classes[name]

        # 새 인스턴스 생성 시도
        try:
            new_engine = engine_cls(new_config)
            warnings = new_engine.validate_config()
            for w in warnings:
                logger.warning("Config validation (%s): %s", name, w)
            if self._whitelist is not None:
                new_engine.set_whitelist(self._whitelist)
        except Exception as exc:
            return False, f"Failed to instantiate engine {name}: {exc}", []

        # 기존 활성 인스턴스 교체 또는 추가
        idx = self._find_active_index(name)
        if idx is not None:
            old_engine = self._engines[idx]
            try:
                old_engine.shutdown()
            except Exception:
                logger.exception("Engine %s shutdown failed during reload", name)
            self._engines[idx] = new_engine
        else:
            self._engines.append(new_engine)

        self._last_tick[name] = 0.0
        logger.info("Reloaded engine: %s", new_engine)
        return True, None, warnings

    def disable_engine(self, name: str) -> tuple[bool, str | None, list[str]]:
        """엔진을 비활성화(shutdown + 제거)한다.

        이미 비활성인 경우에도 성공을 반환한다 (멱등성).

        Args:
            name: 엔진 이름.

        Returns:
            (True, None, []) 성공 시, (False, 에러 메시지, []) 실패 시.
        """
        if name not in self._engine_classes:
            return False, f"Unknown engine: {name}", []

        idx = self._find_active_index(name)
        if idx is None:
            # 이미 비활성 상태 — 멱등
            return True, None, []

        engine = self._engines[idx]
        try:
            engine.shutdown()
        except Exception:
            logger.exception("Engine %s shutdown failed during disable", name)

        del self._engines[idx]
        self._last_tick.pop(name, None)
        logger.info("Disabled engine: %s", name)
        return True, None, []

    def enable_engine(
        self, name: str, config: dict[str, Any],
    ) -> tuple[bool, str | None, list[str]]:
        """엔진을 활성화한다. 이미 활성 상태이면 새 설정으로 리로드한다.

        Args:
            name: 엔진 이름.
            config: 엔진 설정 dict.

        Returns:
            (True, None, warnings) 성공 시,
            (False, 에러 메시지, []) 실패 시.
        """
        if name not in self._engine_classes:
            return False, f"Unknown engine: {name}", []

        return self.reload_engine(name, config)

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _find_active(self, name: str) -> DetectionEngine | None:
        """활성 엔진 리스트에서 이름으로 인스턴스를 찾는다."""
        for engine in self._engines:
            if engine.name == name:
                return engine
        return None

    def _find_active_index(self, name: str) -> int | None:
        """활성 엔진 리스트에서 이름으로 인덱스를 찾는다."""
        for i, engine in enumerate(self._engines):
            if engine.name == name:
                return i
        return None

    @property
    def engines(self) -> list[DetectionEngine]:
        """등록된 활성 엔진 목록의 사본을 반환한다."""
        return list(self._engines)

    @property
    def whitelist(self) -> Whitelist | None:
        """글로벌 화이트리스트 인스턴스를 반환한다."""
        return self._whitelist
