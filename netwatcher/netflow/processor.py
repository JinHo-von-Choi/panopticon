"""FlowProcessor — FlowRecord를 FlowEngine들에 디스패치하는 서비스."""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import TYPE_CHECKING

from netwatcher.netflow.base import FlowEngine
from netwatcher.netflow.models import FlowRecord

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher

logger = logging.getLogger("netwatcher.netflow.processor")


class FlowProcessor:
    """수신된 FlowRecord 리스트를 등록된 FlowEngine들에 분배한다."""

    def __init__(self, dispatcher: "AlertDispatcher | None" = None) -> None:
        self._dispatcher = dispatcher
        self._engines:    list[FlowEngine] = []
        self._total_flows = 0
        self._engine_classes: dict[str, type[FlowEngine]] = {}
        self._configs: dict[str, dict] = {}

    def register_engine(self, engine: FlowEngine) -> None:
        """FlowEngine 인스턴스를 등록한다."""
        self._engines.append(engine)
        self._engine_classes[engine.name] = type(engine)
        self._configs[engine.name] = deepcopy(engine.config)
        logger.info("Registered FlowEngine: %s", engine)

    def configure_engine(self, engine_class: type[FlowEngine], config: dict) -> None:
        """비활성 엔진도 등록해 이후 승인된 변경으로 활성화할 수 있게 한다."""
        name = engine_class.name
        if name in self._engine_classes:
            raise ValueError(f"Duplicate flow engine: {name}")
        from netwatcher.detection.schema_utils import normalize_schema
        defaults = {key: field["default"] for key, field in normalize_schema(engine_class.config_schema).items()}
        config = {**defaults, **config}
        self._engine_classes[name] = engine_class
        self._configs[name] = deepcopy(config)
        if config.get("enabled", True):
            self._engines.append(engine_class(deepcopy(config)))

    def get_engine_schema(self, name: str) -> dict | None:
        engine_class = self._engine_classes.get(name)
        return deepcopy(engine_class.config_schema) if engine_class else None

    def get_engine_info(self, name: str) -> dict | None:
        from netwatcher.detection.schema_utils import schema_to_api
        engine_class = self._engine_classes.get(name)
        if engine_class is None:
            return None
        active = next((engine for engine in self._engines if engine.name == name), None)
        return {"name": name, "description": engine_class.description,
                "description_key": getattr(engine_class, "description_key", None),
                "enabled": active is not None and active.enabled,
                "requires_span": False, "config": deepcopy(self._configs[name]),
                "schema": schema_to_api(engine_class.config_schema)}

    def get_all_engine_info(self) -> list[dict]:
        return [self.get_engine_info(name) for name in self._engine_classes]

    def reload_engine(self, name: str, config: dict) -> tuple[bool, str | None, list[str]]:
        if name not in self._engine_classes:
            return False, "Unknown flow engine", []
        from netwatcher.detection.validation import validate_engine_config
        if (validate_engine_config(self.get_engine_schema(name), config)
                or type(config.get("enabled", True)) is not bool):
            return False, "Invalid flow engine configuration", []
        try:
            replacement = self._engine_classes[name](deepcopy(config))
            previous = next((engine for engine in self._engines if engine.name == name), None)
            if previous is not None:
                previous.shutdown()
        except Exception:
            logger.exception("Flow engine replacement failed: %s", name)
            return False, "Flow engine replacement failed", []
        self._engines = [engine for engine in self._engines if engine.name != name]
        if replacement.enabled:
            self._engines.append(replacement)
        self._configs[name] = deepcopy(config)
        return True, None, []

    def disable_engine(self, name: str) -> tuple[bool, str | None, list[str]]:
        if name not in self._engine_classes:
            return False, "Unknown flow engine", []
        return self.reload_engine(name, {**self._configs[name], "enabled": False})

    def on_flows(self, flows: list[FlowRecord]) -> None:
        """플로우 리스트를 모든 활성 엔진에 분배하고 알림을 디스패처에 큐잉한다."""
        self._total_flows += len(flows)

        for flow in flows:
            for engine in self._engines:
                if not engine.enabled:
                    continue
                try:
                    alert = engine.analyze_flow(flow)
                    if alert is not None and self._dispatcher is not None:
                        self._dispatcher.enqueue(alert)
                except Exception:
                    logger.exception(
                        "FlowEngine %s raised exception on flow %s→%s",
                        engine.name, flow.src_ip, flow.dst_ip,
                    )

    def on_tick(self, timestamp: float) -> None:
        """등록된 모든 활성 FlowEngine의 on_tick을 호출하고 알림을 디스패처에 큐잉한다.

        TickService에서 1초 주기로 호출된다.
        """
        for engine in self._engines:
            if not engine.enabled:
                continue
            try:
                alerts = engine.on_tick(timestamp)
                for alert in alerts:
                    if self._dispatcher is not None:
                        self._dispatcher.enqueue(alert)
            except Exception:
                logger.exception(
                    "FlowEngine %s raised exception in on_tick", engine.name
                )

    @property
    def total_flows(self) -> int:
        """처리된 총 플로우 수."""
        return self._total_flows

    @property
    def engines(self) -> list[FlowEngine]:
        return list(self._engines)
