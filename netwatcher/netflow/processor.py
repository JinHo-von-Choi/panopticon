"""FlowProcessor — FlowRecord를 FlowEngine들에 디스패치하는 서비스."""

from __future__ import annotations

import logging
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

    def register_engine(self, engine: FlowEngine) -> None:
        """FlowEngine 인스턴스를 등록한다."""
        self._engines.append(engine)
        logger.info("Registered FlowEngine: %s", engine)

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

    @property
    def total_flows(self) -> int:
        """처리된 총 플로우 수."""
        return self._total_flows

    @property
    def engines(self) -> list[FlowEngine]:
        return list(self._engines)
