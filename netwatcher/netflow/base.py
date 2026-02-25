"""플로우 기반 탐지 엔진의 추상 기본 클래스."""

from __future__ import annotations

import abc
from typing import Any

from netwatcher.detection.models import Alert
from netwatcher.netflow.models import FlowRecord


class FlowEngine(abc.ABC):
    """FlowRecord를 입력으로 받는 탐지 엔진의 기본 클래스.

    DetectionEngine(패킷 기반)과 완전히 병렬 구조이며,
    동일한 AlertDispatcher로 Alert를 전달한다.
    """

    name:        str = ""
    description: str = ""

    # SPAN/포트 미러링 없이도 동작한다 (NetFlow는 라우터에서 수집).
    requires_span: bool = False

    config_schema: dict[str, Any] = {}

    def __init__(self, config: dict[str, Any]) -> None:
        self.config  = config
        self.enabled = config.get("enabled", True)

    @abc.abstractmethod
    def analyze_flow(self, flow: FlowRecord) -> Alert | None:
        """단일 FlowRecord를 분석한다.

        의심스러운 활동이 탐지되면 Alert를 반환하고, 그렇지 않으면 None을 반환한다.
        on_tick 패턴이 필요한 엔진은 이 메서드 내부에서 상태를 축적하고
        별도의 on_tick을 오버라이드한다.
        """

    def on_tick(self, timestamp: float) -> list[Alert]:
        """시간 윈도우 기반 탐지를 위해 주기적으로 호출된다.

        필요한 서브클래스에서 오버라이드한다.
        """
        return []

    def shutdown(self) -> None:
        """엔진 종료 시 리소스 해제."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} enabled={self.enabled}>"
