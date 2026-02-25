"""탐지 엔진의 추상 기본 클래스."""

from __future__ import annotations

import abc
from typing import Any

from scapy.all import Packet

from netwatcher.detection.models import Alert
from netwatcher.detection.whitelist import Whitelist


class DetectionEngine(abc.ABC):
    """모든 탐지 엔진이 상속해야 하는 기본 클래스."""

    # 서브클래스에서 반드시 설정해야 함
    name: str = ""
    description: str = ""

    # 기본 틱 간격(초) — 서브클래스에서 오버라이드 가능
    tick_interval: int = 1

    # True이면 SPAN/포트 미러링 없이는 탐지 효과가 크게 제한됨.
    # ARP·DHCP 브로드캐스트만으로 동작하는 엔진은 False(기본값)를 유지한다.
    requires_span: bool = False

    # 서브클래스에서 설정 스키마 정의: key -> (type, default) 튜플 또는 dict
    config_schema: dict[str, Any] = {}

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진별 설정(config)으로 인스턴스를 초기화한다."""
        self.config  = config
        self.enabled = config.get("enabled", True)
        self._whitelist: Whitelist | None = None
        # 엔진별 틱 간격 오버라이드 허용
        if "tick_interval" in config:
            self.tick_interval = config["tick_interval"]

    def set_whitelist(self, whitelist: Whitelist) -> None:
        """글로벌 화이트리스트를 주입한다."""
        self._whitelist = whitelist

    def is_whitelisted(self, **kwargs: Any) -> bool:
        """식별자가 화이트리스트에 등록되어 있는지 확인한다."""
        if self._whitelist is None:
            return False
        return self._whitelist.is_whitelisted(**kwargs)

    def validate_config(self) -> list[str]:
        """config_schema에 대해 엔진 설정을 검증한다.

        잘못된 설정 값에 대한 경고 메시지 목록을 반환한다.
        tuple (type, default)과 dict {"type", "default", ...} 형식을 모두 지원한다.
        타입, min, max 제약 조건을 검증한다.
        """
        warnings: list[str] = []
        for key, spec in self.config_schema.items():
            min_val = None
            max_val = None
            if isinstance(spec, dict):
                expected_type = spec.get("type", str)
                default       = spec.get("default")
                min_val       = spec.get("min")
                max_val       = spec.get("max")
            else:
                expected_type, default = spec

            val = self.config.get(key, default)
            if val is None:
                continue

            # 타입 검사
            if not isinstance(val, expected_type):
                # float 기대 위치에 int 허용
                if expected_type is float and isinstance(val, int):
                    pass  # 범위 검사로 이동
                else:
                    warnings.append(
                        f"{self.name}.{key}: expected {expected_type.__name__}, "
                        f"got {type(val).__name__} (value={val!r})"
                    )
                    continue

            # 범위 검사 (숫자 타입만 해당)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                if min_val is not None and val < min_val:
                    warnings.append(
                        f"{self.name}.{key}: value {val!r} is below minimum {min_val}"
                    )
                if max_val is not None and val > max_val:
                    warnings.append(
                        f"{self.name}.{key}: value {val!r} is above maximum {max_val}"
                    )
        return warnings

    @abc.abstractmethod
    def analyze(self, packet: Packet) -> Alert | None:
        """단일 패킷을 분석한다. 1ms 이내에 완료되어야 한다.

        의심스러운 활동이 탐지되면 Alert를 반환하고, 그렇지 않으면 None을 반환한다.
        """

    def on_tick(self, timestamp: float) -> list[Alert]:
        """시간 윈도우 기반 탐지를 위해 주기적으로 호출된다 (약 1초마다).

        주기적 분석이 필요한 서브클래스에서 오버라이드한다.
        알림 목록을 반환한다 (비어 있을 수 있음).
        """
        return []

    def shutdown(self) -> None:
        """엔진 종료 시 리소스 해제. 서브클래스에서 오버라이드."""
        pass

    def __repr__(self) -> str:
        """엔진의 문자열 표현을 반환한다."""
        return f"<{self.__class__.__name__} name={self.name!r} enabled={self.enabled}>"
