"""탐지 엔진용 Alert 및 Severity 모델."""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Severity(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

    def __ge__(self, other: Severity) -> bool:
        """현재 심각도가 other 이상인지 비교한다."""
        order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
        return order[self] >= order[other]

    def __gt__(self, other: Severity) -> bool:
        """현재 심각도가 other 초과인지 비교한다."""
        order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
        return order[self] > order[other]

    def __le__(self, other: Severity) -> bool:
        """현재 심각도가 other 이하인지 비교한다."""
        order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
        return order[self] <= order[other]

    def __lt__(self, other: Severity) -> bool:
        """현재 심각도가 other 미만인지 비교한다."""
        order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
        return order[self] < order[other]


# 심각도 다운그레이드 로직용 순서
_SEVERITY_ORDER = [Severity.INFO, Severity.WARNING, Severity.CRITICAL]


def downgrade_severity(severity: Severity) -> Severity:
    """심각도를 한 단계 낮춘다 (CRITICAL -> WARNING -> INFO)."""
    idx = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[max(0, idx - 1)]


@dataclass
class Alert:
    """탐지 엔진이 생성한 알림."""
    engine: str
    severity: Severity
    title: str
    description: str = ""
    source_ip: str | None = None
    source_mac: str | None = None
    dest_ip: str | None = None
    dest_mac: str | None = None
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)
    packet_info: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    )

    def __post_init__(self) -> None:
        """하위 호환성을 위해 metadata의 confidence를 인스턴스 필드로 추출한다."""
        # 하위 호환성을 위해 metadata에 설정된 confidence 추출
        if "confidence" in self.metadata and self.confidence == 0.5:
            self.confidence = self.metadata["confidence"]

    @property
    def rate_limit_key(self) -> str:
        """중복 제거 / 속도 제한에 사용되는 키."""
        return f"{self.engine}:{self.title}:{self.source_ip or self.source_mac or ''}"

    def to_dict(self) -> dict[str, Any]:
        """알림을 딕셔너리로 직렬화한다."""
        return {
            "engine": self.engine,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "dest_ip": self.dest_ip,
            "dest_mac": self.dest_mac,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "packet_info": self.packet_info,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """알림을 JSON 문자열로 직렬화한다."""
        return json.dumps(self.to_dict())
