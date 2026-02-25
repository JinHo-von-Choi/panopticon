"""알림 채널 추상 기반 클래스."""

from __future__ import annotations

import abc
from typing import Any

from netwatcher.detection.models import Alert, Severity


class NotificationChannel(abc.ABC):
    """알림 채널 기반 클래스 (Telegram, Slack, Discord)."""

    name: str = ""

    def __init__(self, config: dict[str, Any]) -> None:
        """채널 설정과 최소 심각도 필터를 초기화한다."""
        self.config = config
        self.enabled = config.get("enabled", False)
        min_sev = config.get("min_severity", "WARNING")
        self.min_severity = Severity(min_sev)

    def should_send(self, alert: Alert) -> bool:
        """알림이 이 채널의 최소 심각도를 충족하는지 확인한다."""
        return self.enabled and alert.severity >= self.min_severity

    @abc.abstractmethod
    async def send(self, alert: Alert) -> bool:
        """알림을 전송한다. 성공 시 True를 반환한다."""

    def _format_message(self, alert: Alert) -> str:
        """알림을 읽기 쉬운 메시지로 포맷팅한다."""
        icon = {"CRITICAL": "\u26a0\ufe0f", "WARNING": "\u26a0", "INFO": "\u2139\ufe0f"}.get(
            alert.severity.value, ""
        )
        lines = [
            f"{icon} **[{alert.severity.value}] {alert.title}**",
            "",
            alert.description,
            "",
            f"Engine: `{alert.engine}`",
        ]
        if alert.source_ip:
            lines.append(f"Source IP: `{alert.source_ip}`")
        if alert.source_mac:
            lines.append(f"Source MAC: `{alert.source_mac}`")
        if alert.dest_ip:
            lines.append(f"Dest IP: `{alert.dest_ip}`")
        lines.append(f"Time: {alert.timestamp}")
        return "\n".join(lines)
