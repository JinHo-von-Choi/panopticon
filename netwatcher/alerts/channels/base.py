"""알림 채널 추상 기반 클래스."""

from __future__ import annotations

import abc
from typing import Any

from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.i18n import i18n


class NotificationChannel(abc.ABC):
    """알림 채널 기반 클래스 (Telegram, Slack, Discord)."""

    name: str = ""

    def __init__(self, config: dict[str, Any]) -> None:
        """채널 설정과 최소 심각도 필터를 초기화한다."""
        self.config = config
        self.enabled = config.get("enabled", False)
        min_sev = config.get("min_severity", "WARNING")
        self.min_severity = Severity(min_sev)
        # 채널별 언어 설정 (없으면 i18n 기본값 사용)
        self.language = config.get("language")

    def should_send(self, alert: Alert) -> bool:
        """알림이 이 채널의 최소 심각도를 충족하는지 확인한다."""
        return self.enabled and alert.severity >= self.min_severity

    @abc.abstractmethod
    async def send(self, alert: Alert) -> bool:
        """알림을 전송한다. 성공 시 True를 반환한다."""

    def _get_translated_texts(self, alert: Alert) -> tuple[str, str]:
        """알림의 제목과 설명을 채널 언어 설정에 맞춰 번역하여 반환한다."""
        title = alert.title
        if alert.title_key:
            title = i18n.translate(
                alert.title_key, 
                lang=self.language, 
                **alert.metadata
            )
            
        description = alert.description
        if alert.description_key:
            context = alert.metadata.copy()
            context.update({
                "source_ip": alert.source_ip or "-",
                "source_mac": alert.source_mac or "-",
                "dest_ip": alert.dest_ip or "-",
                "dest_mac": alert.dest_mac or "-"
            })
            description = i18n.translate(
                alert.description_key, 
                lang=self.language, 
                **context
            )
        return title, description

    def _format_message(self, alert: Alert) -> str:
        """알림을 읽기 쉬운 메시지로 포맷팅한다."""
        icon = {"CRITICAL": "\u26a0\ufe0f", "WARNING": "\u26a0", "INFO": "\u2139\ufe0f"}.get(
            alert.severity.value, ""
        )
        
        title, description = self._get_translated_texts(alert)

        lines = [
            f"{icon} **[{alert.severity.value}] {title}**",
            "",
            description,
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
