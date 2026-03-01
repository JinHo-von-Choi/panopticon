"""webhook을 통한 Discord 알림 채널."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from netwatcher.alerts.channels.base import NotificationChannel
from netwatcher.detection.models import Alert
from netwatcher.utils.network import validate_outbound_url

logger = logging.getLogger("netwatcher.alerts.channels.discord")


class DiscordChannel(NotificationChannel):
    name = "discord"

    def __init__(self, config: dict[str, Any]) -> None:
        """Discord webhook URL을 설정에서 로드한다."""
        super().__init__(config)
        raw_url = config.get("webhook_url", "")
        self._webhook_url = validate_outbound_url(raw_url) or "" if raw_url else ""
        if raw_url and not self._webhook_url:
            logger.error("Discord webhook URL이 내부 주소를 대상으로 하여 차단됨: %s", raw_url)

    async def send(self, alert: Alert) -> bool:
        """Discord Webhook으로 알림 embed를 전송한다."""
        if not self._webhook_url:
            logger.warning("Discord not configured (missing webhook_url)")
            return False

        title, description = self._get_translated_texts(alert)
        color_map = {
            "CRITICAL": 0xFF0000,
            "WARNING": 0xFFA500,
            "INFO": 0x36A2EB,
        }
        color = color_map.get(alert.severity.value, 0x808080)

        payload = {
            "embeds": [
                {
                    "title": f"[{alert.severity.value}] {title}",
                    "description": description,
                    "color": color,
                    "fields": [
                        {"name": "Engine", "value": alert.engine, "inline": True},
                        {"name": "Source IP", "value": alert.source_ip or "N/A", "inline": True},
                        {"name": "Source MAC", "value": alert.source_mac or "N/A", "inline": True},
                        {"name": "Dest IP", "value": alert.dest_ip or "N/A", "inline": True},
                    ],
                    "timestamp": alert.timestamp,
                }
            ]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._webhook_url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 204):
                        logger.debug("Discord alert sent: %s", alert.title)
                        return True
                    else:
                        body = await resp.text()
                        logger.error("Discord webhook error %d: %s", resp.status, body)
                        return False
        except Exception:
            logger.exception("Failed to send Discord alert")
            return False
