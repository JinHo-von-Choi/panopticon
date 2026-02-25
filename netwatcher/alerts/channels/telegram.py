"""Telegram 알림 채널."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from netwatcher.alerts.channels.base import NotificationChannel
from netwatcher.detection.models import Alert

logger = logging.getLogger("netwatcher.alerts.channels.telegram")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


class TelegramChannel(NotificationChannel):
    name = "telegram"

    def __init__(self, config: dict[str, Any]) -> None:
        """봇 토큰과 채팅 ID를 설정에서 로드한다."""
        super().__init__(config)
        self._token = config.get("bot_token", "")
        self._chat_id = config.get("chat_id", "")

    async def send(self, alert: Alert) -> bool:
        """Telegram Bot API를 통해 알림 메시지를 전송한다."""
        if not self._token or not self._chat_id:
            logger.warning("Telegram not configured (missing bot_token or chat_id)")
            return False

        url = TELEGRAM_API.format(token=self._token)
        text = self._format_message(alert)
        # Telegram은 HTML 또는 Markdown parse_mode를 사용
        text = text.replace("**", "*")  # Markdown 볼드
        text = text.replace("`", "`")

        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        logger.debug("Telegram alert sent: %s", alert.title)
                        return True
                    else:
                        body = await resp.text()
                        logger.error("Telegram API error %d: %s", resp.status, body)
                        return False
        except Exception:
            logger.exception("Failed to send Telegram alert")
            return False
