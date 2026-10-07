"""기동 시 검증한 채널과 비밀값 없는 상태 목록."""

import logging

from netwatcher.alerts.channels.discord import DiscordChannel
from netwatcher.alerts.channels.slack import SlackChannel
from netwatcher.alerts.channels.telegram import TelegramChannel

logger = logging.getLogger(__name__)


def build_channels(configs):
    channels, status = [], {}
    for name, cls in (("telegram", TelegramChannel), ("slack", SlackChannel), ("discord", DiscordChannel)):
        cfg = configs.get(name, {})
        reason = "disabled_by_config"
        if cfg.get("enabled", False):
            required = ("bot_token", "chat_id") if name == "telegram" else ("webhook_url",)
            if any(not str(cfg.get(key) or "").strip() for key in required):
                reason = "missing_configuration"
            else:
                try:
                    channel = cls(cfg)
                    if name != "telegram" and not channel._webhook_url:
                        reason = "invalid_destination"
                    else:
                        channels.append(channel)
                        status[name] = {"status": "enabled", "disabled_reason": None}
                        continue
                except (ValueError, TypeError):
                    reason = "invalid_configuration"
            logger.warning("Notification channel disabled: %s reason=%s", name, reason)
        status[name] = {"status": "disabled", "disabled_reason": reason}
    return channels, status
