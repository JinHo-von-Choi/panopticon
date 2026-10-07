"""미설정 채널의 경보 폭풍과 보고서 연결 회귀 검사."""
from unittest.mock import AsyncMock, patch

import pytest

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.alerts.daily_report import DailyReporter
from netwatcher.alerts.channels.registry import build_channels
from netwatcher.alerts.channels.discord import DiscordChannel
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.config import Config


@pytest.mark.asyncio
async def test_missing_discord_warns_once_for_ten_thousand_alerts(caplog):
    cfg = Config({'alerts': {'channels': {'discord': {'enabled': True}}}})
    dispatcher = AlertDispatcher(cfg, AsyncMock())
    alert = Alert(engine='test', severity=Severity.CRITICAL, title='burst', description='test')
    for _ in range(10000):
        await dispatcher._send_webhooks(alert)
    reporter = DailyReporter(cfg, AsyncMock(), AsyncMock(), AsyncMock(), channels=dispatcher._channels)
    assert not reporter._discord_url
    assert dispatcher.channel_status['discord']['disabled_reason'] == 'missing_configuration'
    assert sum('Notification channel disabled: discord' in r.message for r in caplog.records) == 1


def test_invalid_severity_is_disabled_and_secret_url_is_not_logged(caplog):
    secret = 'https://127.0.0.1/private-secret'
    channels, status = build_channels({'discord': {'enabled': True, 'webhook_url': secret},
        'slack': {'enabled': True, 'webhook_url': 'https://hooks.slack.com/test', 'min_severity': 'WRONG'}})
    assert channels == []
    assert status['discord']['disabled_reason'] == 'invalid_destination'
    assert status['slack']['disabled_reason'] == 'invalid_configuration'
    assert 'private-secret' not in caplog.text


@pytest.mark.asyncio
async def test_failed_delivery_logs_status_without_echoing_response_or_exception(caplog):
    channel = DiscordChannel({'enabled': True, 'webhook_url': 'https://discord.com/api/webhooks/test'})
    alert = Alert(engine='test', severity=Severity.CRITICAL, title='test', description='test')
    with patch('netwatcher.alerts.channels.discord.aiohttp.ClientSession', side_effect=RuntimeError('secret-token')):
        assert await channel.send(alert) is False
    assert 'RuntimeError' in caplog.text
    assert 'secret-token' not in caplog.text


def test_daily_report_uses_only_shared_validated_channels():
    cfg = Config({'alerts': {'channels': {'telegram': {'enabled': True, 'bot_token': 'test-token'}}}})
    channels, status = build_channels(cfg.section('alerts')['channels'])
    reporter = DailyReporter(cfg, AsyncMock(), AsyncMock(), AsyncMock(), channels=channels)
    assert not reporter._tg_token and not reporter._tg_chat_id
    assert status['telegram']['disabled_reason'] == 'missing_configuration'
