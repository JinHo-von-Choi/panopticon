"""Tests for DailyReporter: data collection, formatting helpers, multi-channel dispatch."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netwatcher.alerts.daily_report import DailyReporter, _ReportData, _format_bytes


# ---------------------------------------------------------------------------
# _format_bytes
# ---------------------------------------------------------------------------

class TestFormatBytes:
    def test_bytes(self):
        assert _format_bytes(512)       == "512 B"

    def test_kilobytes(self):
        assert _format_bytes(2048)      == "2.0 KB"

    def test_megabytes(self):
        assert _format_bytes(5_242_880) == "5.0 MB"

    def test_gigabytes(self):
        assert _format_bytes(2_147_483_648) == "2.00 GB"

    def test_zero(self):
        assert _format_bytes(0) == "0 B"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(
    slack_enabled: bool = False,
    slack_url: str = "",
    tg_enabled: bool = False,
    discord_enabled: bool = False,
    discord_url: str = "",
    report_hour: int = 8,
) -> MagicMock:
    """테스트용 Config 모의 객체를 생성한다."""
    cfg = MagicMock()
    cfg.section.side_effect = lambda key: {
        "daily_report": {"enabled": True, "report_hour": report_hour},
        "alerts": {
            "channels": {
                "slack": {
                    "enabled":      slack_enabled,
                    "webhook_url":  slack_url,
                    "dashboard_url":"",
                },
                "telegram": {
                    "enabled":  tg_enabled,
                    "bot_token":"fake-token",
                    "chat_id":  "12345",
                },
                "discord": {
                    "enabled":     discord_enabled,
                    "webhook_url": discord_url,
                },
            },
        },
    }.get(key, {})
    return cfg


def _make_reporter(**kw) -> DailyReporter:
    """repo mock을 주입한 DailyReporter를 반환한다."""
    config      = kw.pop("config", _make_config())
    event_repo  = kw.pop("event_repo",  MagicMock())
    device_repo = kw.pop("device_repo", MagicMock())
    stats_repo  = kw.pop("stats_repo",  MagicMock())
    # validate_outbound_url은 모듈 레벨에서 임포트되므로 daily_report 모듈 네임스페이스에서 패치
    with patch("netwatcher.alerts.daily_report.validate_outbound_url", side_effect=lambda url: url):
        return DailyReporter(
            config=config,
            event_repo=event_repo,
            device_repo=device_repo,
            stats_repo=stats_repo,
        )


def _make_report_data(**kw) -> _ReportData:
    """기본값이 채워진 _ReportData를 반환한다."""
    defaults = dict(
        period          = "02/25 12:00 ~ 02/26 12:00 KST",
        total_events    = 10,
        critical        = 2,
        warning         = 5,
        info            = 3,
        eng_counts      = {"arp_spoof": 2, "port_scan": 8},
        top_sources     = [{"ip": "192.168.1.100", "count": 5}],
        traffic         = {
            "total_packets": 50000,
            "total_bytes":   10_485_760,
            "tcp_count":     30000,
            "udp_count":     15000,
            "arp_count":     2000,
            "dns_count":     3000,
        },
        total_devices   = 15,
        new_today       = 2,
        known_devices   = 10,
        unknown_devices = 5,
        high_risk_count = 3,
        top_risk_devs   = [
            {"mac": "aa:bb:cc:dd:ee:01", "label": "router",    "score": 80},
            {"mac": "aa:bb:cc:dd:ee:02", "label": "unknown-01","score": 65},
        ],
        dashboard_url   = "https://panopticon.example.com",
    )
    defaults.update(kw)
    return _ReportData(**defaults)


# ---------------------------------------------------------------------------
# Channel selection logic
# ---------------------------------------------------------------------------

class TestChannelSelection:
    def test_slack_url_extracted(self):
        cfg      = _make_config(slack_enabled=True, slack_url="https://hooks.slack.com/test")
        reporter = _make_reporter(config=cfg)
        assert reporter._slack_url == "https://hooks.slack.com/test"

    def test_slack_disabled_url_ignored(self):
        cfg      = _make_config(slack_enabled=False, slack_url="https://hooks.slack.com/test")
        reporter = _make_reporter(config=cfg)
        assert reporter._slack_url == ""

    def test_telegram_enabled(self):
        cfg      = _make_config(tg_enabled=True)
        reporter = _make_reporter(config=cfg)
        assert reporter._tg_token   == "fake-token"
        assert reporter._tg_chat_id == "12345"

    def test_telegram_disabled(self):
        cfg      = _make_config(tg_enabled=False)
        reporter = _make_reporter(config=cfg)
        assert reporter._tg_token   == ""
        assert reporter._tg_chat_id == ""


# ---------------------------------------------------------------------------
# _collect_data — mock repos
# ---------------------------------------------------------------------------

class TestCollectData:
    @pytest.fixture
    def reporter(self):
        event_repo  = MagicMock()
        device_repo = MagicMock()
        stats_repo  = MagicMock()

        event_repo.count_by_severity_since = AsyncMock(return_value={"CRITICAL": 1, "WARNING": 2, "INFO": 3})
        event_repo.count_by_engine_since   = AsyncMock(return_value={"arp_spoof": 1})
        event_repo.top_sources_since       = AsyncMock(return_value=[{"ip": "10.0.0.1", "count": 2}])
        device_repo.inventory_summary      = AsyncMock(return_value={
            "total": 5, "known": 3, "unknown": 2, "new_today": 1, "by_type": {},
        })
        device_repo.list_all               = AsyncMock(return_value=[
            {
                "mac_address": "aa:bb:cc:dd:ee:01",
                "is_known":    False,
                "device_type": "unknown",
                "hostname":    "",
                "open_ports":  [23],
                "first_seen":  (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            },
        ])
        stats_repo.summary_since = AsyncMock(return_value={
            "total_packets": 1000, "total_bytes": 2048,
            "tcp_count": 500, "udp_count": 400, "arp_count": 50, "dns_count": 50,
        })

        with patch("netwatcher.alerts.daily_report.validate_outbound_url", side_effect=lambda u: u):
            r = DailyReporter(
                config      = _make_config(),
                event_repo  = event_repo,
                device_repo = device_repo,
                stats_repo  = stats_repo,
            )
        return r

    @pytest.mark.asyncio
    async def test_total_events(self, reporter):
        data = await reporter._collect_data()
        assert data.total_events == 6    # 1+2+3

    @pytest.mark.asyncio
    async def test_critical_count(self, reporter):
        data = await reporter._collect_data()
        assert data.critical == 1

    @pytest.mark.asyncio
    async def test_device_totals(self, reporter):
        data = await reporter._collect_data()
        assert data.total_devices   == 5
        assert data.known_devices   == 3
        assert data.unknown_devices == 2
        assert data.new_today       == 1

    @pytest.mark.asyncio
    async def test_high_risk_detected(self, reporter):
        """미등록 + 타입불명 + 호스트명없음 + Telnet포트 + 신규 기기는 high로 분류된다."""
        data = await reporter._collect_data()
        assert data.high_risk_count >= 1

    @pytest.mark.asyncio
    async def test_top_risk_devs_sorted_by_score(self, reporter):
        data = await reporter._collect_data()
        scores = [d["score"] for d in data.top_risk_devs]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# _send_report — channel dispatch
# ---------------------------------------------------------------------------

class TestSendReport:
    @pytest.mark.asyncio
    async def test_no_channels_skips(self):
        """활성 채널이 없으면 전송을 건너뛰고 예외를 발생시키지 않는다."""
        reporter = _make_reporter()
        reporter._collect_data = AsyncMock(return_value=_make_report_data())
        # 모든 채널 비활성
        reporter._slack_url   = ""
        reporter._tg_token    = ""
        reporter._discord_url = ""
        await reporter._send_report()  # exception이 발생하지 않아야 한다

    @pytest.mark.asyncio
    async def test_slack_only_called(self):
        reporter = _make_reporter()
        reporter._collect_data = AsyncMock(return_value=_make_report_data())
        reporter._slack_url    = "https://hooks.slack.com/test"
        reporter._tg_token     = ""
        reporter._discord_url  = ""

        reporter._send_slack    = AsyncMock()
        reporter._send_telegram = AsyncMock()
        reporter._send_discord  = AsyncMock()

        await reporter._send_report()
        reporter._send_slack.assert_called_once()
        reporter._send_telegram.assert_not_called()
        reporter._send_discord.assert_not_called()

    @pytest.mark.asyncio
    async def test_all_channels_called(self):
        reporter = _make_reporter()
        reporter._collect_data = AsyncMock(return_value=_make_report_data())
        reporter._slack_url    = "https://hooks.slack.com/test"
        reporter._tg_token     = "tok"
        reporter._tg_chat_id   = "123"
        reporter._discord_url  = "https://discord.com/api/webhooks/test"

        reporter._send_slack    = AsyncMock()
        reporter._send_telegram = AsyncMock()
        reporter._send_discord  = AsyncMock()

        await reporter._send_report()
        reporter._send_slack.assert_called_once()
        reporter._send_telegram.assert_called_once()
        reporter._send_discord.assert_called_once()

    @pytest.mark.asyncio
    async def test_channel_failure_does_not_abort_others(self):
        """채널 하나가 예외를 발생시켜도 다른 채널은 계속 전송한다."""
        reporter = _make_reporter()
        reporter._collect_data = AsyncMock(return_value=_make_report_data())
        reporter._slack_url    = "https://hooks.slack.com/test"
        reporter._tg_token     = "tok"
        reporter._tg_chat_id   = "123"
        reporter._discord_url  = ""

        reporter._send_slack    = AsyncMock(side_effect=RuntimeError("slack down"))
        reporter._send_telegram = AsyncMock()

        await reporter._send_report()  # 예외가 전파되지 않아야 한다
        reporter._send_telegram.assert_called_once()


# ---------------------------------------------------------------------------
# start / stop lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_creates_task(self):
        reporter = _make_reporter()
        await reporter.start()
        assert reporter._task is not None
        reporter._task.cancel()
        try:
            await reporter._task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self):
        reporter = _make_reporter()
        await reporter.start()
        await reporter.stop()
        assert reporter._task.cancelled() or reporter._task.done()
