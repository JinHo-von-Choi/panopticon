"""일일 예약 보고서: 설정된 모든 채널(Slack/Telegram/Discord)에 자산+보안 현황 전송."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

import aiohttp

from netwatcher.inventory.risk_scorer import assess
from netwatcher.storage.repositories import (
    DeviceRepository,
    EventRepository,
    TrafficStatsRepository,
)
from netwatcher.utils.config import Config
from netwatcher.utils.network import validate_outbound_url

logger = logging.getLogger("netwatcher.alerts.daily_report")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

# 고위험 기기 최대 표시 수
_TOP_RISK_LIMIT = 5


def _format_bytes(b: int) -> str:
    """바이트 수를 사람이 읽기 쉬운 단위(B/KB/MB/GB)로 포맷팅한다."""
    if b < 1024:
        return f"{b} B"
    if b < 1048576:
        return f"{b / 1024:.1f} KB"
    if b < 1073741824:
        return f"{b / 1048576:.1f} MB"
    return f"{b / 1073741824:.2f} GB"


class _ReportData(NamedTuple):
    """보고서 데이터 집약체 — DB 조회 결과를 채널 포맷터에 전달한다."""

    period:          str
    total_events:    int
    critical:        int
    warning:         int
    info:            int
    eng_counts:      dict[str, int]
    top_sources:     list[dict]
    traffic:         dict[str, int]
    total_devices:   int
    new_today:       int
    known_devices:   int
    unknown_devices: int
    high_risk_count: int
    top_risk_devs:   list[dict]   # [{"mac", "label", "score"}, ...]
    dashboard_url:   str


class DailyReporter:
    """매일 지정 시각(KST)에 자산 현황 + 보안 통계를 활성화된 모든 채널로 전송한다."""

    def __init__(
        self,
        config: Config,
        event_repo: EventRepository,
        device_repo: DeviceRepository,
        stats_repo: TrafficStatsRepository,
    ) -> None:
        """설정과 리포지토리 의존성을 초기화한다."""
        self._event_repo  = event_repo
        self._device_repo = device_repo
        self._stats_repo  = stats_repo
        self._task: asyncio.Task | None = None

        daily_cfg         = config.section("daily_report") or {}
        self._report_hour = daily_cfg.get("report_hour", 12)

        channels_cfg  = config.section("alerts").get("channels", {})
        slack_cfg     = channels_cfg.get("slack",    {})
        tg_cfg        = channels_cfg.get("telegram", {})
        discord_cfg   = channels_cfg.get("discord",  {})

        # Slack
        self._slack_url     = (slack_cfg.get("webhook_url",  "") or "") if slack_cfg.get("enabled") else ""
        self._dashboard_url = (slack_cfg.get("dashboard_url","") or "")

        # Telegram
        self._tg_token   = (tg_cfg.get("bot_token", "") or "") if tg_cfg.get("enabled") else ""
        self._tg_chat_id = (tg_cfg.get("chat_id",   "") or "") if tg_cfg.get("enabled") else ""

        # Discord — SSRF 방지 URL 검증
        raw_discord       = (discord_cfg.get("webhook_url", "") or "") if discord_cfg.get("enabled") else ""
        self._discord_url = validate_outbound_url(raw_discord) or "" if raw_discord else ""

    # ── 생명주기 ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """일일 보고서 스케줄 루프를 백그라운드 태스크로 시작한다."""
        self._task = asyncio.create_task(self._schedule_loop())
        enabled = [
            ch for ch, flag in (
                ("Slack",    bool(self._slack_url)),
                ("Telegram", bool(self._tg_token and self._tg_chat_id)),
                ("Discord",  bool(self._discord_url)),
            ) if flag
        ]
        logger.info(
            "DailyReporter started (report_hour=%02d:00 KST, channels=%s)",
            self._report_hour, enabled or ["none"],
        )

    async def stop(self) -> None:
        """스케줄 루프를 취소하고 종료한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ── 스케줄 루프 ──────────────────────────────────────────────────────────

    async def _schedule_loop(self) -> None:
        """다음 보고 시간까지 대기, 보고서 전송, 반복."""
        KST = timezone(timedelta(hours=9))
        while True:
            now    = datetime.now(KST)
            target = now.replace(hour=self._report_hour, minute=0, second=0, microsecond=0)
            if now >= target:
                target += timedelta(days=1)
            wait_seconds = (target - now).total_seconds()
            logger.info(
                "Next daily report in %.0f seconds (%s)",
                wait_seconds, target.strftime("%Y-%m-%d %H:%M KST"),
            )
            await asyncio.sleep(wait_seconds)
            try:
                await self._send_report()
            except Exception:
                logger.exception("Failed to send daily report")

    # ── 데이터 수집 ──────────────────────────────────────────────────────────

    async def _collect_data(self) -> _ReportData:
        """모든 리포지토리에서 보고서 데이터를 수집한다."""
        KST = timezone(timedelta(hours=9))
        now      = datetime.now(KST)
        since_dt = now - timedelta(hours=24)
        since_str = since_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        period    = f"{since_dt.strftime('%m/%d %H:%M')} ~ {now.strftime('%m/%d %H:%M')} KST"

        # 이벤트 통계
        sev_counts   = await self._event_repo.count_by_severity_since(since_str)
        eng_counts   = await self._event_repo.count_by_engine_since(since_str)
        top_sources  = await self._event_repo.top_sources_since(since_str, limit=5)
        total_events = sum(sev_counts.values())

        # 트래픽 통계
        traffic = await self._stats_repo.summary_since(since_str)

        # 자산 통계 (inventory_summary: total/known/unknown/new_today)
        inv         = await self._device_repo.inventory_summary()
        all_devices = await self._device_repo.list_all()

        # 위험도 평가 — 고위험(high) 기기 추출
        high_risk_devs: list[dict] = []
        for dev in all_devices:
            ra = assess(dev)
            if ra.level == "high":
                label = (
                    dev.get("nickname")
                    or dev.get("hostname")
                    or str(dev.get("ip_address") or "")
                    or str(dev.get("mac_address"))
                )
                high_risk_devs.append({
                    "mac":   str(dev.get("mac_address")),
                    "label": label,
                    "score": ra.score,
                })
        high_risk_devs.sort(key=lambda x: x["score"], reverse=True)

        return _ReportData(
            period          = period,
            total_events    = total_events,
            critical        = sev_counts.get("CRITICAL", 0),
            warning         = sev_counts.get("WARNING",  0),
            info            = sev_counts.get("INFO",     0),
            eng_counts      = eng_counts,
            top_sources     = top_sources,
            traffic         = traffic,
            total_devices   = inv["total"],
            new_today       = inv["new_today"],
            known_devices   = inv["known"],
            unknown_devices = inv["unknown"],
            high_risk_count = len(high_risk_devs),
            top_risk_devs   = high_risk_devs[:_TOP_RISK_LIMIT],
            dashboard_url   = self._dashboard_url,
        )

    # ── 전송 ─────────────────────────────────────────────────────────────────

    async def _send_report(self) -> None:
        """보고서 데이터를 수집하고 활성화된 모든 채널에 병렬 전송한다."""
        data = await self._collect_data()

        tasks = []
        if self._slack_url:
            tasks.append(self._send_slack(data))
        if self._tg_token and self._tg_chat_id:
            tasks.append(self._send_telegram(data))
        if self._discord_url:
            tasks.append(self._send_discord(data))

        if not tasks:
            logger.warning("DailyReporter: no channels configured, skipping")
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for exc in results:
            if isinstance(exc, Exception):
                logger.exception("Daily report channel failed: %s", exc)

    async def _send_slack(self, d: _ReportData) -> None:
        """Slack Blocks 포맷으로 보고서를 전송한다."""
        status_emoji = "\U0001f534" if d.critical > 0 else "\U0001f7e2"
        risk_emoji   = "\u26a0\ufe0f" if d.high_risk_count > 0 else "\u2705"

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "\U0001f4ca NetWatcher Daily Report",
                    "emoji": True,
                },
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*{d.period}*"}],
            },
            {"type": "divider"},
            # 자산 현황
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"\U0001f4bb *Asset Inventory*\n"
                        f"\u2022 Total Devices: *{d.total_devices}* "
                        f"(+{d.new_today} new today)\n"
                        f"\u2022 Registered: *{d.known_devices}* | "
                        f"Unregistered: *{d.unknown_devices}*\n"
                        f"{risk_emoji} High Risk: *{d.high_risk_count}*"
                    ),
                },
            },
        ]

        # 고위험 기기 목록
        if d.top_risk_devs:
            risk_lines = [
                f"\u2022 `{dev['mac']}` {dev['label']} — score *{dev['score']}*"
                for dev in d.top_risk_devs
            ]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top High-Risk Devices*\n" + "\n".join(risk_lines),
                },
            })

        blocks.append({"type": "divider"})

        # 이벤트 요약
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{status_emoji} *Events (24h): {d.total_events}*\n"
                    f"\u2022 Critical: *{d.critical}* | "
                    f"Warning: *{d.warning}* | Info: *{d.info}*"
                ),
            },
        })

        # 엔진별 분류
        if d.eng_counts:
            eng_lines = [
                f"\u2022 `{eng}`: {cnt}"
                for eng, cnt in list(d.eng_counts.items())[:8]
            ]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Engine Breakdown*\n" + "\n".join(eng_lines),
                },
            })

        # 상위 출발지 IP
        if d.top_sources:
            src_lines = [
                f"\u2022 `{s['ip']}` ({s['count']} events)"
                for s in d.top_sources
            ]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Source IPs*\n" + "\n".join(src_lines),
                },
            })

        blocks.append({"type": "divider"})

        # 트래픽 통계
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"\U0001f4e1 *Traffic (24h)*\n"
                    f"\u2022 Packets: *{d.traffic.get('total_packets', 0):,}* | "
                    f"Volume: *{_format_bytes(d.traffic.get('total_bytes', 0))}*\n"
                    f"\u2022 TCP: {d.traffic.get('tcp_count', 0):,} | "
                    f"UDP: {d.traffic.get('udp_count', 0):,} | "
                    f"ARP: {d.traffic.get('arp_count', 0):,} | "
                    f"DNS: {d.traffic.get('dns_count', 0):,}"
                ),
            },
        })

        if d.dashboard_url:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{d.dashboard_url}|Dashboard \u2192>"},
                ],
            })

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self._slack_url,
                json={"blocks": blocks},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    logger.info(
                        "Daily report sent via Slack (%d events, %d devices, %d high-risk)",
                        d.total_events, d.total_devices, d.high_risk_count,
                    )
                else:
                    body = await resp.text()
                    logger.error("Slack daily report error %d: %s", resp.status, body)

    async def _send_telegram(self, d: _ReportData) -> None:
        """Telegram Markdown 포맷으로 보고서를 전송한다."""
        risk_line = (
            f"\u26a0\ufe0f *High Risk: {d.high_risk_count}*"
            if d.high_risk_count
            else "\u2705 High Risk: 0"
        )
        lines = [
            "\U0001f4ca *NetWatcher Daily Report*",
            f"_{d.period}_",
            "",
            "\U0001f4bb *Asset Inventory*",
            f"\u2022 Total: *{d.total_devices}* (+{d.new_today} new today)",
            f"\u2022 Registered: *{d.known_devices}* | Unregistered: *{d.unknown_devices}*",
            risk_line,
        ]

        if d.top_risk_devs:
            lines.append("")
            lines.append("*Top High-Risk Devices:*")
            for dev in d.top_risk_devs:
                lines.append(f"\u2022 `{dev['mac']}` {dev['label']} ({dev['score']}pts)")

        status_icon = "\U0001f534" if d.critical else "\U0001f7e2"
        lines += [
            "",
            f"{status_icon} *Events (24h): {d.total_events}*",
            f"\u2022 Critical: {d.critical} | Warning: {d.warning} | Info: {d.info}",
            "",
            f"\U0001f4e1 *Traffic:* "
            f"{d.traffic.get('total_packets', 0):,} pkts / "
            f"{_format_bytes(d.traffic.get('total_bytes', 0))}",
        ]
        if d.dashboard_url:
            lines.append(f"\n[Dashboard]({d.dashboard_url})")

        url = TELEGRAM_API.format(token=self._tg_token)
        payload = {
            "chat_id":    self._tg_chat_id,
            "text":       "\n".join(lines),
            "parse_mode": "Markdown",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=payload,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    logger.info(
                        "Daily report sent via Telegram (%d events, %d devices, %d high-risk)",
                        d.total_events, d.total_devices, d.high_risk_count,
                    )
                else:
                    body = await resp.text()
                    logger.error("Telegram daily report error %d: %s", resp.status, body)

    async def _send_discord(self, d: _ReportData) -> None:
        """Discord Embeds 포맷으로 보고서를 전송한다."""
        # 고위험 기기 또는 Critical 이벤트 존재 시 붉은 색
        color = 0xFF4B4B if (d.high_risk_count > 0 or d.critical > 0) else 0x4BB543

        risk_val = (
            f"\u26a0\ufe0f {d.high_risk_count} devices"
            if d.high_risk_count
            else "\u2705 None"
        )
        if d.top_risk_devs:
            top_lines = [
                f"`{dev['mac']}` {dev['label']} ({dev['score']}pts)"
                for dev in d.top_risk_devs
            ]
            risk_val += "\n" + "\n".join(top_lines)

        fields = [
            {
                "name":   "\U0001f4bb Assets",
                "value":  (
                    f"Total: **{d.total_devices}** (+{d.new_today} new today)\n"
                    f"Registered: **{d.known_devices}** | "
                    f"Unregistered: **{d.unknown_devices}**"
                ),
                "inline": False,
            },
            {
                "name":   "\u26a0\ufe0f High Risk",
                "value":  risk_val,
                "inline": False,
            },
            {"name": "\U0001f534 Critical", "value": str(d.critical), "inline": True},
            {"name": "\U0001f7e1 Warning",  "value": str(d.warning),  "inline": True},
            {"name": "\U0001f535 Info",     "value": str(d.info),     "inline": True},
            {
                "name":   "\U0001f4e1 Traffic (24h)",
                "value":  (
                    f"{d.traffic.get('total_packets', 0):,} pkts / "
                    f"{_format_bytes(d.traffic.get('total_bytes', 0))}"
                ),
                "inline": False,
            },
        ]

        embed: dict = {
            "title":       "NetWatcher Daily Report",
            "description": d.period,
            "color":       color,
            "fields":      fields,
        }
        if d.dashboard_url:
            embed["url"] = d.dashboard_url

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self._discord_url,
                json={"embeds": [embed]},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status in (200, 204):
                    logger.info(
                        "Daily report sent via Discord (%d events, %d devices, %d high-risk)",
                        d.total_events, d.total_devices, d.high_risk_count,
                    )
                else:
                    body = await resp.text()
                    logger.error("Discord daily report error %d: %s", resp.status, body)
