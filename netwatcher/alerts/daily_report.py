"""일일 예약 보고서: 정오에 24시간 통계를 Slack으로 전송."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import aiohttp

from netwatcher.storage.repositories import (
    DeviceRepository,
    EventRepository,
    TrafficStatsRepository,
)

logger = logging.getLogger("netwatcher.alerts.daily_report")


def _format_bytes(b: int) -> str:
    """바이트 수를 사람이 읽기 쉬운 단위(B/KB/MB/GB)로 포맷팅한다."""
    if b < 1024:
        return f"{b} B"
    if b < 1048576:
        return f"{b / 1024:.1f} KB"
    if b < 1073741824:
        return f"{b / 1048576:.1f} MB"
    return f"{b / 1073741824:.2f} GB"


class DailyReporter:
    """매일 정오(KST)에 24시간 통계 요약을 Slack으로 전송한다."""

    def __init__(
        self,
        webhook_url: str,
        event_repo: EventRepository,
        device_repo: DeviceRepository,
        stats_repo: TrafficStatsRepository,
        dashboard_url: str = "",
        report_hour: int = 12,
    ) -> None:
        """Slack webhook URL과 리포지토리 의존성을 초기화한다."""
        self._webhook_url = webhook_url
        self._event_repo = event_repo
        self._device_repo = device_repo
        self._stats_repo = stats_repo
        self._dashboard_url = dashboard_url
        self._report_hour = report_hour
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """일일 보고서 스케줄 루프를 백그라운드 태스크로 시작한다."""
        self._task = asyncio.create_task(self._schedule_loop())
        logger.info("DailyReporter started (report hour: %02d:00 KST)", self._report_hour)

    async def stop(self) -> None:
        """스케줄 루프를 취소하고 종료한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _schedule_loop(self) -> None:
        """다음 보고 시간까지 대기, 보고서 전송, 반복."""
        KST = timezone(timedelta(hours=9))
        while True:
            now = datetime.now(KST)
            # 다음 실행: 오늘 report_hour 시, 이미 지났으면 내일
            target = now.replace(
                hour=self._report_hour, minute=0, second=0, microsecond=0,
            )
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

    async def _send_report(self) -> None:
        """24시간 통계 보고서를 작성하고 전송한다."""
        KST = timezone(timedelta(hours=9))
        now = datetime.now(KST)
        since_dt = now - timedelta(hours=24)
        since_str = since_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")

        # 데이터 조회
        sev_counts = await self._event_repo.count_by_severity_since(since_str)
        eng_counts = await self._event_repo.count_by_engine_since(since_str)
        top_sources = await self._event_repo.top_sources_since(since_str, limit=5)
        device_count = await self._device_repo.count()
        traffic = await self._stats_repo.summary_since(since_str)

        total_events = sum(sev_counts.values())
        critical = sev_counts.get("CRITICAL", 0)
        warning = sev_counts.get("WARNING", 0)
        info = sev_counts.get("INFO", 0)

        # Slack 블록 구성
        period = f"{since_dt.strftime('%m/%d %H:%M')} ~ {now.strftime('%m/%d %H:%M')} KST"

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "\U0001f4ca NetWatcher 24h Report",
                    "emoji": True,
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*{period}*"},
                ],
            },
            {"type": "divider"},
        ]

        # 이벤트 요약
        status_emoji = "\U0001f534" if critical > 0 else "\U0001f7e2"
        event_text = (
            f"{status_emoji} *Events: {total_events}*\n"
            f"\u2022 Critical: *{critical}*\n"
            f"\u2022 Warning: *{warning}*\n"
            f"\u2022 Info: *{info}*"
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": event_text},
        })

        # 엔진별 분류
        if eng_counts:
            eng_lines = [f"\u2022 `{eng}`: {cnt}" for eng, cnt in eng_counts.items()]
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Engine Breakdown*\n" + "\n".join(eng_lines[:8])},
            })

        # 상위 출발지
        if top_sources:
            src_lines = [f"\u2022 `{s['ip']}` ({s['count']} events)" for s in top_sources]
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top Source IPs*\n" + "\n".join(src_lines)},
            })

        blocks.append({"type": "divider"})

        # 트래픽 + 디바이스
        total_pkts = traffic.get("total_packets", 0)
        total_bytes = traffic.get("total_bytes", 0)
        traffic_text = (
            f"\U0001f4e1 *Traffic*\n"
            f"\u2022 Packets: *{total_pkts:,}*\n"
            f"\u2022 Volume: *{_format_bytes(total_bytes)}*\n"
            f"\u2022 TCP: {traffic.get('tcp_count', 0):,} | "
            f"UDP: {traffic.get('udp_count', 0):,} | "
            f"ARP: {traffic.get('arp_count', 0):,} | "
            f"DNS: {traffic.get('dns_count', 0):,}"
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": traffic_text},
        })

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"\U0001f4bb *Devices Observed:* {device_count}"},
        })

        # 대시보드 링크
        if self._dashboard_url:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{self._dashboard_url}|Dashboard \u2192>"},
                ],
            })

        # 전송
        payload = {"blocks": blocks}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._webhook_url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        logger.info("Daily report sent (%d events, %s traffic)", total_events, _format_bytes(total_bytes))
                    else:
                        body = await resp.text()
                        logger.error("Daily report webhook error %d: %s", resp.status, body)
        except Exception:
            logger.exception("Failed to send daily report webhook")
