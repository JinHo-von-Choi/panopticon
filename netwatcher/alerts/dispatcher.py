"""중앙 알림 디스패처: DB 저장, 로깅, WebSocket 브로드캐스트, webhook 채널."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from netwatcher.alerts.channels.discord import DiscordChannel
from netwatcher.alerts.channels.slack import SlackChannel
from netwatcher.alerts.channels.telegram import TelegramChannel
from netwatcher.alerts.rate_limiter import RateLimiter
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.models import Alert, Severity
from netwatcher.storage.repositories import EventRepository
from netwatcher.utils.config import Config

if TYPE_CHECKING:
    from netwatcher.response.blocker import BlockManager

logger = logging.getLogger("netwatcher.alerts.dispatcher")


class AlertDispatcher:
    """속도 제한 기능을 갖춘 중앙 알림 디스패처.

    각 알림에 대한 처리 흐름:
    1. 속도 제한 확인
    2. DB 삽입
    3. 터미널 로깅
    4. WebSocket 브로드캐스트 (연결된 대시보드로)
    5. PCAP 캡처 (해당하는 경우)
    6. 알림 상관 분석
    7. Webhook 알림 (Telegram/Slack/Discord) -- 타임아웃 적용 병렬 처리
    """

    def __init__(
        self,
        config: Config,
        event_repo: EventRepository,
        correlator: AlertCorrelator | None = None,
        pcap_writer: PCAPWriter | None = None,
        block_manager: BlockManager | None = None,
    ) -> None:
        """설정, 리포지토리, 알림 채널 등 의존성을 초기화한다."""
        self._config        = config
        self._event_repo    = event_repo
        self._correlator    = correlator
        self._pcap_writer   = pcap_writer
        self._block_manager = block_manager
        self._queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=10000)
        self._task: asyncio.Task | None = None

        # 자동 차단 엔진 화이트리스트 (이 엔진들만 자동 차단을 트리거함)
        response_cfg = config.section("response") or {}
        self._auto_block_engines: set[str] = set(
            response_cfg.get("auto_block_engines", [])
        )

        # 속도 제한기
        rl_config = config.section("alerts").get("rate_limit", {})
        self._rate_limiter = RateLimiter(
            window_seconds=rl_config.get("window_seconds", 300),
            max_count=rl_config.get("max_per_key", 5),
        )
        # 주기적 정리 카운터
        self._cleanup_counter = 0

        # 알림 채널
        channels_config = config.section("alerts").get("channels", {})
        self._channels = []
        channel_classes = [
            ("telegram", TelegramChannel),
            ("slack", SlackChannel),
            ("discord", DiscordChannel),
        ]
        for name, cls in channel_classes:
            ch_config = channels_config.get(name, {})
            if ch_config.get("enabled", False):
                self._channels.append(cls(ch_config))
                logger.info("Notification channel enabled: %s", name)

        # WebSocket 구독자
        self._ws_subscribers: set[asyncio.Queue] = set()

    async def start(self) -> None:
        """디스패처 소비자 루프를 시작한다."""
        self._task = asyncio.create_task(self._consumer_loop())
        logger.info("AlertDispatcher started")

    async def stop(self) -> None:
        """디스패처를 중지한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("AlertDispatcher stopped")

    def enqueue(self, alert: Alert) -> None:
        """스레드 안전 큐 삽입 (스니퍼 콜백에서 호출)."""
        try:
            self._queue.put_nowait(alert)
        except asyncio.QueueFull:
            logger.warning("Alert queue full, dropping alert: %s", alert.title)
            try:
                from netwatcher.web.metrics import alerts_queue_depth
                # 큐 깊이가 이미 최대치
            except ImportError:
                pass

    def subscribe_ws(self) -> asyncio.Queue:
        """WebSocket 구독자를 등록한다. 읽기용 큐를 반환한다."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._ws_subscribers.add(q)
        return q

    def unsubscribe_ws(self, q: asyncio.Queue) -> None:
        """WebSocket 구독자를 해제한다."""
        self._ws_subscribers.discard(q)

    async def _consumer_loop(self) -> None:
        """큐에서 알림을 처리한다."""
        while True:
            alert = await self._queue.get()

            # 큐 깊이 메트릭 업데이트
            try:
                from netwatcher.web.metrics import alerts_queue_depth
                alerts_queue_depth.set(self._queue.qsize())
            except ImportError:
                pass

            try:
                await self._process_alert(alert)
            except Exception:
                logger.exception("Error processing alert: %s", alert.title)

            # 100개 알림마다 주기적 속도 제한기 정리
            self._cleanup_counter += 1
            if self._cleanup_counter >= 100:
                self._cleanup_counter = 0
                self._rate_limiter.cleanup()

    async def _process_alert(self, alert: Alert) -> None:
        """알림 한 건에 대해 속도 제한, DB 저장, 로깅, 브로드캐스트, webhook 전체 파이프라인을 실행한다."""
        # 1. 속도 제한
        if not self._rate_limiter.allow(alert.rate_limit_key):
            logger.debug("Rate limited: %s", alert.rate_limit_key)
            try:
                from netwatcher.web.metrics import alerts_rate_limited
                alerts_rate_limited.inc()
            except ImportError:
                pass
            return

        # 저장을 위해 metadata에 confidence 포함
        alert.metadata["confidence"] = alert.confidence

        # Prometheus 알림 카운터
        try:
            from netwatcher.web.metrics import alerts_total
            alerts_total.labels(engine=alert.engine, severity=alert.severity.value).inc()
        except ImportError:
            pass

        # 2. DB 삽입
        event_id = None
        try:
            event_id = await self._event_repo.insert(
                engine=alert.engine,
                severity=alert.severity.value,
                title=alert.title,
                description=alert.description,
                title_key=alert.title_key,
                description_key=alert.description_key,
                source_ip=alert.source_ip,
                source_mac=alert.source_mac,
                dest_ip=alert.dest_ip,
                dest_mac=alert.dest_mac,
                metadata=alert.metadata,
                packet_info=alert.packet_info,
            )
        except Exception:
            logger.exception("Failed to save alert to DB")

        # 3. 터미널 로깅
        log_fn = {
            "CRITICAL": logger.critical,
            "WARNING": logger.warning,
            "INFO": logger.info,
        }.get(alert.severity.value, logger.info)
        log_fn(
            "[%s] %s | %s | src=%s dst=%s | confidence=%.2f",
            alert.severity.value, alert.engine, alert.title,
            alert.source_ip or alert.source_mac or "?",
            alert.dest_ip or alert.dest_mac or "?",
            alert.confidence,
        )

        # 4. WebSocket 브로드캐스트
        alert_dict = alert.to_dict()
        if event_id:
            alert_dict["id"] = event_id
        msg = json.dumps(alert_dict)
        dead_subs = []
        for sub_q in list(self._ws_subscribers):
            try:
                sub_q.put_nowait(msg)
            except asyncio.QueueFull:
                dead_subs.append(sub_q)
        for q in dead_subs:
            self._ws_subscribers.discard(q)

        # 5. PCAP 캡처
        if self._pcap_writer and event_id:
            try:
                pcap_path = self._pcap_writer.capture_for_alert(
                    event_id=event_id,
                    source_ip=alert.source_ip,
                    dest_ip=alert.dest_ip,
                )
                if pcap_path:
                    logger.debug("PCAP saved: %s", pcap_path)
            except Exception:
                logger.debug("PCAP capture failed", exc_info=True)

        # 6. 알림 상관 분석
        if self._correlator and event_id:
            try:
                incident = self._correlator.process_alert(alert, event_id)
                if incident:
                    # 인시던트를 WebSocket으로 브로드캐스트
                    inc_msg = json.dumps({
                        "type": "incident",
                        "incident": incident.to_dict(),
                    })
                    for sub_q in list(self._ws_subscribers):
                        try:
                            sub_q.put_nowait(inc_msg)
                        except asyncio.QueueFull:
                            pass
            except Exception:
                logger.debug("Correlation failed", exc_info=True)

        # 7. 자동 차단 (활성화 상태이고 조건 충족 시)
        if (
            self._block_manager
            and self._block_manager.enabled
            and alert.severity == Severity.CRITICAL
            and alert.source_ip
            and alert.engine in self._auto_block_engines
        ):
            try:
                blocked = await self._block_manager.block(
                    ip=alert.source_ip,
                    reason=f"[{alert.engine}] {alert.title}",
                    alert_id=event_id,
                )
                if blocked:
                    logger.info(
                        "Auto-blocked %s via engine %s",
                        alert.source_ip,
                        alert.engine,
                    )
            except Exception:
                logger.exception("Auto-block failed for %s", alert.source_ip)

        # 8. Webhook 채널 -- 타임아웃 적용 병렬 처리
        await self._send_webhooks(alert)

    async def _send_webhooks(self, alert: Alert) -> None:
        """해당하는 모든 webhook 채널에 알림을 병렬로 전송한다."""
        async def _timed_send(channel, name: str) -> tuple[str, float, Exception | None]:
            """채널 전송을 수행하고 (이름, 소요 시간, 예외)를 반환한다."""
            start = time.monotonic()
            try:
                await asyncio.wait_for(channel.send(alert), timeout=15.0)
                return name, time.monotonic() - start, None
            except Exception as exc:
                return name, time.monotonic() - start, exc

        tasks = [
            _timed_send(channel, channel.name)
            for channel in self._channels
            if channel.should_send(alert)
        ]

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.exception("Webhook task raised unexpected error: %s", result)
                continue
            name, elapsed, exc = result
            if exc is not None:
                logger.exception("Webhook channel %s failed: %s", name, exc)
            else:
                try:
                    from netwatcher.web.metrics import webhook_duration
                    webhook_duration.labels(channel=name).observe(elapsed)
                except ImportError:
                    pass
