"""중앙 알림 디스패처: DB 저장, 로깅, WebSocket 브로드캐스트, webhook 채널."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from netwatcher.alerts.rate_limiter import RateLimiter, EventBudget
from netwatcher.alerts.aggregation import AlertAggregator
from netwatcher.services.evidence_writer import EvidenceWriter
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.models import Alert, Severity
from netwatcher.observability.observation import (
    DROP_SOURCE_APP,
    KIND_ACCEPTED,
    KIND_DROPPED,
    KIND_RECEIVED,
    KIND_SUPPRESSED,
    STAGE_ALERT,
    STAGE_DB,
    STAGE_RESULT_QUEUE,
)
from netwatcher.storage.repositories import DeviceRepository, EventRepository
from netwatcher.utils.config import Config
from netwatcher.web import metrics

if TYPE_CHECKING:
    from netwatcher.observability.observation import ObservationService
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
        device_repo: DeviceRepository | None = None,
        correlator: AlertCorrelator | None = None,
        pcap_writer: PCAPWriter | None = None,
        block_manager: BlockManager | None = None,
        observation: "ObservationService | None" = None,
    ) -> None:
        """설정, 리포지토리, 알림 채널 등 의존성을 초기화한다."""
        self._config        = config
        self._event_repo    = event_repo
        self._device_repo   = device_repo
        self._correlator    = correlator
        self._pcap_writer   = pcap_writer
        evidence_cfg = config.section("evidence")
        self._evidence_writer = EvidenceWriter(
            pcap_writer, event_repo,
            max_jobs=evidence_cfg.get("queue_jobs", 32),
            max_bytes=evidence_cfg.get("queue_bytes", 8 * 1024 * 1024),
            cooldown=evidence_cfg.get("cooldown_seconds", 60),
        ) if pcap_writer is not None else None
        self._block_manager = block_manager
        self._queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=10000)
        self._task: asyncio.Task | None = None
        aggregation_cfg = config.section("alerts").get("aggregation", {})
        self._aggregator = AlertAggregator(
            window_seconds=aggregation_cfg.get("window_seconds", 60),
            max_keys=aggregation_cfg.get("max_keys", 10000),
        ) if aggregation_cfg.get("enabled", False) else None
        self._aggregation_task: asyncio.Task | None = None

        # 관측 범위 (계획서 3장). 경보 옆에 누락을 표시한다.
        self._observation = observation
        self._oldest_enqueued_at: float | None = None
        self._enqueue_times: deque[float] = deque()

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
        budget_cfg = config.section("alerts").get("event_budget", {})
        self._event_budget = EventBudget(
            normal=budget_cfg.get("normal_per_minute", 120),
            critical_reserve=budget_cfg.get("critical_reserve_per_minute", 30),
        )
        # 주기적 정리 카운터
        self._cleanup_counter = 0
        # 종료 배 emptying 중인지 (PR 06)
        self._stopping = False

        # 알림 채널
        channels_config = config.section("alerts").get("channels", {})
        from netwatcher.alerts.channels.registry import build_channels
        self._channels, self.channel_status = build_channels(channels_config)

        # WebSocket 구독자
        self._ws_subscribers: set[asyncio.Queue] = set()

    async def start(self) -> None:
        """디스패처 소비자 루프를 시작한다."""
        self._task = asyncio.create_task(self._consumer_loop())
        if self._aggregator is not None:
            self._aggregation_task = asyncio.create_task(self._aggregation_loop())
        logger.info("AlertDispatcher started")

    async def stop(self, drain_timeout: float | None = None) -> None:
        """디스패처를 중지한다.

        큐에 남아 있는 알림을 먼저 배 emptying 비운 뒤 소비자를 멈춘다.
        이전 구현은 소비자를 즉시 cancel 해서, 큐에 쌓인 알림(DB 미저장,
        미브로드캐스트, 미차단)을 그대로 버렸다. 종료 경로에서 탐지 결과를
        잃는 것은 영속성 결함이다 (PR 06).

        Args:
            drain_timeout: 배 emptying에 쓸 최대 초. None 이면 설정값을 쓰고,
                그것도 없으면 기본값을 쓴다. 배 emptying이 끝나도 남은 알림은
                경고와 함께 포기한다 (무한 대기 금지).
        """
        timeout = drain_timeout
        if timeout is None:
            alerts_cfg = self._config.section("alerts") or {}
            timeout = float(alerts_cfg.get("drain_timeout_seconds", 5.0))

        deadline = time.monotonic() + timeout
        remaining = self._queue.qsize()
        if remaining:
            logger.info(
                "Draining %d pending alert(s) before shutdown (timeout=%.1fs)",
                remaining, timeout,
            )

        self._stopping = True
        if self._task is not None:
            # drain_timeout 안에 큐가 비면 소비자가 스스로 끝나도록 신호를 준다
            try:
                await asyncio.wait_for(
                    self._queue.join(), timeout=timeout,
                )
            except asyncio.TimeoutError:
                left = self._queue.qsize()
                if left:
                    logger.warning(
                        "Shutdown drain timed out: %d alert(s) will not be persisted",
                        left,
                    )
            except Exception:
                logger.debug("Queue join failed during drain", exc_info=True)

            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        else:
            # 소비자가 아직 시작되지 않았다면 큐를 직접 비운다
            dropped = 0
            while True:
                try:
                    self._queue.get_nowait()
                    if self._enqueue_times:
                        self._enqueue_times.popleft()
                    dropped += 1
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break
            if dropped:
                logger.warning("Dispatcher stopped with %d unprocessed alert(s)", dropped)

        if self._aggregation_task is not None:
            self._aggregation_task.cancel()
            try:
                await self._aggregation_task
            except asyncio.CancelledError:
                pass
        if self._aggregator is not None:
            try:
                async with asyncio.timeout(max(0, deadline - time.monotonic())):
                    self._aggregator.expire(force=True)
                    while self._aggregator.pending:
                        await self._aggregator.flush(self._event_repo)
            except Exception:
                logger.warning("Aggregation shutdown incomplete; pending_windows=%d", len(self._aggregator.pending))
        if self._evidence_writer is not None:
            await self._evidence_writer.stop(timeout=max(0, deadline - time.monotonic()))
        self._oldest_enqueued_at = self._enqueue_times[0] if self._enqueue_times else None
        self.refresh_queue_metrics()

        logger.info("AlertDispatcher stopped")

    async def _aggregation_loop(self):
        while True:
            await asyncio.sleep(1)
            try:
                async with asyncio.timeout(2):
                    await self._aggregator.flush(self._event_repo)
                if self._aggregator.overflow:
                    metrics.alerts_suppressed.labels(reason="aggregation_overflow").inc(self._aggregator.overflow)
                    self._aggregator.overflow = 0
            except Exception:
                logger.debug("Aggregation update deferred; bounded pending windows retained")

    def enqueue(self, alert: Alert) -> None:
        """스레드 안전 큐 삽입 (스니퍼 콜백에서 호출)."""
        observation = self._observation
        if observation is not None:
            observation.record(STAGE_RESULT_QUEUE, KIND_RECEIVED)
        try:
            self._queue.put_nowait(alert)
            self._enqueue_times.append(time.monotonic())
            self._oldest_enqueued_at = self._enqueue_times[0]
            self.refresh_queue_metrics()
        except asyncio.QueueFull:
            metrics.alerts_queue_dropped.inc()
            # 큐 포화는 앱 결정이다. 커널 drop 과 합산하지 않는다.
            if observation is not None:
                observation.record(
                    STAGE_RESULT_QUEUE, KIND_DROPPED, 1, drop_source=DROP_SOURCE_APP,
                )
            logger.warning("Alert queue full, dropping alert: %s", alert.title)
            try:
                from netwatcher.web.metrics import alerts_queue_depth
                # 큐 깊이가 이미 최대치
            except ImportError:
                pass

    @property
    def oldest_queue_age_seconds(self) -> float | None:
        """큐에 가장 오래 머문 알림의 나이.

        큐 깊이만으로는 "얼마나 밀렸는지" 를 알 수 없다. 관측 상태가
        `partial` 인 이유를 설명할 때 이 값을 쓴다.
        """
        if self._oldest_enqueued_at is None:
            return None
        return max(0.0, time.monotonic() - self._oldest_enqueued_at)

    def refresh_queue_metrics(self) -> None:
        """현재 큐 깊이와 대기 시간을 관측 API·Prometheus에 반영한다."""
        age = self.oldest_queue_age_seconds or 0.0
        depth = self._queue.qsize()
        metrics.alerts_queue_depth.set(depth)
        metrics.alerts_queue_age.set(age)
        if self._observation is not None:
            self._observation.set_queue_metrics(STAGE_RESULT_QUEUE, depth, age)

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
            if self._enqueue_times:
                enqueued_at = self._enqueue_times.popleft()
                metrics.alerts_queue_wait.observe(max(0.0, time.monotonic() - enqueued_at))
            self._oldest_enqueued_at = self._enqueue_times[0] if self._enqueue_times else None
            self.refresh_queue_metrics()

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
            finally:
                # 반드시 task_done() 을 호출해야 stop() 의 배 emptying이 진행된다
                self._queue.task_done()

            # 100개 알림마다 주기적 속도 제한기 정리
            self._cleanup_counter += 1
            if self._cleanup_counter >= 100:
                self._cleanup_counter = 0
                self._rate_limiter.cleanup()

    async def _process_alert(self, alert: Alert) -> None:
        """알림 한 건에 대해 속도 제한, DB 저장, 로깅, 브로드캐스트, webhook 전체 파이프라인을 실행한다."""
        if self._observation is not None:
            self._observation.record(STAGE_ALERT, KIND_RECEIVED)
        if self._aggregator is not None and self._aggregator.repeat(alert):
            metrics.alerts_suppressed.labels(reason="aggregate_repeat").inc()
            if self._observation is not None:
                self._observation.record(STAGE_ALERT, KIND_SUPPRESSED)
            return
        # 1. 속도 제한
        limit_key = (self._aggregator.key(alert) + ":" + alert.severity.value
                     if self._aggregator is not None else alert.rate_limit_key)
        if not self._rate_limiter.allow(limit_key):
            metrics.alerts_suppressed.labels(reason="rate_limit").inc()
            logger.debug("Rate limited: %s", alert.rate_limit_key)
            if self._observation is not None:
                # 억제는 손실이 아니다. "알림 없음" 이 "탐지 없음" 이 되므로
                # 경보 옆에 그 사실을 남긴다.
                self._observation.record(STAGE_ALERT, KIND_SUPPRESSED)
            try:
                from netwatcher.web.metrics import alerts_rate_limited
                alerts_rate_limited.inc()
            except ImportError:
                pass
            return

        # 저장을 위해 metadata에 confidence 포함
        if not self._event_budget.allow(critical=alert.severity == Severity.CRITICAL):
            metrics.alerts_suppressed.labels(reason="global_budget").inc()
            if self._observation is not None:
                self._observation.record(STAGE_ALERT, KIND_SUPPRESSED)
            return

        alert.metadata["confidence"] = alert.confidence

        # 탐지 결과 계약 (PR 08): 요약 → 근거 → 원자료 세 층을 판정하고 기록한다.
        # 누락이 있어도 저장은 막지 않는다. 대신 metadata["evidence"] 로 드러내
        # "근거 없는 탐지"를 걸러낼 수 있게 한다.
        if self._observation is not None:
            self._observation.record(STAGE_ALERT, KIND_ACCEPTED)

        from netwatcher.detection.evidence import apply_evidence_contract
        evidence = apply_evidence_contract(alert)
        if self._evidence_writer is not None:
            alert.metadata["pcap"] = {"state": "pending", "reason": "awaiting_event_commit", "policy_version": 1}
        if self._aggregator is not None:
            alert.metadata["aggregation"] = self._aggregator.initial_summary(alert)
        if not evidence.complete:
            logger.debug(
                "탐지 결과 계약 미충족 (engine=%s, 누락=%s): %s",
                alert.engine, ",".join(evidence.missing), alert.title,
            )

        # Prometheus 알림 카운터
        try:
            from netwatcher.web.metrics import alerts_total
            alerts_total.labels(engine=alert.engine, severity=alert.severity.value).inc()
        except ImportError:
            pass

        # 2. DB 삽입
        event_id = None
        insert_started = time.monotonic()
        if self._observation is not None:
            self._observation.record(STAGE_DB, KIND_RECEIVED)
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
                mitre_attack_id=alert.mitre_attack_id,
                threat_level=alert.threat_level,
            )
        except Exception:
            logger.exception("Failed to save alert to DB")
        finally:
            result = "committed" if event_id is not None else "failed"
            metrics.event_store_duration.labels(result=result).observe(time.monotonic() - insert_started)
            metrics.event_store_total.labels(result=result).inc()

        if self._observation is not None:
            if event_id is not None:
                self._observation.record(STAGE_DB, KIND_ACCEPTED)
                self._observation.mark_durable_event()
            else:
                # DB 저장이 실패했는데 아무 표시가 없으면 "경보가 없다" 와 구분되지 않는다
                self._observation.record(
                    STAGE_DB, KIND_DROPPED, 1, drop_source=DROP_SOURCE_APP,
                )
        if self._aggregator is not None and event_id is not None:
            self._aggregator.register(alert, event_id)

        # 2b. 행동 레이블 — metadata에 host_label이 있으면 devices 테이블에 기록
        host_label = alert.metadata.get("host_label")
        if host_label and alert.source_ip and self._device_repo is not None:
            try:
                await self._device_repo.add_label_by_ip(alert.source_ip, host_label)
            except Exception:
                logger.debug("host_label update failed for %s", alert.source_ip)

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
                state = self._evidence_writer.submit(event_id, alert)
                if state["state"] != "pending":
                    await self._evidence_writer._store_state(event_id, state)
            except Exception:
                logger.debug("PCAP capture failed", exc_info=True)

        # 6. 알림 상관 분석
        if self._correlator and event_id:
            try:
                # await 로 영속화해 DB 가 부여한 id 를 인시던트가 갖게 한다 (PR 05).
                # 이렇게 해야 WebSocket/대시보드가 보는 id 와 DB 행이 일치한다.
                incident = await self._correlator.async_process_alert(alert, event_id)
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
                await asyncio.wait_for(channel.send(alert), timeout=5.0)
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
                logger.error("Webhook task failed: %s", type(result).__name__)
                continue
            name, elapsed, exc = result
            if exc is not None:
                logger.error("Webhook channel %s failed: %s", name, type(exc).__name__)
            else:
                try:
                    from netwatcher.web.metrics import webhook_duration
                    webhook_duration.labels(channel=name).observe(elapsed)
                except ImportError:
                    pass
