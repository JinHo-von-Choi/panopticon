"""비동기 엔진 디스패치 레지스트리.

EngineRegistry를 감싸서 CPU-bound 엔진은 ThreadPoolExecutor로,
fast 엔진은 인라인으로, io 엔진은 코루틴으로 실행한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from scapy.all import Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.attack_mapping import enrich_alert_metadata
from netwatcher.detection.engine_sla import EngineSLAMonitor
from netwatcher.detection.models import Alert, downgrade_severity
from netwatcher.detection.registry import EngineRegistry

try:
    from netwatcher.web.metrics import engine_analyze_duration as _engine_analyze_duration
except ImportError:
    _engine_analyze_duration = None

logger = logging.getLogger("netwatcher.detection.async_registry")


class AsyncEngineRegistry:
    """EngineRegistry를 비동기 디스패치로 감싼다.

    엔진의 engine_type 속성에 따라 실행 경로를 결정한다:
    - "fast": 인라인 실행 (executor 오버헤드 없음)
    - "cpu": ThreadPoolExecutor에서 실행
    - "io": analyze_async 코루틴이 있으면 코루틴 실행, 없으면 cpu와 동일

    서킷 브레이커가 열린 엔진은 건너뛴다.
    """

    def __init__(
        self,
        registry: EngineRegistry,
        executor: ThreadPoolExecutor | None = None,
        sla_monitor: EngineSLAMonitor | None = None,
    ) -> None:
        self._registry = registry
        self._executor = executor or ThreadPoolExecutor(max_workers=4)
        self._sla      = sla_monitor or EngineSLAMonitor()

    async def process_packet_async(self, packet: Packet) -> list[Alert]:
        """패킷을 모든 활성 엔진에 비동기로 분배한다.

        화이트리스트 필터링은 동기 레지스트리와 동일하게 적용된다.
        """
        # 화이트리스트 IP 스킵
        whitelist = self._registry.whitelist
        if whitelist is not None and packet.haslayer("IP"):
            src_ip = packet["IP"].src
            if whitelist.is_ip_whitelisted(src_ip):
                return []

        tasks: list[asyncio.Task[Alert | None]] = []
        engines_for_tasks: list[DetectionEngine] = []
        inline_alerts: list[Alert] = []

        loop = asyncio.get_running_loop()

        for engine in self._registry.engines:
            if not engine.enabled:
                continue
            if self._sla.is_circuit_open(engine.name):
                logger.debug("Skipping engine %s (circuit open)", engine.name)
                continue

            engine_type = getattr(engine, "engine_type", "cpu")

            if engine_type == "fast":
                alert = self._run_inline(engine, packet)
                if alert is not None:
                    inline_alerts.append(alert)
            elif engine_type == "io" and hasattr(engine, "analyze_async"):
                task = asyncio.create_task(
                    self._run_io(engine, packet)
                )
                tasks.append(task)
                engines_for_tasks.append(engine)
            else:
                # cpu 또는 io without analyze_async
                task = asyncio.create_task(
                    self._run_in_executor(loop, engine, packet)
                )
                tasks.append(task)
                engines_for_tasks.append(engine)

        # 병렬 실행된 태스크 수집
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for engine, result in zip(engines_for_tasks, results):
                if isinstance(result, BaseException):
                    logger.exception(
                        "Engine %s raised exception", engine.name,
                        exc_info=result,
                    )
                    continue
                if result is not None:
                    inline_alerts.append(result)

        return inline_alerts

    def _run_inline(self, engine: DetectionEngine, packet: Packet) -> Alert | None:
        """fast 엔진을 인라인으로 실행하고 SLA를 기록한다."""
        start = time.monotonic()
        success = True
        try:
            alert = engine.analyze(packet)
        except Exception:
            logger.exception("Engine %s raised exception", engine.name)
            success = False
            alert = None
        elapsed_ms = (time.monotonic() - start) * 1000.0

        if _engine_analyze_duration is not None:
            _engine_analyze_duration.labels(engine=engine.name).observe(
                elapsed_ms / 1000.0
            )
        self._sla.record(engine.name, elapsed_ms, success)

        if alert is not None:
            self._enrich_alert(engine, alert)
        return alert

    async def _run_in_executor(
        self,
        loop: asyncio.AbstractEventLoop,
        engine: DetectionEngine,
        packet: Packet,
    ) -> Alert | None:
        """CPU-bound 엔진을 ThreadPoolExecutor에서 실행한다."""
        start = time.monotonic()
        success = True
        try:
            alert = await loop.run_in_executor(
                self._executor, engine.analyze, packet
            )
        except Exception:
            logger.exception("Engine %s raised exception", engine.name)
            success = False
            alert = None
        elapsed_ms = (time.monotonic() - start) * 1000.0

        if _engine_analyze_duration is not None:
            _engine_analyze_duration.labels(engine=engine.name).observe(
                elapsed_ms / 1000.0
            )
        self._sla.record(engine.name, elapsed_ms, success)

        if alert is not None:
            self._enrich_alert(engine, alert)
        return alert

    async def _run_io(
        self,
        engine: DetectionEngine,
        packet: Packet,
    ) -> Alert | None:
        """IO-bound 엔진의 analyze_async 코루틴을 실행한다."""
        start = time.monotonic()
        success = True
        try:
            alert = await engine.analyze_async(packet)  # type: ignore[attr-defined]
        except Exception:
            logger.exception("Engine %s raised exception", engine.name)
            success = False
            alert = None
        elapsed_ms = (time.monotonic() - start) * 1000.0

        if _engine_analyze_duration is not None:
            _engine_analyze_duration.labels(engine=engine.name).observe(
                elapsed_ms / 1000.0
            )
        self._sla.record(engine.name, elapsed_ms, success)

        if alert is not None:
            self._enrich_alert(engine, alert)
        return alert

    @staticmethod
    def _enrich_alert(engine: DetectionEngine, alert: Alert) -> None:
        """MITRE ATT&CK 메타데이터 주입 및 심각도 조정."""
        if alert.mitre_attack_id is None:
            ids = getattr(engine, "mitre_attack_ids", [])
            if ids:
                alert.mitre_attack_id = ids[0]
        alert.metadata = enrich_alert_metadata(
            alert.mitre_attack_id, alert.metadata
        )
        if alert.confidence < 0.3:
            alert.severity = downgrade_severity(alert.severity)

    @property
    def sla_monitor(self) -> EngineSLAMonitor:
        """SLA 모니터 인스턴스를 반환한다."""
        return self._sla

    @property
    def registry(self) -> EngineRegistry:
        """내부 동기 레지스트리를 반환한다."""
        return self._registry

    def shutdown(self) -> None:
        """executor를 종료한다. 내부 레지스트리 shutdown은 호출자 책임."""
        self._executor.shutdown(wait=False)
