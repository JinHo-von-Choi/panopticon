"""멀티프로세스 패킷 분석 워커.

Scapy 패킷을 독립 프로세스에서 병렬 분석하기 위한 워커 구현.
각 워커는 자체 EngineRegistry를 보유하며, IPC 큐를 통해 부모 프로세스와 통신한다.

작성자: 최진호
작성일: 2026-03-30
"""

from __future__ import annotations

import logging
import multiprocessing as mp
import os
import signal
import time
from multiprocessing import Queue
from typing import Any

from netwatcher.detection.models import Alert
from netwatcher.utils.config import Config


class PacketWorker:
    """멀티프로세스 패킷 분석 워커.

    독립 프로세스 내에서 EngineRegistry를 초기화하고,
    입력 큐에서 raw bytes를 수신하여 탐지 엔진으로 분석한 뒤
    결과 Alert를 직렬화하여 결과 큐로 전송한다.
    """

    def __init__(
        self,
        worker_id: int,
        config: Config,
        input_queue: Queue,
        result_queue: Queue,
    ) -> None:
        self._worker_id   = worker_id
        self._config      = config
        self._input_queue  = input_queue
        self._result_queue = result_queue
        self._running      = True
        self._logger       = logging.getLogger(f"netwatcher.capture.worker.{worker_id}")

    def run(self) -> None:
        """워커 메인 루프.

        1. EngineRegistry 초기화 및 엔진 자동 등록
        2. SIGTERM 시그널 핸들러 설정
        3. 입력 큐에서 패킷 수신 -> 분석 -> 결과 전송
        4. 주기적 tick 호출 (1초 간격)
        """
        # fork 이후 Scapy import (fork 안전)
        from scapy.layers.l2 import Ether

        from netwatcher.detection.registry import EngineRegistry

        self._logger.info("Worker %d started (pid=%d)", self._worker_id, os.getpid())

        # 엔진 레지스트리 초기화
        registry = EngineRegistry(self._config)
        registry.discover_and_register()

        # SIGTERM graceful shutdown
        def _handle_sigterm(signum: int, frame: Any) -> None:
            self._logger.info("Worker %d received SIGTERM, shutting down", self._worker_id)
            self._running = False

        signal.signal(signal.SIGTERM, _handle_sigterm)

        last_tick_time = time.monotonic()

        try:
            while self._running:
                # tick 처리: 1초 간격
                now = time.monotonic()
                if now - last_tick_time >= 1.0:
                    last_tick_time = now
                    try:
                        tick_alerts = registry.tick()
                        for alert in tick_alerts:
                            self._result_queue.put(alert.to_dict())
                    except Exception:
                        self._logger.exception(
                            "Worker %d tick failed", self._worker_id
                        )

                # 큐에서 패킷 수신 (timeout=0.1초로 tick 실행 기회 보장)
                try:
                    raw: bytes | None = self._input_queue.get(timeout=0.1)
                except Exception:
                    # queue.Empty 또는 기타 예외 — 다음 루프 반복
                    continue

                # sentinel: None 수신 시 종료
                if raw is None:
                    self._logger.info(
                        "Worker %d received sentinel, exiting", self._worker_id
                    )
                    break

                # raw bytes -> Scapy Ether 패킷 역직렬화
                try:
                    packet = Ether(raw)
                except Exception:
                    self._logger.debug(
                        "Worker %d failed to deserialize packet (%d bytes)",
                        self._worker_id,
                        len(raw),
                    )
                    continue

                # 엔진 분석
                try:
                    alerts: list[Alert] = registry.process_packet(packet)
                    for alert in alerts:
                        self._result_queue.put(alert.to_dict())
                except Exception:
                    self._logger.exception(
                        "Worker %d process_packet failed", self._worker_id
                    )
        finally:
            registry.shutdown()
            self._logger.info("Worker %d stopped", self._worker_id)


def worker_entry(
    worker_id: int,
    config_dict: dict[str, Any],
    input_queue: Queue,
    result_queue: Queue,
) -> None:
    """multiprocessing.Process(target=...)에 전달할 최상위 진입 함수.

    Config 객체는 직렬화 불가능할 수 있으므로 plain dict를 받아 복원한다.

    Args:
        worker_id: 워커 식별자 (0-based).
        config_dict: Config._data에 해당하는 plain dict.
        input_queue: 부모 프로세스로부터 raw bytes를 수신하는 큐.
        result_queue: Alert.to_dict() 결과를 부모 프로세스로 전송하는 큐.
    """
    # 워커 프로세스 내에서 로깅 재설정
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [worker-{worker_id}] %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger(f"netwatcher.capture.worker.{worker_id}")

    try:
        config = Config(config_dict)
        worker = PacketWorker(worker_id, config, input_queue, result_queue)
        worker.run()
    except Exception:
        logger.exception("Worker %d crashed", worker_id)
