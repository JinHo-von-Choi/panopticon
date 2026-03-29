"""멀티프로세스 워커 풀 관리자."""

from __future__ import annotations

import logging
import multiprocessing as mp
import os
import time
from multiprocessing import Process, Queue
from typing import Any, Callable

from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.capture.pool")

_QUEUE_MAXSIZE = 10_000


class WorkerPool:
    """패킷을 N개 워커 프로세스로 분배하는 관리자.

    src_ip 해싱으로 같은 호스트의 패킷이 항상 같은 워커로 라우팅되어
    상태 기반 엔진이 정확히 동작한다.
    """

    def __init__(self, config: Config, num_workers: int = 0) -> None:
        if num_workers == 0:
            num_workers = max(1, (os.cpu_count() or 2) - 1)

        self._config = config
        self._num_workers = num_workers
        self._single_process = num_workers < 2

        self._input_queues: list[Queue] = []
        self._result_queue: Queue = Queue()
        self._workers: list[Process] = []
        self._alive = False
        self._dropped: int = 0
        self._rr_counter: int = 0

        if not self._single_process:
            self._input_queues = [Queue(maxsize=_QUEUE_MAXSIZE) for _ in range(num_workers)]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """워커 프로세스를 생성하고 시작한다."""
        if self._single_process:
            logger.info("단일프로세스 모드 -- 워커를 생성하지 않음")
            self._alive = True
            return

        from netwatcher.capture.worker import worker_entry

        config_dict: dict[str, Any] = self._config.raw

        for wid in range(self._num_workers):
            p = Process(
                target=worker_entry,
                args=(wid, config_dict, self._input_queues[wid], self._result_queue),
                daemon=True,
                name=f"nw-worker-{wid}",
            )
            p.start()
            self._workers.append(p)
            logger.info("워커 %d (pid=%d) 시작", wid, p.pid)

        self._alive = True

    def stop(self) -> None:
        """모든 워커를 정상 종료한다."""
        if self._single_process or not self._alive:
            self._alive = False
            return

        for wid, q in enumerate(self._input_queues):
            try:
                q.put_nowait(None)
            except Exception:
                logger.warning("워커 %d sentinel 전송 실패", wid)

        for wid, p in enumerate(self._workers):
            p.join(timeout=5)
            if p.is_alive():
                logger.warning("워커 %d 타임아웃 -- terminate()", wid)
                p.terminate()

        self._workers.clear()
        for q in self._input_queues:
            q.close()
        self._input_queues.clear()
        self._result_queue.close()
        self._alive = False
        logger.info("워커 풀 종료 완료")

    # ------------------------------------------------------------------
    # Packet routing
    # ------------------------------------------------------------------

    def route_packet(self, packet_bytes: bytes, src_ip: str | None) -> bool:
        """패킷을 적절한 워커로 라우팅한다.

        Returns:
            단일프로세스 모드에서는 False (호출측이 직접 처리).
            멀티프로세스 모드에서는 큐 전송 시도 후 True.
        """
        if self._single_process:
            return False

        if src_ip is not None:
            idx = hash(src_ip) % self._num_workers
        else:
            idx = self._rr_counter % self._num_workers
            self._rr_counter += 1

        try:
            self._input_queues[idx].put_nowait(packet_bytes)
        except Exception:
            self._dropped += 1
            return True

        return True

    # ------------------------------------------------------------------
    # Result collection
    # ------------------------------------------------------------------

    def collect_alerts(self, max_batch: int = 100) -> list[dict]:
        """result_queue에서 non-blocking으로 Alert dict를 수집한다."""
        alerts: list[dict] = []
        for _ in range(max_batch):
            try:
                item = self._result_queue.get_nowait()
            except Exception:
                break
            if item is not None:
                alerts.append(item)
        return alerts

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """각 워커의 생존 상태를 확인하고 죽은 워커를 재시작한다."""
        if self._single_process:
            return {"mode": "single_process"}

        from netwatcher.capture.worker import worker_entry

        config_dict = self._config.raw
        status: dict[str, Any] = {}

        for wid in range(len(self._workers)):
            p = self._workers[wid]
            alive = p.is_alive()
            status[f"worker_{wid}"] = alive

            if not alive and self._alive:
                logger.warning("워커 %d 사망 감지 -- 재시작", wid)
                new_q: Queue = Queue(maxsize=_QUEUE_MAXSIZE)
                new_p = Process(
                    target=worker_entry,
                    args=(wid, config_dict, new_q, self._result_queue),
                    daemon=True,
                    name=f"nw-worker-{wid}",
                )
                new_p.start()
                self._workers[wid] = new_p
                self._input_queues[wid] = new_q
                status[f"worker_{wid}"] = True
                logger.info("워커 %d (pid=%d) 재시작 완료", wid, new_p.pid)

        return status

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def num_workers(self) -> int:
        """활성 워커 수."""
        return len(self._workers)

    @property
    def is_multiprocess(self) -> bool:
        """멀티프로세스 모드 여부."""
        return not self._single_process

    @property
    def dropped_count(self) -> int:
        """라우팅 시 드롭된 패킷 누적 수."""
        return self._dropped
