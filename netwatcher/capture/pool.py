"""멀티프로세스 워커 풀 관리자."""

from __future__ import annotations

import logging
import json
from copy import deepcopy
from queue import Empty, Full
from uuid import uuid4
import multiprocessing as mp
import os
import time
from multiprocessing import Process, Queue
from typing import Any

from netwatcher.utils.config import Config
from netwatcher.capture.worker_control import WorkerEngineChange, WorkerWhitelistChange, WorkerFeedChange, WorkerRulesChange, WorkerEngineReceipt, WorkerSynchronizationError

logger = logging.getLogger("netwatcher.capture.pool")

_QUEUE_MAXSIZE = 10_000
_RESULT_QUEUE_MAXSIZE = 1_000


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
        self._context = mp.get_context("spawn")

        self._input_queues: list[Queue] = []
        self._result_queue: Queue = self._context.Queue(maxsize=_RESULT_QUEUE_MAXSIZE)
        self._result_failure = self._context.Event()
        self._workers: list[Process] = []
        self._ready_events = []
        self._alive = False
        self._dropped: int = 0
        self._rr_counter: int = 0
        self._control_results: Queue | None = self._context.Queue(maxsize=num_workers * 2) if not self._single_process else None
        self._control_failed = False
        self._routing_paused = False
        self._feed_snapshot_json = "null"
        self._rules_snapshot_json = None
        self._on_failure = None
        if not self._single_process:
            self._input_queues = [self._context.Queue(maxsize=_QUEUE_MAXSIZE) for _ in range(num_workers)]

    def bind_failure(self, callback) -> None:
        if not callable(callback):
            raise ValueError("Worker failure callback is required")
        self._on_failure = callback

    def _fail(self) -> None:
        first = not self._control_failed
        self._control_failed = True
        self._routing_paused = True
        if first and self._on_failure is not None:
            self._on_failure()

    def _worker_config(self):
        return {"engines": deepcopy(self._config.get("engines", {})),
                "whitelist": deepcopy(self._config.get("whitelist", {}))}

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

        config_dict: dict[str, Any] = self._worker_config()

        for wid in range(self._num_workers):
            ready = self._context.Event()
            p = self._context.Process(
                target=worker_entry,
                args=(wid, config_dict, self._input_queues[wid], self._result_queue, self._control_results, self._feed_snapshot_json, self._rules_snapshot_json, ready, self._result_failure),
                daemon=True,
                name=f"nw-worker-{wid}",
            )
            p.start()
            self._workers.append(p)
            self._ready_events.append(ready)
            logger.info("워커 %d (pid=%d) 시작", wid, p.pid)

        self._alive = True

    def wait_ready(self, timeout: float = 30) -> None:
        """기동 준비를 기다린다. 설정 적용의 짧은 제한 시간과 구분한다."""
        import math
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Invalid worker readiness timeout")
        if self._single_process:
            return
        deadline = time.monotonic() + timeout
        while True:
            if (not self._alive or self._control_failed or self._result_failure.is_set()
                    or len(self._workers) != self._num_workers
                    or any(not worker.is_alive() for worker in self._workers)):
                self._fail()
                raise WorkerSynchronizationError("Worker stopped before readiness")
            if all(event.is_set() for event in self._ready_events):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail()
                raise WorkerSynchronizationError("Worker readiness timed out")
            time.sleep(min(.02, remaining))

    def stop(self, timeout: float = 5, preserve_results: bool = False) -> None:
        """모든 워커를 정상 종료한다."""
        if self._single_process or not self._alive:
            self._alive = False
            return

        for wid, q in enumerate(self._input_queues):
            try:
                q.put_nowait(None)
            except Exception:
                logger.warning("워커 %d sentinel 전송 실패", wid)

        deadline = time.monotonic() + max(0, timeout)
        forced = []
        for wid, p in enumerate(self._workers):
            p.join(timeout=max(0, deadline - time.monotonic()))
            if p.is_alive():
                logger.warning("워커 %d 타임아웃 -- terminate()", wid)
                p.terminate()
                forced.append(p)

        for p in forced:
            p.join(timeout=max(0, deadline - time.monotonic()))
            if p.is_alive():
                p.kill()
        # 정지 상태의 프로세스도 회수한다. 정리용 대기는 풀 전체가 공유한다.
        reap_deadline = time.monotonic() + .1
        for p in forced:
            p.join(timeout=max(0, reap_deadline - time.monotonic()))
            if p.is_alive():
                self._fail()
                logger.error("Worker termination unconfirmed: pid=%s", p.pid)

        self._workers.clear()
        self._ready_events.clear()
        for q in self._input_queues:
            q.cancel_join_thread()
            q.close()
        self._input_queues.clear()
        if not preserve_results:
            self.close_results()
        if self._control_results is not None:
            self._control_results.cancel_join_thread()
            self._control_results.close()
        self._alive = False
        logger.info("워커 풀 종료 완료")

    def close_results(self) -> None:
        self._result_queue.cancel_join_thread()
        self._result_queue.close()

    # ------------------------------------------------------------------
    # Packet routing
    # ------------------------------------------------------------------

    def route_packet(self, packet_bytes: bytes, src_ip: str | None, captured_at: float | None = None) -> bool:
        """패킷을 적절한 워커로 라우팅한다.

        Returns:
            단일프로세스 모드에서는 False (호출측이 직접 처리).
            멀티프로세스 모드에서는 큐 전송 시도 후 True.
        """
        if self._single_process:
            return False
        if self._result_failure.is_set():
            self._fail()
        if self._routing_paused or self._control_failed:
            self._dropped += 1
            return True

        if src_ip is not None:
            idx = hash(src_ip) % self._num_workers
        else:
            idx = self._rr_counter % self._num_workers
            self._rr_counter += 1

        try:
            self._input_queues[idx].put_nowait((packet_bytes, captured_at) if captured_at is not None else packet_bytes)
        except Full:
            self._dropped += 1
            return True
        except (OSError, EOFError, ValueError):
            self._dropped += 1
            self._fail()
            logger.exception("Worker packet queue failed; routing stopped")
            return True

        return True

    # ------------------------------------------------------------------
    # Result collection
    # ------------------------------------------------------------------

    def collect_alerts(self, max_batch: int = 1000) -> list[dict]:
        """result_queue에서 non-blocking으로 Alert dict를 수집한다."""
        alerts: list[dict] = []
        if self._result_failure.is_set():
            self._fail()
        for _ in range(max_batch):
            try:
                item = self._result_queue.get_nowait()
            except Empty:
                break
            except (OSError, EOFError, ValueError):
                self._fail()
                logger.exception("Worker result queue failed; routing stopped")
                break
            if item is not None:
                alerts.append(item)
        return alerts

    def configure_engine(self, name: str, updates: dict, *, timeout: float = 2) -> None:
        """기존 패킷 뒤에 변경을 넣고 모든 워커의 적용 확인을 기다린다."""
        config = {**self._config.get(f"engines.{name}", {}), **deepcopy(updates)}
        payload = json.dumps(config, allow_nan=False, separators=(",", ":"))
        if len(payload.encode()) > 32768:
            raise ValueError("Worker configuration is too large")
        self._synchronize(WorkerEngineChange(str(uuid4()), name, payload), timeout=timeout)
        self._config.raw.setdefault("engines", {})[name] = config
        if name == "signature":
            self._rules_snapshot_json = None
        self._routing_paused = False

    def configure_whitelist(self, values: dict, *, timeout: float = 2) -> None:
        from netwatcher.services.sensor_whitelist import normalize_config
        config = normalize_config(values)
        payload = json.dumps(config, allow_nan=False, separators=(",", ":"))
        self._synchronize(WorkerWhitelistChange(str(uuid4()), payload), timeout=timeout)
        self._config.raw["whitelist"] = config
        self._routing_paused = False

    def _synchronize(self, command, *, timeout: float) -> None:
        import math
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 5):
            raise ValueError("Invalid worker control timeout")
        if self._single_process or not self._alive or self._control_failed or self._control_results is None:
            raise WorkerSynchronizationError("Worker control is unavailable")
        deadline = time.monotonic() + timeout
        self._routing_paused = True
        try:
            self.wait_ready(timeout=min(30, max(.001, deadline - time.monotonic())))
            if len(self._workers) != self._num_workers or any(not worker.is_alive() for worker in self._workers):
                raise WorkerSynchronizationError("Worker is not running")
            for queue in self._input_queues:
                queue.put(command, timeout=max(0, deadline - time.monotonic()))
            pending = set(range(self._num_workers))
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkerSynchronizationError("Worker control timed out")
                receipt = self._control_results.get(timeout=remaining)
                if (not isinstance(receipt, WorkerEngineReceipt) or receipt.request_id != command.request_id
                        or type(receipt.worker_id) is not int or receipt.worker_id not in pending
                        or receipt.applied is not True):
                    raise WorkerSynchronizationError("Worker change is unconfirmed")
                pending.remove(receipt.worker_id)
            if any(not worker.is_alive() for worker in self._workers):
                raise WorkerSynchronizationError("Worker stopped during change")
        except (Empty, Full, OSError, EOFError, ValueError, WorkerSynchronizationError) as exc:
            self._fail()
            raise WorkerSynchronizationError("Worker change is unconfirmed") from exc

    def configure_feeds(self, manager, *, timeout: float = 2) -> None:
        from netwatcher.capture.worker_feeds import feed_payload
        # 피드는 이미 부모에 반영된 상태다. 직렬화 실패도 동기화 실패로 취급한다.
        try:
            payload = feed_payload(manager)
        except (ValueError, TypeError, AttributeError) as exc:
            self._fail()
            raise WorkerSynchronizationError("Worker feed snapshot is invalid") from exc
        self._synchronize(WorkerFeedChange(str(uuid4()), payload), timeout=timeout)
        self._feed_snapshot_json = payload
        self._routing_paused = False

    def configure_rules(self, rules, *, reset_matcher: bool = True, timeout: float = 2) -> None:
        from netwatcher.capture.worker_rules import rules_payload
        if type(reset_matcher) is not bool:
            raise ValueError("Invalid worker matcher reset")
        payload = rules_payload(rules)
        self._synchronize(WorkerRulesChange(str(uuid4()), payload, reset_matcher), timeout=timeout)
        self._rules_snapshot_json = payload
        self._routing_paused = False

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """각 워커의 생존 상태를 확인하고 죽은 워커를 재시작한다."""
        if self._single_process:
            return {"mode": "single_process"}
        if self._result_failure.is_set():
            self._fail()
        if self._control_failed:
            return {"configuration_confirmed": False}

        from netwatcher.capture.worker import worker_entry

        config_dict = self._worker_config()
        status: dict[str, Any] = {}

        for wid in range(len(self._workers)):
            p = self._workers[wid]
            alive = p.is_alive()
            status[f"worker_{wid}"] = alive

            if not alive and self._alive:
                logger.warning("워커 %d 사망 감지 -- 재시작", wid)
                new_q: Queue = self._context.Queue(maxsize=_QUEUE_MAXSIZE)
                ready = self._context.Event()
                new_p = self._context.Process(
                    target=worker_entry,
                    args=(wid, config_dict, new_q, self._result_queue, self._control_results, self._feed_snapshot_json, self._rules_snapshot_json, ready, self._result_failure),
                    daemon=True,
                    name=f"nw-worker-{wid}",
                )
                new_p.start()
                previous_queue = self._input_queues[wid]
                previous_queue.cancel_join_thread()
                previous_queue.close()
                self._workers[wid] = new_p
                self._ready_events[wid] = ready
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
