"""멀티프로세스 패킷 분석 워커.

Scapy 패킷을 독립 프로세스에서 병렬 분석하기 위한 워커 구현.
각 워커는 자체 EngineRegistry를 보유하며, IPC 큐를 통해 부모 프로세스와 통신한다.

작성자: 최진호
작성일: 2026-03-30
"""

from __future__ import annotations

import logging
import json
import multiprocessing as mp
import os
import signal
import time
from queue import Empty, Full
from multiprocessing import Queue
from typing import Any
from types import FrameType

from netwatcher.detection.models import Alert
from netwatcher.utils.config import Config
from netwatcher.capture.worker_control import WorkerEngineChange, WorkerWhitelistChange, WorkerFeedChange, WorkerRulesChange, WorkerEngineReceipt


def decode_capture(envelope):
    from scapy.layers.l2 import Ether
    import math
    captured_at = None
    if isinstance(envelope, tuple) and len(envelope) == 2:
        raw, captured_at = envelope
        if not isinstance(captured_at, (float, int)) or not math.isfinite(captured_at) or captured_at <= 0:
            raise ValueError('Invalid capture time')
    else:
        raw = envelope
    packet = Ether(raw)
    if captured_at is not None:
        packet.time = captured_at
        object.__setattr__(packet, 'capture_time_verified', True)
    return packet


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
        control_results: Queue | None = None,
        feed_snapshot_json: str = "null",
        rules_snapshot_json: str | None = None,
        ready_event=None,
        result_failure=None,
    ) -> None:
        self._worker_id   = worker_id
        self._config      = config
        self._input_queue  = input_queue
        self._result_queue = result_queue
        self._control_results = control_results
        self._feed_snapshot_json = feed_snapshot_json
        self._rules_snapshot_json = rules_snapshot_json
        self._ready_event = ready_event
        self._result_failure = result_failure
        self._running      = True
        self._logger       = logging.getLogger(f"netwatcher.capture.worker.{worker_id}")

    def run(self) -> None:
        """워커 메인 루프.

        1. EngineRegistry 초기화 및 엔진 자동 등록
        2. SIGTERM 시그널 핸들러 설정
        3. 입력 큐에서 패킷 수신 -> 분석 -> 결과 전송
        4. 주기적 tick 호출 (1초 간격)
        """
        # 워커 프로세스 안에서 탐지 라이브러리를 초기화한다.
        from scapy.layers.l2 import Ether

        from netwatcher.detection.registry import EngineRegistry

        self._logger.info("Worker %d started (pid=%d)", self._worker_id, os.getpid())

        # 엔진 레지스트리 초기화
        registry = EngineRegistry(self._config)
        registry.discover_and_register()
        from netwatcher.capture.worker_feeds import WorkerFeeds
        registry.set_feeds(WorkerFeeds.from_payload(self._feed_snapshot_json))
        if self._rules_snapshot_json is not None:
            self._install_rules(registry, self._rules_snapshot_json, True)

        # SIGTERM graceful shutdown
        def _handle_sigterm(signum: int, frame: FrameType | None) -> None:
            self._logger.info("Worker %d received SIGTERM, shutting down", self._worker_id)
            self._running = False

        signal.signal(signal.SIGTERM, _handle_sigterm)
        if self._ready_event is not None:
            self._ready_event.set()

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
                            if not self._emit_alert(alert):
                                break
                    except Exception:
                        self._logger.exception(
                            "Worker %d tick failed", self._worker_id
                        )

                # 큐에서 패킷 수신 (timeout=0.1초로 tick 실행 기회 보장)
                try:
                    raw: bytes | None = self._input_queue.get(timeout=0.1)
                except Empty:
                    continue
                except (OSError, EOFError, ValueError):
                    self._logger.exception("Worker %d input queue failed", self._worker_id)
                    break

                # sentinel: None 수신 시 종료
                if raw is None:
                    self._logger.info(
                        "Worker %d received sentinel, exiting", self._worker_id
                    )
                    break

                if self._apply_control(registry, raw):
                    continue
                self._process_packet(registry, raw)
        finally:
            registry.shutdown()
            self._logger.info("Worker %d stopped", self._worker_id)

    def _apply_control(self, registry, command) -> bool:
        handlers = {WorkerEngineChange: self._apply_engine_change,
                    WorkerWhitelistChange: self._apply_whitelist_change,
                    WorkerFeedChange: self._apply_feed_change,
                    WorkerRulesChange: self._apply_rule_change}
        handler = handlers.get(type(command))
        if handler is None:
            return False
        handler(registry, command)
        return True

    def _apply_rule_change(self, registry, command) -> None:
        applied = False
        try:
            if self._control_results is None:
                raise ValueError("Worker rule control channel unavailable")
            self._install_rules(registry, command.rules_json, command.reset_matcher)
            applied = True
        except Exception:
            self._logger.exception("Worker %d rule change failed", self._worker_id)
        if self._control_results is not None:
            self._control_results.put(WorkerEngineReceipt(command.request_id, self._worker_id, applied), timeout=1)

    def _process_packet(self, registry, raw) -> None:
        try:
            packet = decode_capture(raw)
        except Exception:
            self._logger.debug("Worker %d failed to deserialize packet", self._worker_id)
            return
        try:
            from netwatcher.utils.packet_info import extract_packet_info
            info = None
            for alert in registry.process_packet(packet):
                if info is None:
                    info = extract_packet_info(packet)
                alert.packet_info = info
                if not self._emit_alert(alert):
                    break
        except Exception:
            self._logger.exception("Worker %d process_packet failed", self._worker_id)

    def _emit_alert(self, alert) -> bool:
        try:
            document = alert.to_dict()
            if len(json.dumps(document, allow_nan=False, separators=(",", ":")).encode()) > 65536:
                raise ValueError("Worker alert exceeds capacity")
            self._result_queue.put_nowait(document)
            return True
        except (Full, OSError, EOFError, ValueError, TypeError):
            self._logger.exception("Worker %d result channel unavailable; analysis stopped", self._worker_id)
            self._running = False
            if self._result_failure is not None:
                self._result_failure.set()
            return False

    def _install_rules(self, registry, payload, reset_matcher):
        from netwatcher.capture.worker_rules import restore_rules
        if type(reset_matcher) is not bool:
            raise ValueError("Invalid worker matcher reset")
        engine = registry._find_active("signature")
        if engine is None:
            raise ValueError("Worker signature engine unavailable")
        engine.install_rules(restore_rules(payload), reset_matcher=reset_matcher)
        self._rules_snapshot_json = payload

    def _apply_feed_change(self, registry, command: WorkerFeedChange) -> None:
        from netwatcher.capture.worker_feeds import WorkerFeeds
        applied = False
        try:
            registry.set_feeds(WorkerFeeds.from_payload(command.snapshot_json))
            self._feed_snapshot_json = command.snapshot_json
            applied = True
        except Exception:
            self._logger.exception("Worker %d feed change failed", self._worker_id)
        if self._control_results is not None:
            self._control_results.put(WorkerEngineReceipt(command.request_id, self._worker_id, applied), timeout=1)

    def _apply_whitelist_change(self, registry, command: WorkerWhitelistChange) -> None:
        from netwatcher.services.sensor_whitelist import normalize_config
        from netwatcher.detection.whitelist import Whitelist
        applied = False
        try:
            if self._control_results is None or len(command.config_json.encode()) > 58000:
                raise ValueError("Invalid worker whitelist channel")
            config = normalize_config(json.loads(command.config_json))
            if registry.whitelist is None:
                raise ValueError("Worker whitelist is unavailable")
            replacement = Whitelist(config)
            registry.whitelist.__dict__.update(replacement.__dict__)
            self._config.raw["whitelist"] = config
            applied = True
        except Exception:
            self._logger.exception("Worker %d whitelist change failed", self._worker_id)
        if self._control_results is not None:
            self._control_results.put(WorkerEngineReceipt(command.request_id, self._worker_id, applied), timeout=1)

    def _apply_engine_change(self, registry, command: WorkerEngineChange) -> None:
        from netwatcher.detection.validation import validate_engine_config
        from netwatcher.detection.schema_utils import normalize_schema
        applied = False
        try:
            if self._control_results is None or len(command.config_json.encode()) > 32768:
                raise ValueError("Invalid worker control channel")
            schema = registry.get_engine_schema(command.engine)
            if schema is None:
                raise ValueError("Unknown worker engine")
            updates = json.loads(command.config_json)
            if not isinstance(updates, dict):
                raise ValueError("Invalid worker engine configuration")
            defaults = {key: field["default"] for key, field in normalize_schema(schema).items()}
            merged = {**defaults, **updates}
            if validate_engine_config(schema, merged) or type(merged.get("enabled", True)) is not bool:
                raise ValueError("Invalid worker engine configuration")
            if merged.get("enabled", True):
                applied, _, _ = registry.reload_engine(command.engine, merged)
            else:
                applied, _, _ = registry.disable_engine(command.engine)
            if applied:
                self._config.raw.setdefault("engines", {})[command.engine] = merged
        except Exception:
            self._logger.exception("Worker %d engine change failed", self._worker_id)
        if self._control_results is not None:
            self._control_results.put(WorkerEngineReceipt(command.request_id, self._worker_id, applied), timeout=1)


def worker_entry(
    worker_id: int,
    config_dict: dict[str, Any],
    input_queue: Queue,
    result_queue: Queue,
    control_results: Queue | None = None,
    feed_snapshot_json: str = "null",
    rules_snapshot_json: str | None = None,
    ready_event=None,
    result_failure=None,
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
        worker = PacketWorker(worker_id, config, input_queue, result_queue, control_results, feed_snapshot_json, rules_snapshot_json, ready_event, result_failure)
        worker.run()
    except Exception:
        logger.exception("Worker %d crashed", worker_id)
