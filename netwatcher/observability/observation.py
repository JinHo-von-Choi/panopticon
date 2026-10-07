"""관측 범위(Observation Scope) 모델 — 경보 옆에 누락을 표시한다 (PR 11).

계획서 3장의 요구:

    "'경보 없음' 이 '문제 없음' 으로 읽히지 않게 한다"
    "트래픽 0 만으로 장애를 선언하지 않는다"
    "커널 drop 과 앱 drop 을 단순 합산해 전체 손실률로 만들지 않는다"
    "손실률은 같은 단계 · 같은 시간창의 분모로만 계산한다"
    "측정 불가능한 NIC/스위치 손실은 unknown 이다"

기존 HealthChecker 는 이 중 대부분을 하지 못했다. 스니퍼가 실행 중이고 큐가
안 찼으면 `healthy` 을 반환하는데, 그러면 다음 두 경우가 구분되지 않는다.

    1. 실제로 아무 일도 없었다
    2. 아무것도 관측하지 못했다 (인터페이스 정지, 워커 정지, 큐 포화, DB 단절)

이 모듈은 그 구분을 만든다. 판단을 억지로 confident 하게 만들지 않는다.
측정할 수 없는 것은 `unknown` 이라고 말한다.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("netwatcher.observability.observation")

# 파이프라인 단계 — 계획서의 계측 지점
STAGE_CAPTURE = "capture"          # NIC 에서 들어온 패킷
STAGE_INPUT_QUEUE = "input_queue"  # 입력 큐
STAGE_ENGINE = "engine"            # 엔진 분석
STAGE_RESULT_QUEUE = "result_queue"  # 결과 큐
STAGE_DB = "db"                    # DB 저장
STAGE_ALERT = "alert"              # 알림 생성

PIPELINE_STAGES: tuple[str, ...] = (
    STAGE_CAPTURE, STAGE_INPUT_QUEUE, STAGE_ENGINE,
    STAGE_RESULT_QUEUE, STAGE_DB, STAGE_ALERT,
)

# 계측 종류
KIND_RECEIVED = "received"
KIND_ACCEPTED = "accepted"
KIND_DROPPED = "dropped"
KIND_SUPPRESSED = "suppressed"

# drop 의 주체 — 합산 금지 (계획서 3장)
DROP_SOURCE_KERNEL = "kernel"   # NIC·커널 버퍼 — 앱이 알 수 없음
DROP_SOURCE_APP = "app"         # 백프레셔 등 앱 결정

# 상태
STATE_OBSERVED = "observed"
STATE_PARTIAL = "partial"
STATE_STALE = "stale"
STATE_UNKNOWN = "unknown"

# 이 센서에서 측정 불가능한 항목 — 없는 지표를 만들지 않는다
UNSUPPORTED_MEASUREMENTS: tuple[str, ...] = (
    "nic_drop",              # NIC/스위치 손실은 이 구성에서 측정할 수 없다
    "switch_loss",           # 상위 링크 손실
    "span_coverage",         # SPAN 구성 완전성
)

DEFAULT_HEARTBEAT_SECONDS = 10.0
DEFAULT_MISSED_BEATS_TO_STALE = 3


@dataclass
class StageCounters:
    """한 단계의 계측값.

    dropped 는 주체를 분리한다. 커널 drop 과 앱 drop 을 더하면 서로 다른
    분모를 가진 두 손실이 합쳐져 의미 없는 숫자가 된다.
    """

    received: int = 0
    accepted: int = 0
    suppressed: int = 0
    dropped_app: int = 0
    dropped_kernel: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "received": self.received,
            "accepted": self.accepted,
            "suppressed": self.suppressed,
            "dropped_app": self.dropped_app,
            "dropped_kernel": self.dropped_kernel,
        }


@dataclass
class ObservationWindow:
    """센서 하나의 관측 창."""

    sensor_id: str
    boot_id: str
    started_at: float
    expected_scope_version: int = 0
    last_received_at: float | None = None
    last_heartbeat_at: float | None = None
    last_durable_event_at: float | None = None
    queue_age_seconds: float | None = None
    counter_reset_at: float | None = None
    stages: dict[str, StageCounters] = field(
        default_factory=lambda: {s: StageCounters() for s in PIPELINE_STAGES},
    )
    unsupported: tuple[str, ...] = UNSUPPORTED_MEASUREMENTS

    def stage(self, name: str) -> StageCounters:
        if name not in self.stages:
            self.stages[name] = StageCounters()
        return self.stages[name]


class ObservationService:
    """관측 창을 수집하고 상태를 판정한다.

    판정 결과는 항상 ``observed / partial / stale / unknown`` 중 하나와
    그 **이유** 를 함께 돌려준다. 이유 없는 상태는 만들지 않는다.
    """

    def __init__(
        self,
        sensor_id: str,
        boot_id: str | None = None,
        heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
        missed_beats_to_stale: int = DEFAULT_MISSED_BEATS_TO_STALE,
    ) -> None:
        self._sensor_id = sensor_id
        self._boot_id = boot_id or _new_boot_id()
        self._heartbeat_seconds = heartbeat_seconds
        self._missed_beats_to_stale = missed_beats_to_stale
        self._started_at = time.time()
        self._window = ObservationWindow(
            sensor_id=sensor_id, boot_id=self._boot_id, started_at=self._started_at,
        )
        # 카운터는 패킷 처리 스레드에서 갱신되고 HTTP 스레드에서 읽힌다
        self._lock = threading.Lock()
        self._queues: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # 수집
    # ------------------------------------------------------------------

    @property
    def sensor_id(self) -> str:
        return self._sensor_id

    @property
    def boot_id(self) -> str:
        return self._boot_id

    def record(
        self,
        stage: str,
        kind: str,
        count: int = 1,
        drop_source: str | None = None,
    ) -> None:
        """단계별 계측값을 기록한다."""
        with self._lock:
            counters = self._window.stage(stage)
            if kind == KIND_RECEIVED:
                counters.received += count
                self._window.last_received_at = time.time()
            elif kind == KIND_ACCEPTED:
                counters.accepted += count
            elif kind == KIND_SUPPRESSED:
                counters.suppressed += count
            elif kind == KIND_DROPPED:
                if drop_source == DROP_SOURCE_KERNEL:
                    counters.dropped_kernel += count
                else:
                    # 주체를 명시하지 않은 drop 은 앱 결정으로 본다.
                    counters.dropped_app += count
            else:
                logger.warning("알 수 없는 계측 종류라 무시했다: %s", kind)

    def mark_heartbeat(self) -> None:
        with self._lock:
            self._window.last_heartbeat_at = time.time()

    def mark_durable_event(self) -> None:
        """DB 에 실제로 기록된 이벤트를 표시한다."""
        with self._lock:
            self._window.last_durable_event_at = time.time()

    def set_queue_age(self, seconds: float | None) -> None:
        with self._lock:
            self._window.queue_age_seconds = seconds

    def set_queue_metrics(self, stage: str, depth: int, age: float, wire_bytes: int | None = None) -> None:
        """큐 대기 상태. wire_bytes 는 Python 객체 메모리 크기가 아니다."""
        with self._lock:
            self._queues[stage] = {
                "depth": depth, "oldest_age_seconds": age,
                "wire_bytes": wire_bytes,
                "memory_bytes": None,
                "memory_note": "객체 메모리는 프로세스 RSS로 별도 측정한다",
            }

    def set_expected_scope_version(self, version: int) -> None:
        with self._lock:
            self._window.expected_scope_version = version

    def mark_counter_reset(self) -> None:
        """카운터 리셋(재시작 등)을 기록한다."""
        with self._lock:
            self._window.counter_reset_at = time.time()

    # ------------------------------------------------------------------
    # 판정
    # ------------------------------------------------------------------

    def snapshot(
        self, from_ts: float | None = None, to_ts: float | None = None,
    ) -> dict[str, Any]:
        """관측 상태를 요약한다.

        Returns:
            ``state``, ``reasons``, 단계별 계측, 미측정 항목, 손실률.
        """
        with self._lock:
            window = self._window
            received_total = sum(s.received for s in window.stages.values())
            stages = {name: c.as_dict() for name, c in window.stages.items()}
            queues = {name: dict(values) for name, values in self._queues.items()}

        now = time.time()
        reasons: list[str] = []
        state = STATE_OBSERVED

        # 1) heartbeat — 3회 이상 없으면 stale
        heartbeat = window.last_heartbeat_at
        missed = (
            float("inf") if heartbeat is None
            else max(0.0, (now - heartbeat) / self._heartbeat_seconds)
        )
        if missed >= self._missed_beats_to_stale:
            state = STATE_STALE
            if heartbeat is None:
                reasons.append("heartbeat 를 한 번도 받지 못했다")
            else:
                reasons.append(
                    f"heartbeat 가 {missed:.0f}회 연속 누락 "
                    f"(기준 {self._missed_beats_to_stale}회)"
                )

        # 2) 카운터 리셋 — 창이 끊겼으므로 부분 관측
        if window.counter_reset_at is not None:
            if state != STATE_STALE:
                state = STATE_PARTIAL
            reasons.append("카운터 리셋이 발생해 창이 연속이 아니다")

        # 3) 앱 포화 — 큐가 가득 찼으면 관측이 온전하지 않다
        queue_pressure = _queue_pressure(received_total, stages)
        if queue_pressure is not None:
            if state == STATE_OBSERVED:
                state = STATE_PARTIAL
            reasons.append(queue_pressure)

        # 4) 트래픽 0 은 장애가 아니다 — 명시적으로 그렇게 말한다
        no_traffic = received_total == 0
        if no_traffic and state == STATE_OBSERVED:
            reasons.append(
                "관측된 트래픽이 0 이다 — 이것만으로는 장애로 판정하지 않는다"
            )

        # 5) 판단은 항상 이유를 동반한다.
        # 근거가 없는데 "관측됨" 이라고 말하면, 그건 판정이 아니라 침묵이다.
        if not reasons:
            reasons.append("관측 창에 이상이 감지되지 않았다 (아래 계측 참고)")

        # 6) 측정 불가능 항목은 unknown 으로 남긴다
        loss = self._loss_report(stages)

        return {
            "sensor_id": window.sensor_id,
            "boot_id": window.boot_id,
            "state": state,
            "reasons": reasons,
            "from": from_ts or window.started_at,
            "to": to_ts or now,
            "expected_scope_version": window.expected_scope_version,
            "last_received_at": window.last_received_at,
            "last_heartbeat_at": heartbeat,
            "last_durable_event_at": window.last_durable_event_at,
            "heartbeat_missed_beats": None if heartbeat is None else round(missed, 2),
            "queue_age_seconds": window.queue_age_seconds,
            "counter_reset_at": window.counter_reset_at,
            "observed_traffic": received_total,
            "no_traffic_observed": no_traffic,
            "stages": stages,
            "queues": queues,
            "loss": loss,
            "unsupported_measurements": list(window.unsupported),
        }

    def _loss_report(self, stages: dict[str, dict[str, int]]) -> dict[str, Any]:
        """손실률을 단계별로 계산한다.

        규칙
        - **커널 drop 과 앱 drop 을 더하지 않는다.** 분모가 다르고 원인이 다르다.
        - 분모(같은 단계·같은 시간창의 received)가 없으면 백분율을 내지 않고
          원시 계수와 ``unknown`` 을 돌려준다.
        - 측정 불가능한 NIC/스위치 손실은 아예 숫자로 만들지 않는다.
        """
        per_stage: dict[str, Any] = {}
        for name, counters in stages.items():
            app_denominator = counters["received"] - counters["dropped_app"]
            app_loss: float | None = None
            if counters["received"] > 0:
                app_loss = counters["dropped_app"] / counters["received"]
            else:
                # 분모가 없으면 백분율을 만들지 않는다
                pass

            entry: dict[str, Any] = {
                # 분모를 숫자 옆에 둔다. 백분율만 떼어 보면 무엇에 대한
                # 비율인지 알 수 없다.
                "received": counters["received"],
                "app_dropped": counters["dropped_app"],
                "kernel_dropped": counters["dropped_kernel"],
                "suppressed": counters["suppressed"],
                "app_loss_ratio": app_loss,
                "comparable": counters["received"] > 0,
            }
            if counters["received"] == 0:
                entry["unknown_reason"] = "분모(수신)가 없어 백분율을 계산할 수 없다"
            if counters["dropped_kernel"] > 0:
                # 합산하지 않는다. 이 숫자는 앱 손실이 아니다.
                entry["kernel_loss_note"] = (
                    "커널 drop 은 앱 손실과 합산하지 않는다 (분모·원인 이 다름)"
                )
            per_stage[name] = entry

        return {
            "per_stage": per_stage,
            # NIC/스위치 손실은 이 구성에서 측정 불가
            "link_loss": {
                "value": None,
                "status": STATE_UNKNOWN,
                "reason": "NIC·스위치 손실은 이 센서에서 측정할 수 없다",
            },
            "warning": (
                "전체 손실률로 합산하지 않는다 — 단계별·분모 일치 경우에만 비교한다"
            ),
        }


class KernelDropProbe:
    """커널(softnet) drop 을 실제로 읽는다.

    계획서는 "NIC/스위치 손실은 측정 불가 → unknown" 이라고 한다. 그건 맞다.
    그러나 **커널 버퍼 drop 은 이 구성에서 실제로 읽을 수 있다**
    (``/proc/net/softnet_stat`` 2번째 필드). 이를 unknown 으로 덮어쓰면
    측정 가능한 값을 버리는 것이므로, 별도 원인으로 계측한다.

    단, 이 값은 앱 관측창의 분모와 다른 시점이므로 ``app_loss_ratio`` 에
    절대 포함하지 않는다. `ObservationService._loss_report` 가 그것을 보장한다.
    """

    SOFTNET_PATH = "/proc/net/softnet_stat"

    def __init__(self, observation: "ObservationService | None" = None) -> None:
        self._observation = observation
        self._last_total: int | None = None
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """이 커널에서 커널 drop 을 읽을 수 있는지."""
        return self._read_total() is not None

    def _read_total(self) -> int | None:
        """모든 CPU 의 softnet drop 합계. 읽을 수 없으면 None."""
        try:
            with open(self.SOFTNET_PATH, "r", encoding="ascii") as fh:
                total = 0
                seen = False
                for line in fh:
                    fields = line.split()
                    if len(fields) < 2:
                        continue
                    # 필드 2 = dropped (필드 1 = processed)
                    total += int(fields[1], 16)
                    seen = True
                return total if seen else None
        except (OSError, ValueError, IndexError):
            return None

    def poll(self) -> int | None:
        """직전 폴 이후의 커널 drop 증분을 계측값에 반영한다.

        Returns:
            이번에 감지한 증분. 계측 대상이 없거나 첫 폴이면 0.
        """
        total = self._read_total()
        if total is None:
            self._available = False
            return None

        self._available = True
        if self._last_total is None:
            # 첫 폴은 기준값만 잡는다. 프로세스 시작 이전 손실을 이 창에 넣지 않는다.
            self._last_total = total
            return 0

        delta = total - self._last_total
        if delta < 0:
            # 카운터 리셋(부팅/모듈 재적재). 관측 창이 끊겼음을 알린다.
            self._last_total = total
            if self._observation is not None:
                self._observation.mark_counter_reset()
            return 0

        self._last_total = total
        if delta and self._observation is not None:
            self._observation.record(
                STAGE_CAPTURE, KIND_DROPPED, delta, drop_source=DROP_SOURCE_KERNEL,
            )
        return delta

    def status(self) -> dict[str, Any]:
        """지원 여부를 명시한다 — 없는 지표를 만들지 않는다."""
        return {
            "source": self.SOFTNET_PATH,
            "available": self._available is not False and self.available,
            "note": (
                "커널 drop 은 측정되지만 NIC/스위치 링크 손실은 측정되지 않는다"
            ),
        }


def _queue_pressure(received_total: int, stages: dict[str, dict[str, int]]) -> str | None:
    """큐 포화를 확인한다."""
    for name in (STAGE_INPUT_QUEUE, STAGE_RESULT_QUEUE):
        counters = stages.get(name)
        if not counters:
            continue
        if counters["received"] > 0:
            ratio = counters["dropped_app"] / counters["received"]
            if ratio >= 0.1:
                return f"{name} 단계에서 {ratio:.0%} 가 앱 백프레셔로 유실됐다"
    return None


def _new_boot_id() -> str:
    """부팅 식별자 — 재시작하면 관측 창이 달라져야 한다."""
    import uuid
    return uuid.uuid4().hex[:12]
