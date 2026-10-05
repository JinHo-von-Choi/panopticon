"""관측 범위(observation scope) 계약 테스트 (PR 11 / 계획서 3장).

이 테스트가 고정하는 것은 기능이 아니라 **판단의 정직함** 이다.

    "'경보 없음' 이 '문제 없음' 으로 읽히지 않게 한다"
    "트래픽 0 만으로 장애를 선언하지 않는다"
    "커널 drop 과 앱 drop 을 단순 합산해 전체 손실률로 만들지 않는다"
    "손실률은 같은 단계 · 같은 시간창의 분모로만 계산한다"
    "측정 불가능한 NIC/스위치 손실은 unknown 이다"

이 중 하나라도 깨지면 "숫자가 있다" 는 이유로 오독이 시작된다.
"""

from __future__ import annotations

import time

import pytest

from netwatcher.observability.observation import (
    DROP_SOURCE_APP,
    DROP_SOURCE_KERNEL,
    KIND_ACCEPTED,
    KIND_DROPPED,
    KIND_RECEIVED,
    KIND_SUPPRESSED,
    STAGE_ALERT,
    STAGE_CAPTURE,
    STAGE_DB,
    STAGE_INPUT_QUEUE,
    STATE_OBSERVED,
    STATE_PARTIAL,
    STATE_STALE,
    STATE_UNKNOWN,
    KernelDropProbe,
    ObservationService,
)


@pytest.fixture
def obs() -> ObservationService:
    service = ObservationService(sensor_id="test-sensor", heartbeat_seconds=10.0)
    service.mark_heartbeat()
    return service


class TestLossRatio:
    """손실률 계산 규칙."""

    def test_kernel_and_app_drops_are_not_summed(self, obs: ObservationService) -> None:
        """커널 drop 과 앱 drop 을 한 손실률로 합치지 않는다.

        두 값의 분모가 다르고 원인도 다르다. 합산하면 의미 없는 숫자가 나오고,
        그 숫자가 "애플리케이션 손실률" 로 읽힌다.
        """
        obs.record(STAGE_CAPTURE, KIND_RECEIVED, 1000)
        obs.record(STAGE_CAPTURE, KIND_DROPPED, 300, drop_source=DROP_SOURCE_KERNEL)
        obs.record(STAGE_CAPTURE, KIND_DROPPED, 20, drop_source=DROP_SOURCE_APP)

        entry = obs.snapshot()["loss"]["per_stage"][STAGE_CAPTURE]

        # 합산했다면 (300+20)/1000 = 32% 가 된다
        assert entry["app_loss_ratio"] == pytest.approx(0.02)
        assert entry["kernel_dropped"] == 300
        assert entry["app_dropped"] == 20
        assert "kernel_loss_note" in entry

    def test_unknown_drop_source_is_not_silently_kernel(self, obs: ObservationService) -> None:
        """주체를 명시하지 않은 drop 은 앱 결정으로 분류한다.

        커널 drop 으로 몰아넣으면 측정 불가한 값을 측정 가능하다고 속인다.
        """
        obs.record(STAGE_INPUT_QUEUE, KIND_RECEIVED, 10)
        obs.record(STAGE_INPUT_QUEUE, KIND_DROPPED, 3)

        entry = obs.snapshot()["loss"]["per_stage"][STAGE_INPUT_QUEUE]
        assert entry["app_dropped"] == 3
        assert entry["kernel_dropped"] == 0

    def test_zero_denominator_yields_no_percentage(self, obs: ObservationService) -> None:
        """분모가 0 이면 백분율을 만들지 않고 왜 없는지 말한다."""
        entry = obs.snapshot()["loss"]["per_stage"][STAGE_DB]

        assert entry["received"] == 0
        assert entry["app_loss_ratio"] is None
        assert entry["comparable"] is False
        assert "분모" in entry["unknown_reason"]

    def test_link_loss_is_always_unknown(self, obs: ObservationService) -> None:
        """NIC/스위치 링크 손실은 측정 불가 — 숫자를 만들지 않는다."""
        obs.record(STAGE_CAPTURE, KIND_RECEIVED, 500)
        loss = obs.snapshot()["loss"]

        assert loss["link_loss"]["value"] is None
        assert loss["link_loss"]["status"] == STATE_UNKNOWN
        assert loss["link_loss"]["reason"]


class TestNoTrafficIsNotAnOutage:
    """관측 부재와 관측 결과 부재를 구분한다."""

    def test_zero_traffic_does_not_declare_outage(self, obs: ObservationService) -> None:
        """트래픽 0 은 장애가 아니다. 다만 "0 이다" 라고는 말해야 한다."""
        snap = obs.snapshot()

        assert snap["observed_traffic"] == 0
        assert snap["no_traffic_observed"] is True
        assert snap["state"] == STATE_OBSERVED
        assert any("0" in r for r in snap["reasons"])

    def test_snapshot_always_carries_reasons(self, obs: ObservationService) -> None:
        """상태는 반드시 이유를 동반한다."""
        obs.record(STAGE_CAPTURE, KIND_RECEIVED, 10)
        assert obs.snapshot()["reasons"]

    def test_observed_state_is_not_claimed_when_queue_saturated(
        self, obs: ObservationService,
    ) -> None:
        """입력 큐가 10% 이상 유실되면 관측은 온전하지 않다."""
        obs.record(STAGE_INPUT_QUEUE, KIND_RECEIVED, 100)
        obs.record(STAGE_INPUT_QUEUE, KIND_DROPPED, 15, drop_source=DROP_SOURCE_APP)

        snap = obs.snapshot()
        assert snap["state"] == STATE_PARTIAL
        assert any("input_queue" in r for r in snap["reasons"])


class TestHeartbeat:
    """heartbeat 로 센서 생존을 판정한다."""

    def test_fresh_heartbeat_is_observed(self, obs: ObservationService) -> None:
        obs.record(STAGE_CAPTURE, KIND_RECEIVED, 10)
        assert obs.snapshot()["state"] == STATE_OBSERVED

    def test_three_missed_beats_are_stale(self, obs: ObservationService) -> None:
        """10초 주기에서 3회(30초) 이상 heartbeat 가 없으면 stale."""
        obs._window.last_heartbeat_at = time.time() - 31
        snap = obs.snapshot()

        assert snap["state"] == STATE_STALE
        assert snap["heartbeat_missed_beats"] >= 3
        assert any("heartbeat" in r for r in snap["reasons"])

    def test_never_seen_heartbeat_is_stale(self, obs: ObservationService) -> None:
        obs._window.last_heartbeat_at = None
        snap = obs.snapshot()

        assert snap["state"] == STATE_STALE
        assert snap["heartbeat_missed_beats"] is None

    def test_counter_reset_marks_partial(self, obs: ObservationService) -> None:
        """카운터 리셋은 창이 끊겼다는 뜻 — 관측이 온전하지 않다."""
        obs.record(STAGE_CAPTURE, KIND_RECEIVED, 100)
        obs.mark_counter_reset()

        snap = obs.snapshot()
        assert snap["state"] == STATE_PARTIAL
        assert snap["counter_reset_at"] is not None
        assert any("리셋" in r for r in snap["reasons"])


class TestSuppressionIsNotLoss:
    """억제는 손실이 아니라 별도의 사실이다."""

    def test_suppressed_counted_separately(self, obs: ObservationService) -> None:
        obs.record(STAGE_ALERT, KIND_RECEIVED, 10)
        obs.record(STAGE_ALERT, KIND_SUPPRESSED, 7)
        entry = obs.snapshot()["loss"]["per_stage"][STAGE_ALERT]

        assert entry["suppressed"] == 7
        assert entry["app_dropped"] == 0
        # 억제는 손실률이 아니다 — 앱 drop 이 0 이므로 0 이고 비교 가능하다
        assert entry["app_loss_ratio"] == pytest.approx(0.0)
        assert entry["comparable"] is True


class TestKernelDropProbe:
    """커널 drop 은 측정 가능하되, 앱 분모와 섞지 않는다."""

    def test_first_poll_is_baseline_only(self, tmp_path) -> None:
        probe = KernelDropProbe()
        probe.SOFTNET_PATH = str(_write_softnet(tmp_path, ["00000010 00000005"]))

        assert probe.poll() == 0
        assert probe.available is True

    def test_delta_recorded_as_kernel_drop(self, obs: ObservationService, tmp_path) -> None:
        path = _write_softnet(tmp_path, ["00000010 00000005"])
        probe = KernelDropProbe(obs)
        probe.SOFTNET_PATH = str(path)

        probe.poll()  # 기준값
        _write_softnet(tmp_path, ["00000010 00000008"], overwrite=True)
        assert probe.poll() == 3

        entry = obs.snapshot()["loss"]["per_stage"][STAGE_CAPTURE]
        assert entry["kernel_dropped"] == 3
        # 앱 손실률에는 반영되지 않는다
        assert entry["app_loss_ratio"] is None

    def test_counter_decrease_marks_reset_instead_of_negative(
        self, obs: ObservationService, tmp_path,
    ) -> None:
        path = _write_softnet(tmp_path, ["00000010 000000ff"])
        probe = KernelDropProbe(obs)
        probe.SOFTNET_PATH = str(path)
        probe.poll()

        _write_softnet(tmp_path, ["00000010 00000001"], overwrite=True)
        assert probe.poll() == 0
        assert obs.snapshot()["counter_reset_at"] is not None

    def test_unreadable_source_is_not_fabricated(self, tmp_path) -> None:
        probe = KernelDropProbe()
        probe.SOFTNET_PATH = str(tmp_path / "does-not-exist")

        assert probe.poll() is None
        assert probe.available is False
        assert "측정되지 않는다" in probe.status()["note"]


def _write_softnet(tmp_path, rows, overwrite: bool = False):
    """softnet_stat 형태의 더미 파일을 만든다 (필드 2 = dropped)."""
    path = tmp_path / "softnet_stat"
    if overwrite or not path.exists():
        path.write_text("\n".join(rows) + "\n", encoding="ascii")
    return path


class TestDurableEvent:
    """DB 기록 여부를 경보 옆에 남긴다."""

    def test_durable_event_marked(self, obs: ObservationService) -> None:
        obs.mark_durable_event()
        assert obs.snapshot()["last_durable_event_at"] is not None
