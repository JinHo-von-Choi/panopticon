"""관측 계측이 실제 파이프라인 지점에서 동작하는지 검증 (PR 11).

``test_observation_scope`` 는 계측 모델 자체의 계약을 고정한다. 이 파일은
**계측 지점이 실제로 존재하고 호출되는지** 를 고정한다.

모듈이 있어도 배선되지 않으면 계측값은 항상 0 이고, 그러면 "관측됨" 이라는
판정은 아무것도 보지 않은 통과다. 배선이 사라지면 이 테스트가 먼저 깨진다.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from scapy.all import Ether, IP, TCP

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.detection.models import Alert, Severity
from netwatcher.observability.observation import (
    STAGE_ALERT,
    STAGE_CAPTURE,
    STAGE_DB,
    STAGE_INPUT_QUEUE,
    STAGE_RESULT_QUEUE,
    ObservationService,
)
from netwatcher.utils.config import Config


def _config() -> Config:
    return Config({
        "alerts": {
            "rate_limit": {"window_seconds": 300, "max_per_key": 100000},
            "channels": {},
        },
    })


def _alert(title: str = "a") -> Alert:
    # rate_limit_key 는 Alert 의 파생 속성이므로 생성자에 넣지 않는다
    return Alert(
        engine="port_scan",
        severity=Severity.WARNING,
        title=title,
        description="d",
        source_ip="10.0.0.9",
    )


def _dispatcher(observation: ObservationService, insert_result=1) -> AlertDispatcher:
    repo = MagicMock()
    repo.insert = AsyncMock(return_value=insert_result)
    return AlertDispatcher(
        config=_config(),
        event_repo=repo,
        device_repo=None,
        correlator=None,
        pcap_writer=None,
        block_manager=None,
        observation=observation,
    )


# ------------------------------------------------------------------
# 디스패처 (result_queue / alert / db)
# ------------------------------------------------------------------

def test_enqueue_counts_result_queue():
    """알림이 큐에 들어가면 result_queue 수신으로 계측된다."""
    obs = ObservationService(sensor_id="s")
    d = _dispatcher(obs)

    d.enqueue(_alert("a"))
    d.enqueue(_alert("b"))

    assert obs.snapshot()["stages"][STAGE_RESULT_QUEUE]["received"] == 2


def test_full_result_queue_is_app_drop():
    """결과 큐 포화로 버려진 알림은 앱 drop 으로 계측된다.

    커널 drop 과 합산되지 않는다는 것도 함께 고정한다.
    """
    obs = ObservationService(sensor_id="s")
    d = _dispatcher(obs)
    d._queue = asyncio.Queue(maxsize=1)  # type: ignore[assignment]

    d.enqueue(_alert("kept"))
    d.enqueue(_alert("dropped"))

    entry = obs.snapshot()["loss"]["per_stage"][STAGE_RESULT_QUEUE]
    assert entry["app_dropped"] == 1
    assert entry["kernel_dropped"] == 0
    assert entry["app_loss_ratio"] == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_rate_limited_alert_is_suppressed_not_lost():
    """속도 제한으로 막힌 알림은 '손실'이 아니라 '억제'로 계측된다."""
    obs = ObservationService(sensor_id="s")
    d = _dispatcher(obs)
    d._rate_limiter = MagicMock()
    d._rate_limiter.allow = MagicMock(return_value=False)

    await d._process_alert(_alert("limited"))

    stages = obs.snapshot()["stages"]
    assert stages[STAGE_ALERT]["suppressed"] == 1
    assert stages[STAGE_ALERT]["dropped_app"] == 0


@pytest.mark.asyncio
async def test_persisted_alert_marks_durable_event():
    """DB 저장이 성공하면 그 사실이 관측 창에 남는다."""
    obs = ObservationService(sensor_id="s")
    d = _dispatcher(obs)

    await d._process_alert(_alert("stored"))

    snap = obs.snapshot()
    assert snap["stages"][STAGE_DB]["accepted"] == 1
    assert snap["last_durable_event_at"] is not None


@pytest.mark.asyncio
async def test_db_failure_is_not_silent():
    """DB 저장이 실패해도 기록이 없다면 '경보 없음'과 구분되지 않는다."""
    obs = ObservationService(sensor_id="s")
    d = _dispatcher(obs, insert_result=None)
    d._event_repo.insert = AsyncMock(side_effect=RuntimeError("db down"))

    await d._process_alert(_alert("lost"))

    stages = obs.snapshot()["stages"]
    assert stages[STAGE_DB]["accepted"] == 0
    assert stages[STAGE_DB]["dropped_app"] == 1
    assert obs.snapshot()["last_durable_event_at"] is None


@pytest.mark.asyncio
async def test_queue_age_is_reported():
    """큐 체류 나이는 큐가 실제로 찼을 때만 나온다."""
    obs = ObservationService(sensor_id="s")
    d = _dispatcher(obs)

    assert d.oldest_queue_age_seconds is None
    d.enqueue(_alert("waiting"))
    assert d.oldest_queue_age_seconds is not None

    await d._queue.get()
    d._oldest_enqueued_at = None
    assert d.oldest_queue_age_seconds is None


# ------------------------------------------------------------------
# 스니퍼 (capture / input_queue)
# ------------------------------------------------------------------

def _packet():
    return Ether(src="aa:bb:cc:dd:ee:01") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()


def _sniffer(observation: ObservationService, loop, maxlen: int = 50000) -> PacketSniffer:
    s = PacketSniffer(
        Config({"interface": "lo"}), loop, lambda p: None, observation=observation,
    )
    s._packet_buffer = type(s._packet_buffer)(maxlen=maxlen)  # type: ignore[assignment]
    return s


def test_sniffer_counts_capture_and_queue():
    """캡처된 패킷이 capture 와 input_queue 양쪽에 계측된다."""
    obs = ObservationService(sensor_id="s")
    loop = asyncio.new_event_loop()
    try:
        s = _sniffer(obs, loop)
        s._on_packet(_packet())
        s._on_packet(_packet())
        # 아직 루프가 돌지 않았으므로 계측은 아직 반영되지 않았다
        assert obs.snapshot()["observed_traffic"] == 0

        s.flush_observation()

        stages = obs.snapshot()["stages"]
        assert stages[STAGE_CAPTURE]["received"] == 2
        assert stages[STAGE_INPUT_QUEUE]["received"] == 2
    finally:
        loop.close()


def test_sniffer_backpressure_is_app_drop():
    """배압 버퍼가 가득 차면 앱 drop 으로 계측된다 (수신 대비 비율이 남는다)."""
    obs = ObservationService(sensor_id="s")
    loop = asyncio.new_event_loop()
    try:
        s = _sniffer(obs, loop, maxlen=2)
        for _ in range(5):
            s._on_packet(_packet())

        s.flush_observation()

        entry = obs.snapshot()["loss"]["per_stage"][STAGE_INPUT_QUEUE]
        assert entry["received"] == 2
        assert entry["app_dropped"] == 3
        assert entry["kernel_dropped"] == 0
        assert entry["app_loss_ratio"] == pytest.approx(3 / 2)
    finally:
        loop.close()


def test_flush_never_loses_counted_packets():
    """스왑 중 도착한 패킷이 유실되지 않는다 — 계측이 과대 계상되지도 않는다."""
    obs = ObservationService(sensor_id="s")
    loop = asyncio.new_event_loop()
    try:
        s = _sniffer(obs, loop)
        s._on_packet(_packet())
        s.flush_observation()
        s._on_packet(_packet())
        s.flush_observation()

        assert obs.snapshot()["stages"][STAGE_CAPTURE]["received"] == 2
    finally:
        loop.close()


def test_sniffer_exposes_kernel_probe():
    """스니퍼는 커널 drop 측정기를 노출한다 (미지원이면 false 로 말해야 한다)."""
    obs = ObservationService(sensor_id="s")
    loop = asyncio.new_event_loop()
    try:
        s = _sniffer(obs, loop)
        status = s.kernel_probe.status()
        assert status["source"] == "/proc/net/softnet_stat"
        assert isinstance(status["available"], bool)
    finally:
        loop.close()
