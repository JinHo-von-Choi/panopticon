"""알림 디스패처 영속성 계약 (PR 06).

종료 경로에서 탐지 결과를 잃지 않아야 한다. 이전 구현은 ``stop()`` 이 소비자를
즉시 cancel 해서, 큐(maxsize 10000)에 쌓인 알림을 **DB 미저장·미브로드캐스트·
미차단** 상태로 버렸다. 버스트 중 종료하면 그만큼의 탐지 결과가 사라진다.

이 테스트는 다음을 고정한다.

1. 종료 전에 큐가 배 emptying된다
2. 배 emptying이 끝나면 소비자가 멈춘다
3. 배 emptying이 불가능하면(시간 초과) 버린 개수를 경고로 남긴다
4. 소비자가 시작되지 않은 상태에서 멈추면 큐를 비우고 경고한다
5. 처리 중 예외가 발생해도 ``task_done()`` 이 호출되어 배 emptying이 막히지 않는다
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.config import Config


def _alert(title: str = "a") -> Alert:
    return Alert(
        engine="port_scan",
        severity=Severity.WARNING,
        title=title,
        description="d",
        source_ip="10.0.0.9",
    )


def _config(drain: float = 5.0) -> Config:
    return Config({
        "alerts": {
            "rate_limit": {"window_seconds": 300, "max_per_key": 100000},
            "channels": {},
            "drain_timeout_seconds": drain,
        },
    })


def _dispatcher(repo: MagicMock) -> AlertDispatcher:
    repo = MagicMock()
    repo.insert = AsyncMock(return_value=1)
    d = AlertDispatcher(
        config=_config(),
        event_repo=repo,
        device_repo=None,
        correlator=None,
        pcap_writer=None,
        block_manager=None,
    )
    return d


# ------------------------------------------------------------------
# 배 emptiness
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pending_alerts_are_processed_before_stop():
    d = _dispatcher(MagicMock())
    processed: list[str] = []

    async def fake_process(alert: Alert) -> None:
        await asyncio.sleep(0.01)
        processed.append(alert.title)

    d._process_alert = fake_process  # type: ignore[assignment]
    await d.start()

    for i in range(25):
        d.enqueue(_alert(f"a{i}"))

    await d.stop(drain_timeout=5.0)

    assert len(processed) == 25, "종료 전에 큐가 비워지지 않았다"
    assert d._queue.qsize() == 0


@pytest.mark.asyncio
async def test_events_are_persisted_before_shutdown_completes():
    d = _dispatcher(MagicMock())
    d._process_alert = AsyncMock()  # type: ignore[assignment]
    await d.start()

    for i in range(10):
        d.enqueue(_alert(f"a{i}"))

    await d.stop(drain_timeout=5.0)

    assert d._process_alert.await_count == 10  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_consumer_task_is_cancelled_after_drain():
    d = _dispatcher(MagicMock())
    d._process_alert = AsyncMock()  # type: ignore[assignment]
    await d.start()
    task = d._task
    assert task is not None

    d.enqueue(_alert("x"))
    await d.stop(drain_timeout=5.0)

    assert task.cancelled() or task.done()


# ------------------------------------------------------------------
# 배 emptiness 실패
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_drain_timeout_does_not_hang():
    """처리 중hung인 알림이 있어도 stop() 이 무한정 기다리지 않는다."""
    d = _dispatcher(MagicMock())
    release = asyncio.Event()

    async def blocking(_alert_: Alert) -> None:
        await release.wait()

    d._process_alert = blocking  # type: ignore[assignment]
    await d.start()
    for i in range(5):
        d.enqueue(_alert(f"a{i}"))

    await asyncio.wait_for(d.stop(drain_timeout=0.1), timeout=2.0)
    assert d._task is None or d._task.done()


@pytest.mark.asyncio
async def test_unprocessed_alerts_are_reported_not_silently_dropped(caplog):
    d = _dispatcher(MagicMock())
    release = asyncio.Event()

    async def blocking(_alert_: Alert) -> None:
        await release.wait()

    d._process_alert = blocking  # type: ignore[assignment]
    await d.start()
    for i in range(7):
        d.enqueue(_alert(f"a{i}"))

    with caplog.at_level("WARNING"):
        await asyncio.wait_for(d.stop(drain_timeout=0.1), timeout=2.0)

    text = caplog.text
    assert "will not be persisted" in text or "Draining" in text


@pytest.mark.asyncio
async def test_stop_without_consumer_drains_queue():
    d = _dispatcher(MagicMock())
    for i in range(4):
        d.enqueue(_alert(f"a{i}"))
    assert d._task is None

    await d.stop(drain_timeout=1.0)
    assert d._queue.qsize() == 0


@pytest.mark.asyncio
async def test_stop_is_safe_to_call_twice():
    d = _dispatcher(MagicMock())
    d._process_alert = AsyncMock()  # type: ignore[assignment]
    await d.start()
    d.enqueue(_alert("a"))
    await d.stop(drain_timeout=1.0)
    await d.stop(drain_timeout=1.0)  # 예외 없이 종료되어야 한다


@pytest.mark.asyncio
async def test_stop_with_empty_queue_is_immediate():
    d = _dispatcher(MagicMock())
    d._process_alert = AsyncMock()  # type: ignore[assignment]
    await d.start()
    await asyncio.wait_for(d.stop(drain_timeout=5.0), timeout=1.0)


# ------------------------------------------------------------------
# 예처가 배 emptiness를 막지 않는지
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_processing_error_does_not_block_drain():
    """알림 하나가 실패해도 나머지는 처리되어야 한다."""
    d = _dispatcher(MagicMock())
    seen: list[str] = []

    async def flaky(alert: Alert) -> None:
        seen.append(alert.title)
        if alert.title == "boom":
            raise RuntimeError("processing failed")

    d._process_alert = flaky  # type: ignore[assignment]
    await d.start()
    for title in ("a", "boom", "b", "c"):
        d.enqueue(_alert(title))

    await asyncio.wait_for(d.stop(drain_timeout=5.0), timeout=3.0)
    assert seen == ["a", "boom", "b", "c"]


@pytest.mark.asyncio
async def test_task_done_called_even_when_processing_raises():
    d = _dispatcher(MagicMock())

    async def always_fail(_alert_: Alert) -> None:
        raise RuntimeError("nope")

    d._process_alert = always_fail  # type: ignore[assignment]
    await d.start()
    d.enqueue(_alert("x"))
    # join() 이 완료되어야 task_done() 이 호출된 것이다
    await asyncio.wait_for(d._queue.join(), timeout=1.0)
    await d.stop(drain_timeout=1.0)
