"""BatchWriter 테스트: 버퍼 축적, 자동 플러시, 주기적 플러시, stop 플러시."""

from __future__ import annotations

import asyncio

import pytest

from netwatcher.storage.batch_writer import BatchWriter
from netwatcher.storage.repositories import EventRepository


def _make_event(n: int = 0) -> dict:
    """테스트용 이벤트 dict를 생성한다."""
    return {
        "engine": "test_engine",
        "severity": "WARNING",
        "title": f"Test Event {n}",
        "description": f"desc {n}",
        "source_ip": "10.0.0.1",
    }


@pytest.mark.asyncio
async def test_enqueue_accumulates(event_repo: EventRepository):
    """batch_size에 도달하지 않으면 DB에 즉시 삽입되지 않는다."""
    writer = BatchWriter(event_repo, batch_size=10, flush_interval_ms=60_000)

    await writer.enqueue(_make_event(1))
    await writer.enqueue(_make_event(2))

    assert writer.pending == 2
    events = await event_repo.list_recent(limit=100)
    assert len(events) == 0


@pytest.mark.asyncio
async def test_auto_flush_on_batch_size(event_repo: EventRepository):
    """batch_size에 도달하면 자동으로 플러시된다."""
    writer = BatchWriter(event_repo, batch_size=3, flush_interval_ms=60_000)

    await writer.enqueue(_make_event(1))
    await writer.enqueue(_make_event(2))
    await writer.enqueue(_make_event(3))

    assert writer.pending == 0
    events = await event_repo.list_recent(limit=100)
    assert len(events) == 3


@pytest.mark.asyncio
async def test_manual_flush(event_repo: EventRepository):
    """수동 flush 호출 시 버퍼의 모든 이벤트가 DB에 삽입된다."""
    writer = BatchWriter(event_repo, batch_size=100, flush_interval_ms=60_000)

    for i in range(5):
        await writer.enqueue(_make_event(i))

    assert writer.pending == 5
    count = await writer.flush()
    assert count == 5
    assert writer.pending == 0

    events = await event_repo.list_recent(limit=100)
    assert len(events) == 5


@pytest.mark.asyncio
async def test_flush_empty_buffer(event_repo: EventRepository):
    """빈 버퍼를 플러시하면 0을 반환한다."""
    writer = BatchWriter(event_repo, batch_size=10, flush_interval_ms=60_000)
    count = await writer.flush()
    assert count == 0


@pytest.mark.asyncio
async def test_periodic_flush(event_repo: EventRepository):
    """주기적 플러시 태스크가 interval 후 자동으로 버퍼를 비운다."""
    writer = BatchWriter(event_repo, batch_size=100, flush_interval_ms=200)
    await writer.start()

    try:
        for i in range(3):
            await writer.enqueue(_make_event(i))

        assert writer.pending == 3
        # 플러시 인터벌 + 여유 시간 대기
        await asyncio.sleep(0.5)

        events = await event_repo.list_recent(limit=100)
        assert len(events) == 3
        assert writer.pending == 0
    finally:
        await writer.stop()


@pytest.mark.asyncio
async def test_stop_flushes_remaining(event_repo: EventRepository):
    """stop() 호출 시 잔여 이벤트가 모두 플러시된다."""
    writer = BatchWriter(event_repo, batch_size=100, flush_interval_ms=60_000)
    await writer.start()

    for i in range(4):
        await writer.enqueue(_make_event(i))

    assert writer.pending == 4
    await writer.stop()

    assert writer.pending == 0
    events = await event_repo.list_recent(limit=100)
    assert len(events) == 4


@pytest.mark.asyncio
async def test_multiple_batch_flushes(event_repo: EventRepository):
    """batch_size를 여러 번 초과하면 각각 플러시된다."""
    writer = BatchWriter(event_repo, batch_size=2, flush_interval_ms=60_000)

    for i in range(7):
        await writer.enqueue(_make_event(i))

    # 2개씩 3번 자동 플러시 = 6개, 나머지 1개는 버퍼에 대기
    assert writer.pending == 1

    count = await writer.flush()
    assert count == 1

    events = await event_repo.list_recent(limit=100)
    assert len(events) == 7
