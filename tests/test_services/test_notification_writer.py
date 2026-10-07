import asyncio
from unittest.mock import AsyncMock

import pytest

from netwatcher.detection.models import Alert, Severity
from netwatcher.services.notification_writer import NotificationWriter


def alert(title='test', severity=Severity.WARNING):
    return Alert(engine='test', severity=severity, title=title)


@pytest.mark.asyncio
async def test_reserved_critical_budget_and_immutable_fifo_payload():
    sent = []
    async def send(item):
        sent.append(item.title)
        return True
    writer = NotificationWriter(send, max_jobs=4)
    first = alert('first')
    assert writer.submit(first)
    first.title = 'changed after enqueue'
    assert writer.submit(alert('second'))
    assert writer.submit(alert('third'))
    assert not writer.submit(alert('full'))
    assert writer.submit(alert('critical', Severity.CRITICAL))
    writer.start()
    await writer.stop(timeout=1)
    assert sent == ['critical', 'first', 'second', 'third']
    assert writer.status()['payload_bytes'] == 0
    assert writer.rejected == 1


@pytest.mark.asyncio
async def test_blocked_remote_channel_is_cancelled_and_byte_budget_is_bounded():
    entered = asyncio.Event()
    async def blocked(item):
        entered.set()
        await asyncio.sleep(10)
    writer = NotificationWriter(blocked, max_jobs=2, max_bytes=2048)
    writer.start()
    assert writer.submit(alert())
    await entered.wait()
    assert not writer.submit(alert('x' * 4096, Severity.CRITICAL))
    await writer.stop(timeout=.03)
    await asyncio.sleep(0)
    assert writer.unconfirmed == 1
    assert writer.bytes == 0


@pytest.mark.asyncio
async def test_failed_delivery_is_visible_without_retrying_uncertain_remote_send():
    send = AsyncMock(return_value=False)
    writer = NotificationWriter(send)
    writer.submit(alert())
    writer.start()
    await writer.stop()
    assert writer.failed == 1
    send.assert_awaited_once()


@pytest.mark.asyncio
async def test_job_budget_includes_inflight_delivery():
    entered = asyncio.Event()
    release = asyncio.Event()
    async def blocked(item):
        entered.set()
        await release.wait()
        return True
    writer = NotificationWriter(blocked, max_jobs=1)
    writer.start()
    assert writer.submit(alert())
    await entered.wait()
    assert not writer.submit(alert('overflow', Severity.CRITICAL))
    assert writer.status()['inflight'] == 1
    release.set()
    await writer.stop()
    assert writer.bytes == 0
