"""Tests for AlertDispatcher."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.config import Config


def _make_alert(engine="test_engine", severity=Severity.WARNING, title="Test Alert",
                source_ip="192.168.1.100", confidence=0.8):
    return Alert(
        engine=engine,
        severity=severity,
        title=title,
        source_ip=source_ip,
        confidence=confidence,
    )


@pytest.mark.asyncio
async def test_enqueue_and_process(config, event_repo):
    """Alert enqueue -> DB insert should work."""
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )
    await dispatcher.start()
    try:
        alert = _make_alert()
        dispatcher.enqueue(alert)

        # Wait for consumer to process
        await asyncio.sleep(0.3)

        # Verify DB insert
        events = await event_repo.list_recent(limit=10)
        assert len(events) >= 1
        assert events[0]["engine"] == "test_engine"
        assert events[0]["title"] == "Test Alert"
    finally:
        await dispatcher.stop()


@pytest.mark.asyncio
async def test_rate_limiting(config, event_repo):
    """Same rate_limit_key sent 6 times should only store 5."""
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )
    await dispatcher.start()
    try:
        for _ in range(6):
            alert = _make_alert()
            dispatcher.enqueue(alert)

        await asyncio.sleep(0.5)

        events = await event_repo.list_recent(limit=20)
        # Rate limiter default max_per_key=5 with same key
        assert len(events) == 5
    finally:
        await dispatcher.stop()


@pytest.mark.asyncio
async def test_ws_broadcast(config, event_repo):
    """WebSocket subscriber should receive alert message."""
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )
    await dispatcher.start()
    try:
        sub_q = dispatcher.subscribe_ws()
        alert = _make_alert(title="WS Test")
        dispatcher.enqueue(alert)

        await asyncio.sleep(0.3)

        assert not sub_q.empty()
        msg = sub_q.get_nowait()
        assert "WS Test" in msg
    finally:
        dispatcher.unsubscribe_ws(sub_q)
        await dispatcher.stop()


@pytest.mark.asyncio
async def test_queue_full_drops():
    """When queue is full, new alerts should be dropped."""
    config = MagicMock(spec=Config)
    config.section.return_value = {"rate_limit": {"window_seconds": 300, "max_per_key": 100}, "channels": {}}

    event_repo = AsyncMock()
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )
    # Queue is maxsize=10000, fill it up
    original_maxsize = dispatcher._queue.maxsize
    # Replace with tiny queue for testing
    dispatcher._queue = asyncio.Queue(maxsize=3)

    for i in range(5):
        dispatcher.enqueue(_make_alert(title=f"Alert {i}"))

    # Only 3 should be in the queue
    assert dispatcher._queue.qsize() == 3


@pytest.mark.asyncio
async def test_webhook_parallel(config, event_repo):
    """Mock webhook channels should be called in parallel."""
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )

    # Add mock channels
    channels = []
    for i in range(3):
        ch = MagicMock()
        ch.name = f"channel_{i}"
        ch.should_send.return_value = True
        ch.send = AsyncMock(return_value=None)
        channels.append(ch)
    dispatcher._channels = channels

    alert = _make_alert()
    await dispatcher._send_webhooks(alert)

    for ch in channels:
        ch.send.assert_called_once_with(alert)


@pytest.mark.asyncio
async def test_webhook_failure_isolation(config, event_repo):
    """One channel failing should not prevent others from succeeding."""
    dispatcher = AlertDispatcher(
        config=config,
        event_repo=event_repo,
        correlator=None,
    )

    ok_channel = MagicMock()
    ok_channel.name = "ok_channel"
    ok_channel.should_send.return_value = True
    ok_channel.send = AsyncMock(return_value=None)

    fail_channel = MagicMock()
    fail_channel.name = "fail_channel"
    fail_channel.should_send.return_value = True
    fail_channel.send = AsyncMock(side_effect=Exception("Network error"))

    ok_channel2 = MagicMock()
    ok_channel2.name = "ok_channel2"
    ok_channel2.should_send.return_value = True
    ok_channel2.send = AsyncMock(return_value=None)

    dispatcher._channels = [ok_channel, fail_channel, ok_channel2]

    alert = _make_alert()
    # Should not raise
    await dispatcher._send_webhooks(alert)

    ok_channel.send.assert_called_once()
    fail_channel.send.assert_called_once()
    ok_channel2.send.assert_called_once()
