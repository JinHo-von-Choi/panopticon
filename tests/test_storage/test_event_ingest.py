import uuid
import asyncio
from unittest.mock import AsyncMock

import asyncpg
import pytest

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.config import Config


@pytest.mark.asyncio
async def test_batch_maps_ids_without_order_assumption_and_retries_same_rows(event_repo):
    events = [{'engine': 'test', 'title': str(i), 'ingest_id': str(uuid.uuid4())} for i in range(100)]
    first = await event_repo.insert_batch_mapped(events)
    second = await event_repo.insert_batch_mapped(list(reversed(events)))
    assert first == second
    assert len(first) == 100
    assert len(await event_repo.list_recent(limit=200)) == 100
    for event in events:
        row = await event_repo.get_by_id(first[uuid.UUID(event['ingest_id'])])
        assert row['title'] == event['title']


@pytest.mark.asyncio
async def test_entire_multirow_statement_rolls_back_on_one_invalid_row(event_repo):
    with pytest.raises(asyncpg.PostgresError):
        await event_repo.insert_batch_mapped([
            {'engine': 'test', 'title': 'valid'},
            {'engine': 'test', 'title': 'invalid', 'source_ip': 'invalid-ip'},
        ])
    assert await event_repo.list_recent() == []
    assert await event_repo._db.pool.fetchval('SELECT count(*) FROM event_ingest') == 0


@pytest.mark.asyncio
async def test_concurrent_retry_returns_same_event_id(event_repo):
    ingest_id = uuid.uuid4()
    ids = await asyncio.gather(*[event_repo.insert(engine='test', severity='WARNING', title='same', ingest_id=ingest_id) for _ in range(3)])
    assert len(set(ids)) == 1
    assert len(await event_repo.list_recent()) == 1


@pytest.mark.asyncio
async def test_dispatcher_lost_commit_response_recovers_id_and_notifies_once(event_repo):
    original = event_repo.insert
    calls = []
    async def uncertain(**kwargs):
        result = await original(**kwargs)
        calls.append(kwargs['ingest_id'])
        if len(calls) == 1:
            raise ConnectionError('ack lost')
        return result
    event_repo.insert = uncertain
    dispatcher = AlertDispatcher(Config({}), event_repo)
    dispatcher._send_webhooks = AsyncMock()
    alert = Alert(engine='test', severity=Severity.CRITICAL, title='ack loss')
    await dispatcher._process_alert(alert)
    assert len(calls) == 2 and calls[0] == calls[1]
    assert len(await event_repo.list_recent()) == 1
    dispatcher._send_webhooks.assert_awaited_once()


@pytest.mark.asyncio
async def test_unconfirmed_commit_does_not_trigger_notification_or_evidence():
    repository = AsyncMock()
    repository.insert.side_effect = ConnectionError()
    dispatcher = AlertDispatcher(Config({}), repository)
    dispatcher._send_webhooks = AsyncMock()
    await dispatcher._process_alert(Alert(engine='test', severity=Severity.CRITICAL, title='offline'))
    assert repository.insert.await_count == 2
    dispatcher._send_webhooks.assert_not_awaited()


@pytest.mark.asyncio
async def test_live_dispatcher_commits_unique_burst_in_one_batch_with_correct_ui_ids(event_repo):
    import json
    original = event_repo.insert_batch_mapped
    calls = []
    async def tracked(events):
        calls.append(len(events))
        return await original(events)
    event_repo.insert_batch_mapped = tracked
    cfg = Config({'alerts': {'batch': {'enabled': True, 'size': 100},
        'rate_limit': {'max_per_key': 1000}}})
    dispatcher = AlertDispatcher(cfg, event_repo)
    subscriber = dispatcher.subscribe_ws()
    for i in range(100):
        dispatcher.enqueue(Alert(engine='burst', severity=Severity.WARNING, title=f'event {i}', source_ip=f'192.0.2.{i+1}'))
    await dispatcher.start()
    await dispatcher.stop(drain_timeout=5)
    assert calls == [100]
    rows = await event_repo.list_recent(limit=200)
    assert len(rows) == 100
    expected = {row['title']: row['id'] for row in rows}
    messages = [json.loads(subscriber.get_nowait()) for _ in range(100)]
    assert {message['title']: message['id'] for message in messages} == expected


@pytest.mark.asyncio
async def test_batching_preserves_first_representative_and_severity_escalation(event_repo):
    cfg = Config({'alerts': {'batch': {'enabled': True, 'size': 100}, 'aggregation': {'enabled': True}}})
    dispatcher = AlertDispatcher(cfg, event_repo)
    for severity in (Severity.WARNING, Severity.WARNING, Severity.CRITICAL, Severity.CRITICAL):
        dispatcher.enqueue(Alert(engine='scan', severity=severity, title='scan', source_ip='192.0.2.1'))
    await dispatcher.start()
    await dispatcher.stop(drain_timeout=5)
    rows = await event_repo.list_recent()
    assert len(rows) == 2
    assert {row['severity']: row['metadata']['aggregation']['count'] for row in rows} == {'WARNING': 2, 'CRITICAL': 2}


@pytest.mark.asyncio
async def test_unresponsive_webhook_does_not_delay_committed_burst(event_repo):
    cfg = Config({'alerts': {'batch': {'enabled': True}, 'channels': {
        'telegram': {'enabled': True, 'bot_token': 'isolated-test', 'chat_id': 'isolated-test'}}}})
    dispatcher = AlertDispatcher(cfg, event_repo)
    entered = asyncio.Event()
    async def blocked(alert):
        entered.set()
        await asyncio.sleep(10)
    dispatcher._notification_writer.send = blocked  # 실제 외부 전송을 하지 않는다.
    for i in range(100):
        dispatcher.enqueue(Alert(engine='burst', severity=Severity.WARNING, title=f'event {i}', source_ip=f'192.0.2.{i+1}'))
    await dispatcher.start()
    try:
        async with asyncio.timeout(2):
            await dispatcher._queue.join()
        assert len(await event_repo.list_recent(limit=200)) == 100
        assert dispatcher._notification_writer.queue.qsize() > 0
    finally:
        await dispatcher.stop(drain_timeout=.1)


@pytest.mark.asyncio
async def test_expired_queued_alert_is_visible_and_fresh_alert_still_commits(event_repo):
    import time
    dispatcher = AlertDispatcher(Config({'alerts': {'max_queue_age_seconds': 1, 'batch': {'enabled': True}}}), event_repo)
    dispatcher.enqueue(Alert(engine='test', severity=Severity.WARNING, title='expired'))
    dispatcher._enqueue_times[0] = time.monotonic() - 2
    dispatcher.enqueue(Alert(engine='test', severity=Severity.WARNING, title='fresh'))
    await dispatcher.start()
    await dispatcher.stop()
    rows = await event_repo.list_recent()
    assert [row['title'] for row in rows] == ['fresh']
    assert dispatcher._queue_expired == 1
