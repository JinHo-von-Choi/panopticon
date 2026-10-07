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
