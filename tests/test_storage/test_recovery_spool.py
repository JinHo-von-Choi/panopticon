"""Recovery journals bound disk use and retain original UUID receipts."""
import json
import os
import uuid
from pathlib import Path
import pytest
from netwatcher.storage.recovery_spool import RecoverySpool


def test_restart_preserves_payload_and_ack(tmp_path):
    key = uuid.uuid4()
    payload = [{'ingest_id': str(uuid.uuid4()), 'title': 'Evidence', 'ports': {22, 445}}]
    spool = RecoverySpool(tmp_path)
    assert spool.put(key, payload)
    assert os.stat(tmp_path / (key.hex + '.json')).st_mode & 0o777 == 0o600
    restart = RecoverySpool(tmp_path)
    name, frame = restart.next()
    assert frame['payload'][0]['ingest_id'] == payload[0]['ingest_id']
    assert frame['payload'][0]['ports'] == [22,445]
    restart.ack(name, recovered=1)
    assert restart.status()['files'] == 0
    assert restart.status()['recovered_records'] == 1


def test_limits_refuse_without_evicting_pending(tmp_path):
    spool = RecoverySpool(tmp_path, max_files=1, max_bytes=1024)
    key = uuid.uuid4()
    assert spool.put(key, {'data': 'original'})
    assert spool.put(key, {'data': 'different'})  # immutable receipt wins
    assert not spool.put(uuid.uuid4(), {'data': 'overflow'})
    assert spool.next()[1]['payload']['data'] == 'original'
    assert spool.status()['refused_records'] == 1


def test_expired_records_reported_and_removed(tmp_path):
    spool = RecoverySpool(tmp_path, ttl=1)
    key = uuid.uuid4(); spool.put(key, {'data': 'old'}, count=3)
    path = tmp_path / (key.hex+'.json')
    frame = json.loads(path.read_text()); frame['created_at'] -= 10
    path.write_text(json.dumps(frame))
    assert spool.next() is None
    assert spool.status()['expired_records'] == 3
    assert not path.exists()


def test_corrupt_records_preserved_and_recovery_fails_closed(tmp_path):
    path = tmp_path / (uuid.uuid4().hex+'.json');path.write_text('{broken')
    spool = RecoverySpool(tmp_path)
    assert spool.next() is None
    assert spool.status()['state'] == 'invalid'
    assert path.exists()
    assert not spool.put(uuid.uuid4(), {'data': 'new'})


@pytest.mark.asyncio
async def test_db_commit_reply_loss_then_restart_has_one_event(db, tmp_path):
    from unittest.mock import AsyncMock
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.detection.models import Alert, Severity
    from netwatcher.storage.repositories import EventRepository
    from netwatcher.utils.config import Config
    config = Config({'storage': {'recovery_spool': {'enabled': True, 'directory': str(tmp_path)}}})
    repo = EventRepository(db)
    failed = AsyncMock()
    async def committed_without_reply(**kwargs):
        await repo.insert(**kwargs)
        raise ConnectionError('Commit reply lost')
    failed.insert.side_effect = committed_without_reply
    dispatcher = AlertDispatcher(config, failed)
    await dispatcher._process_alert(Alert(engine='port_scan', severity=Severity.WARNING, title='Scan', source_ip='192.0.2.1'))
    assert dispatcher._recovery_spool.status()['files'] == 1
    assert await db.pool.fetchval('SELECT count(*) FROM events') == 1
    restart = AlertDispatcher(config, repo)
    await restart.recover_spool_once()
    assert await db.pool.fetchval('SELECT count(*) FROM events') == 1
    assert restart._recovery_spool.status()['files'] == 0
    assert restart._recovery_spool.status()['recovered_records'] == 1
