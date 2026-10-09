"""같은 DB 시퀀스에서 먼저 배정한 ID로 사건을 연결한다."""

from uuid import uuid4

import pytest

from netwatcher.storage.repositories import EventRepository

pytestmark = pytest.mark.asyncio


async def test_reserved_batch_links_exact_ids_and_native_sequence_keeps_advancing(db):
    repository = EventRepository(db)
    identities = [uuid4(), uuid4()]
    async with db.pool.acquire() as conn, conn.transaction():
        rows = await conn.fetch("SELECT nextval(pg_get_serial_sequence('events','id')) AS id FROM generate_series(1,2)")
        reserved = dict(zip(identities, [row["id"] for row in rows]))
        events = [{"ingest_id": str(identity), "title": f"Event {index}"}
                  for index, identity in enumerate(identities)]
        saved = await repository.insert_batch_mapped(events, connection=conn, event_ids=reserved)
        assert saved == reserved
        assert await repository.insert_batch_mapped(events, connection=conn, event_ids=reserved) == saved
        native = await repository.insert_batch_mapped([{"title": "Native event"}], connection=conn)
        assert min(native.values()) > max(reserved.values())
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 3
    for index, identity in enumerate(identities):
        assert await db.pool.fetchval("SELECT title FROM events WHERE id=$1", saved[identity]) == f"Event {index}"


@pytest.mark.parametrize("invalid_id", [0, -1, True, "1", 2**63, {}])
async def test_invalid_reserved_id_rejected_before_database_write(db, invalid_id):
    identity = uuid4()
    with pytest.raises(ValueError, match="reserved event IDs"):
        await EventRepository(db).insert_batch_mapped([{"ingest_id": str(identity)}], event_ids={identity: invalid_id})
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 0
    assert await db.pool.fetchval("SELECT count(*) FROM event_ingest") == 0


async def test_shared_or_unrelated_reserved_ids_are_rejected(db):
    first, second, unrelated = uuid4(), uuid4(), uuid4()
    events = [{"ingest_id": str(identity)} for identity in (first, second)]
    for reserved in ({first: 1, second: 1}, {unrelated: 1}):
        with pytest.raises(ValueError, match="reserved event IDs"):
            await EventRepository(db).insert_batch_mapped(events, event_ids=reserved)
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 0
