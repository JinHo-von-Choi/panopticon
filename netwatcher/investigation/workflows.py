"""사건 담당자·처리 상태와 수정할 수 없는 인계 기록."""
from datetime import datetime, timezone
from uuid import UUID

from netwatcher.investigation.reviews import ReviewConflict

MAX_HISTORY = 1000


def serialize(row):
    result = dict(row)
    value = result['updated_at']
    result['updated_at'] = (value if isinstance(value, datetime) else datetime.fromisoformat(str(value))).astimezone(timezone.utc).isoformat()
    for key in ('owner_id', 'actor_id'):
        if result.get(key) is not None:
            result[key] = str(result[key])
    return result


class CaseWorkflows:
    def __init__(self, db):
        self.db = db

    async def raw(self, event_id):
        row = await self.db.pool.fetchrow('''SELECT w.*,h.note,u.enabled AS owner_enabled
            FROM case_workflows w LEFT JOIN case_history h ON h.event_id=w.event_id AND h.version=w.version
            LEFT JOIN user_accounts u ON u.id=w.owner_id WHERE w.event_id=$1''', event_id)
        return serialize(row) if row else None

    async def get(self, event_id, before_version=None):
        async with self.db.pool.acquire() as conn, conn.transaction(isolation="repeatable_read", readonly=True):
            return await self._read(conn, event_id, before_version)

    async def _read(self, conn, event_id, before_version=None):
        if not await conn.fetchval('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', event_id):
            raise ReviewConflict('event_missing')
        current = await conn.fetchrow('''SELECT w.*,u.enabled AS owner_enabled FROM case_workflows w
            LEFT JOIN user_accounts u ON u.id=w.owner_id WHERE w.event_id=$1''', event_id)
        rows = await conn.fetch('''SELECT * FROM case_history WHERE event_id=$1
            AND ($2::bigint IS NULL OR version<$2) ORDER BY version DESC LIMIT 51''',
            event_id, before_version)
        return {'case': serialize(current) if current else {'event_id': event_id, 'version': 0,
                'owner': '', 'owner_id': None, 'owner_enabled': None, 'status': 'open',
                'actor': None, 'actor_id': None, 'updated_at': None},
                'history': [serialize(row) for row in rows[:50]],
                'next_before_version': rows[49]['version'] if len(rows) > 50 else None}

    async def save(self, event_id, body, actor, actor_id=None, actor_version=None):
        now = datetime.now(timezone.utc)
        async with self.db.pool.acquire() as conn, conn.transaction():
            if not await conn.fetchval('SELECT id FROM events WHERE id=$1 FOR UPDATE', event_id):
                raise ReviewConflict('event_missing')
            current = await conn.fetchrow('SELECT * FROM case_workflows WHERE event_id=$1', event_id)
            version = current['version'] if current else 0
            if version != body.expected_version:
                raise ReviewConflict('version_changed')
            if version >= MAX_HISTORY:
                raise ReviewConflict('history_capacity')
            owner_id = getattr(body, 'owner_id', None)
            owner = body.owner
            if (current is not None and 'owner_id' not in getattr(body, 'model_fields_set', {'owner_id'})
                    and owner == current['owner']):
                owner_id = current['owner_id']
            if owner_id is not None:
                account = await conn.fetchrow('SELECT username,enabled FROM user_accounts WHERE id=$1 FOR SHARE', owner_id)
                if account is None:
                    raise ReviewConflict('owner_account_missing')
                if not account['enabled'] and (current is None or current['owner_id'] != owner_id):
                    raise ReviewConflict('owner_account_disabled')
                if owner and owner != account['username']:
                    raise ReviewConflict('owner_account_mismatch')
                owner = account['username']
            if actor_id is not None:
                actor_id = UUID(str(actor_id))
                author = await conn.fetchrow('SELECT username,enabled,role,version FROM user_accounts WHERE id=$1 FOR SHARE', actor_id)
                if (author is None or not author['enabled'] or author['role'] != 'admin'
                        or author['username'] != actor or author['version'] != actor_version):
                    raise ReviewConflict('actor_account_changed')
            await conn.execute('''INSERT INTO case_workflows(event_id,version,owner,status,actor,updated_at,owner_id,actor_id)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(event_id) DO UPDATE SET
                version=EXCLUDED.version,owner=EXCLUDED.owner,status=EXCLUDED.status,
                actor=EXCLUDED.actor,updated_at=EXCLUDED.updated_at,
                owner_id=EXCLUDED.owner_id,actor_id=EXCLUDED.actor_id''',
                event_id, version + 1, owner, body.status, actor[:255], now, owner_id, actor_id)
            await conn.execute('''INSERT INTO case_history(event_id,version,owner,status,note,actor,updated_at,owner_id,actor_id)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)''', event_id, version + 1, owner,
                body.status, body.note, actor[:255], now, owner_id, actor_id)
            result = await self._read(conn, event_id)
        return result
