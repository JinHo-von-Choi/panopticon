"""담당자가 등록한 작업 범위와 사건 연결. 탐지 설정은 변경하지 않는다."""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from netwatcher.investigation.reviews import ReviewConflict, event_scope

NAMESPACE = uuid.UUID('cb2a96f5-9d71-48b6-8c52-a17e429f9ba9')
MAX_SCHEDULES = 2000


def identity(body):
    content = body.model_dump(mode='json')
    digest = hashlib.sha256(json.dumps(content,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    return uuid.uuid5(NAMESPACE,digest),digest,content


def serialize(row):
    result = dict(row)
    result['id'] = str(result['id'])
    for key in ('starts_at','ends_at','created_at','revoked_at'):
        value = result.get(key)
        if value is not None:
            value = value if isinstance(value,datetime) else datetime.fromisoformat(str(value))
            result[key] = value.astimezone(timezone.utc).isoformat()
    result.pop('fingerprint',None)
    return result


def matches(schedule,event):
    content = schedule['content']
    scope = event_scope(event)
    observed = datetime.fromisoformat(str(event['timestamp']))
    start = datetime.fromisoformat(str(schedule['starts_at']))
    end = datetime.fromisoformat(str(schedule['ends_at']))
    return (start <= observed < end and content['source_ip'] == scope['source_ip']
            and content['dest_ip'] == scope['dest_ip'] and content['protocol'] == scope['protocol']
            and (content['dest_port'] is None or content['dest_port'] == scope['dest_port'])
            and (content['source_mac'] is None or content['source_mac'] == scope['source_mac']))


class WorkSchedules:
    def __init__(self,db):
        self.db = db

    async def raw(self, schedule_id):
        row = await self.db.pool.fetchrow('SELECT * FROM work_schedules WHERE id=$1',schedule_id)
        return serialize(row) if row else None

    async def batch_state(self,bodies):
        ids = [identity(body)[0] for body in bodies]
        rows = await self.db.pool.fetch('SELECT * FROM work_schedules WHERE id=ANY($1::uuid[]) ORDER BY id',ids)
        return [serialize(row) for row in rows]

    async def create(self,bodies,actor):
        entries = {entry[0]: entry for entry in map(identity,bodies)}
        async with self.db.pool.acquire() as conn,conn.transaction():
            await conn.execute('LOCK TABLE work_schedules IN SHARE ROW EXCLUSIVE MODE')
            await conn.execute("""DELETE FROM work_schedules w WHERE ends_at<NOW()-interval '90 days'
                AND NOT EXISTS(SELECT 1 FROM event_work_links l WHERE l.schedule_id=w.id)""")
            count = await conn.fetchval('SELECT count(*) FROM work_schedules')
            existing = await conn.fetch('SELECT id FROM work_schedules WHERE id=ANY($1::uuid[])',list(entries))
            existing_ids = {row['id'] for row in existing}
            if count+len(set(entries)-existing_ids) > MAX_SCHEDULES:
                raise ReviewConflict('schedule_capacity')
            created = []
            for key,(schedule_id,digest,content) in entries.items():
                if key in existing_ids:
                    continue
                await conn.execute('''INSERT INTO work_schedules(id,fingerprint,content,starts_at,ends_at,actor)
                    VALUES($1,$2,$3,$4,$5,$6)''',schedule_id,digest,content,
                    content['starts_at'],content['ends_at'],actor[:255])
                created.append(str(schedule_id))
        return {'created_ids':created,'existing_count':len(entries)-len(created),
                'duplicate_rows':len(bodies)-len(entries)}

    async def list(self,limit,offset):
        async with self.db.pool.acquire() as conn,conn.transaction(isolation='repeatable_read',readonly=True):
            rows = await conn.fetch('SELECT * FROM work_schedules ORDER BY starts_at DESC,id DESC LIMIT $1 OFFSET $2',limit,offset)
            count = await conn.fetchval('SELECT count(*) FROM work_schedules')
        return {'schedules':[serialize(row) for row in rows],'total':count}

    async def revoke(self,schedule_id,body,actor):
        row = await self.db.pool.fetchrow('''UPDATE work_schedules SET version=version+1,
            revoked_at=NOW(),revoked_by=$3,revocation_note=$4
            WHERE id=$1 AND version=$2 AND revoked_at IS NULL RETURNING *''',
            schedule_id,body.expected_version,actor[:255],body.note)
        if row is None:
            raise ReviewConflict('schedule_version_changed')
        return serialize(row)

    async def for_event(self,event_id,limit=50,offset=0):
        async with self.db.pool.acquire() as conn,conn.transaction(isolation='repeatable_read',readonly=True):
            event = await conn.fetchrow('SELECT * FROM events WHERE id=$1',event_id)
            if event is None:
                raise ReviewConflict('event_missing')
            scope = event_scope(event)
            where = """starts_at<=$1::timestamptz AND ends_at>$1::timestamptz AND revoked_at IS NULL
                AND content->>'source_ip'=$2 AND content->>'dest_ip'=$3 AND content->>'protocol'=$4
                AND (content->>'dest_port' IS NULL OR content->>'dest_port'=$5)
                AND (content->>'source_mac' IS NULL OR content->>'source_mac'=$6)"""
            args = [event['timestamp'],scope['source_ip'],scope['dest_ip'],scope['protocol'],
                    str(scope['dest_port']) if scope['dest_port'] is not None else None,scope['source_mac']]
            rows = await conn.fetch('SELECT * FROM work_schedules WHERE '+where+
                ' ORDER BY created_at DESC,id DESC LIMIT $7 OFFSET $8',*args,limit,offset)
            count = await conn.fetchval('SELECT count(*) FROM work_schedules WHERE '+where,*args)
            link = await conn.fetchrow('SELECT * FROM event_work_links WHERE event_id=$1',event_id)
            linked = await conn.fetchrow('SELECT * FROM work_schedules WHERE id=$1',link['schedule_id']) if link else None
        current = None
        if link:
            current = {'version':link['version'],'schedule':serialize(linked),'actor':link['actor'],
                       'state':'revoked' if linked['revoked_at'] else ('matched' if matches(linked,event) else 'scope_changed')}
        return {'current':current,'matches':[serialize(row) for row in rows],'total_matches':count}

    async def link(self,event_id,schedule_id,expected_version,actor):
        async with self.db.pool.acquire() as conn,conn.transaction():
            event = await conn.fetchrow('SELECT * FROM events WHERE id=$1 FOR UPDATE',event_id)
            if event is None:
                raise ReviewConflict('event_missing')
            schedule = await conn.fetchrow('SELECT * FROM work_schedules WHERE id=$1 FOR SHARE',schedule_id)
            if schedule is None or schedule['revoked_at'] or not matches(schedule,event):
                raise ReviewConflict('schedule_scope_mismatch')
            row = await conn.fetchrow('''INSERT INTO event_work_links(event_id,schedule_id,version,actor)
                SELECT $1,$2,1,$4 WHERE $3=0 OR EXISTS(SELECT 1 FROM event_work_links WHERE event_id=$1)
                ON CONFLICT(event_id) DO UPDATE SET schedule_id=$2,version=event_work_links.version+1,
                    actor=$4,linked_at=NOW() WHERE event_work_links.version=$3 RETURNING version''',
                event_id,schedule_id,expected_version,actor[:255])
            if row is None:
                raise ReviewConflict('version_changed')
        return await self.for_event(event_id)
