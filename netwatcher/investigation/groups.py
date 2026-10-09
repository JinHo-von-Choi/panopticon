"""원본 경보를 보존하며 같은 시간대의 반복 경보를 조회한다."""
from datetime import datetime, timedelta, timezone

# 임시 출발 포트·flow_id가 달라도 같은 서비스의 반복을 볼 수 있다.
SCOPE_FIELDS = ('src_ip', 'dest_ip', 'src_mac', 'dest_mac', 'src_macs', 'dest_macs',
                'proto', 'dest_port')
RULE_FIELDS = ('signature_id', 'gid', 'rev', 'severity', 'action')
SCOPE_SQL = ' AND '.join(
    [f"r.record->'{key}' IS NOT DISTINCT FROM $5::jsonb->'{key}'" for key in SCOPE_FIELDS] +
    [f"r.record->'details'->'{key}' IS NOT DISTINCT FROM $5::jsonb->'details'->'{key}'"
     for key in RULE_FIELDS])


class EventGroups:
    def __init__(self, db):
        self.db = db

    async def get(self, event_id, *, offset=0, limit=50, previous=False, days=30):
        async with self.db.pool.acquire() as conn, conn.transaction(isolation='repeatable_read', readonly=True):
            exists = await conn.fetchval('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', event_id)
            if not exists:
                return None
            anchor = await conn.fetchrow('SELECT * FROM eve_records WHERE event_id=$1', event_id)
            if anchor is None or anchor['event_type'] != 'alert' or anchor['observed_at'] is None:
                return {'available': False, 'reason': 'eve_alert_required'}
            record = anchor['record']
            observed = anchor['observed_at']
            observed = observed if isinstance(observed, datetime) else datetime.fromisoformat(observed)
            start = observed.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
            end = start + timedelta(hours=1)
            # 출발지·목적지가 빠진 경보는 다른 미확인 장치와 묶지 않는다.
            identity = bool(record.get('src_ip') and record.get('dest_ip'))
            if previous:
                if not identity:
                    return {'available':False,'reason':'addresses_required'}
                end = start
                start = end-timedelta(days=days)
            where = (f'r.sensor_id=$1 AND r.source_id=$2 AND r.observed_at>=$3 AND r.observed_at<$4 '
                     f"AND r.event_type='alert' AND {SCOPE_SQL}")
            if not identity:
                where += ' AND r.event_id=$6'
            args = [anchor['sensor_id'], anchor['source_id'], start.isoformat(), end.isoformat(), record]
            if not identity:
                args.append(event_id)
            joins = '''FROM eve_records r JOIN events e ON e.id=r.event_id
                LEFT JOIN case_workflows w ON w.event_id=e.id
                LEFT JOIN business_reviews b ON b.event_id=e.id'''
            projection = 'b.decision AS recorded_decision,b.reviewed_at'
            if previous:
                joins += ' LEFT JOIN case_history h ON h.event_id=w.event_id AND h.version=w.version'
                projection += ',b.note AS review_note,b.actor AS reviewer,b.expires_at,b.scope->\'asset_context\' AS recorded_asset_context,h.note AS handover_note'
            summary = await conn.fetchrow(f'''SELECT count(*) AS total,
                count(*) FILTER(WHERE b.event_id IS NULL) AS without_review,
                count(*) FILTER(WHERE COALESCE(w.status,'open')!='closed') AS not_closed,
                min(r.observed_at) AS first_seen,max(r.observed_at) AS last_seen
                {joins} WHERE {where}''', *args)
            rows = await conn.fetch(f'''SELECT e.id,e.timestamp,e.title,e.severity,
                COALESCE(w.owner,'') AS owner,COALESCE(w.status,'open') AS status,
                {projection}
                {joins} WHERE {where} ORDER BY r.observed_at DESC,e.id DESC
                LIMIT ${len(args)+1} OFFSET ${len(args)+2}''', *args, limit, offset)
            snapshot = await conn.fetchval('SELECT transaction_timestamp()')
        def stamp(value):
            return value.isoformat() if hasattr(value, 'isoformat') else value
        return {'available': True, 'view':'previous_same_scope' if previous else 'same_hour', 'window': {'start': start.isoformat(), 'end': end.isoformat(),
                    'end_exclusive': True}, 'snapshot_at': stamp(snapshot),
                'scope': {key: record.get(key) for key in SCOPE_FIELDS} |
                    {'sensor_id': anchor['sensor_id'], 'source_id': anchor['source_id'],
                     'rule': {key: record.get('details', {}).get(key) for key in RULE_FIELDS}},
                'addresses_complete': identity, 'total': summary['total'],
                'without_review': summary['without_review'], 'not_closed': summary['not_closed'],
                'first_seen': stamp(summary['first_seen']), 'last_seen': stamp(summary['last_seen']),
                'offset': offset, 'limit': limit,
                'events': [{key: stamp(value) for key, value in dict(row).items()} for row in rows]}

    async def list(self, start, end, *, offset=0, limit=50):
        from netwatcher.investigation.reviews import ReviewConflict
        key_fields = ','.join(f"'{key}',r.record->'{key}'" for key in SCOPE_FIELDS)
        rule_fields = ','.join(f"'{key}',r.record->'details'->'{key}'" for key in RULE_FIELDS)
        key = f'''jsonb_build_object('sensor_id',r.sensor_id,'source_id',r.source_id,{key_fields},
            'rule',jsonb_build_object({rule_fields}),'unidentified_record',
            CASE WHEN r.record->>'src_ip' IS NULL OR r.record->>'dest_ip' IS NULL
                 THEN r.ingest_id::text ELSE NULL END)'''
        async with self.db.pool.acquire() as conn, conn.transaction(isolation='repeatable_read', readonly=True):
            count = await conn.fetchval('''SELECT count(*) FROM eve_records r JOIN events e ON e.id=r.event_id
                WHERE r.event_type='alert' AND r.observed_at>=$1 AND r.observed_at<$2''',
                start.isoformat(), end.isoformat())
            if count > 50000:
                raise ReviewConflict('group_period_capacity')
            result = await conn.fetchrow(f'''WITH grouped AS (
                SELECT {key} AS scope,
                    date_trunc('hour',r.observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS window_start,
                    count(*) AS occurrences,
                    count(*) FILTER(WHERE b.event_id IS NULL) AS without_review,
                    count(*) FILTER(WHERE COALESCE(w.status,'open')!='closed') AS not_closed,
                    min(r.observed_at) AS first_seen,max(r.observed_at) AS last_seen,
                    (array_agg(e.id ORDER BY r.observed_at DESC,e.id DESC))[1] AS representative_id,
                    (array_agg(e.title ORDER BY r.observed_at DESC,e.id DESC))[1] AS title,
                    (array_agg(e.severity ORDER BY r.observed_at DESC,e.id DESC))[1] AS severity
                FROM eve_records r JOIN events e ON e.id=r.event_id
                LEFT JOIN business_reviews b ON b.event_id=e.id
                LEFT JOIN case_workflows w ON w.event_id=e.id
                WHERE r.event_type='alert' AND r.observed_at>=$1 AND r.observed_at<$2
                GROUP BY 1,2
            ), page AS (
                SELECT * FROM grouped ORDER BY
                    CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,
                    without_review DESC,not_closed DESC,last_seen DESC,representative_id DESC
                LIMIT $3 OFFSET $4
            ) SELECT (SELECT count(*) FROM grouped) AS total,
                COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY
                    CASE page.severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,
                    page.without_review DESC,page.not_closed DESC,page.last_seen DESC,page.representative_id DESC) FROM page),'[]'::jsonb) AS groups''',
                start.isoformat(), end.isoformat(), limit, offset)
            snapshot = await conn.fetchval('SELECT transaction_timestamp()')
        return {'period': {'start': start.isoformat(), 'end': end.isoformat(), 'end_exclusive': True},
                'snapshot_at': snapshot.isoformat() if isinstance(snapshot, datetime) else snapshot,
                'total': result['total'], 'stored_alerts': count, 'offset': offset, 'limit': limit,
                'groups': result['groups']}
