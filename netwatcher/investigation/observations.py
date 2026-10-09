"""전체 보존 EVE 기록의 주소·통신 상대 첫 관측을 집계한다."""
from datetime import datetime,timedelta,timezone
from netwatcher.investigation.reviews import ReviewConflict

MAX_OBSERVATION_RECORDS=250000


class EveObservations:
    def __init__(self,db):
        self.db=db

    async def get(self,kind='addresses',*,hours=24,offset=0,limit=50):
        async with self.db.pool.acquire() as conn,conn.transaction(isolation='repeatable_read',readonly=True):
            snapshot=await conn.fetchval('SELECT transaction_timestamp()')
            now=snapshot if isinstance(snapshot,datetime) else datetime.fromisoformat(snapshot)
            now=now.astimezone(timezone.utc);since=now-timedelta(hours=hours)
            baseline=await conn.fetchrow('''SELECT count(*) AS retained_records,min(observed_at) AS oldest_observed_at,
                max(observed_at) AS newest_observed_at,count(*) FILTER(WHERE observed_at>transaction_timestamp()) AS future_records
                FROM eve_records WHERE event_type IN ('alert','flow','dns','tls') AND observed_at IS NOT NULL''')
            if baseline['retained_records']>MAX_OBSERVATION_RECORDS:
                raise ReviewConflict('observation_history_capacity')
            if kind=='addresses':
                scope="jsonb_build_object('sensor_id',r.sensor_id,'source_id',r.source_id,'ip',endpoint.ip,'mac',endpoint.mac)"
                extra="CROSS JOIN LATERAL (VALUES(r.record->>'src_ip',r.record->>'src_mac'),(r.record->>'dest_ip',r.record->>'dest_mac')) endpoint(ip,mac)"
                valid="endpoint.ip IS NOT NULL"
            else:
                fields=('src_ip','src_mac','dest_ip','dest_mac','proto','dest_port')
                scope="jsonb_build_object('sensor_id',r.sensor_id,'source_id',r.source_id,"+','.join(f"'{key}',r.record->'{key}'" for key in fields)+')'
                extra='';valid="r.record->>'src_ip' IS NOT NULL AND r.record->>'dest_ip' IS NOT NULL"
            result=await conn.fetchrow(f'''WITH grouped AS (
                SELECT {scope} AS scope,min(r.observed_at) AS first_seen,max(r.observed_at) AS last_seen,
                    count(*) AS observations,max(e.id) AS related_event_id
                FROM eve_records r {extra} LEFT JOIN events e ON e.id=r.event_id
                WHERE r.event_type IN ('alert','flow','dns','tls') AND r.observed_at IS NOT NULL AND {valid}
                GROUP BY 1
            ), recent AS (
                SELECT * FROM grouped WHERE first_seen>=$1 AND first_seen<=$2
            ), page AS (
                SELECT * FROM recent ORDER BY first_seen DESC,scope::text LIMIT $3 OFFSET $4
            ) SELECT (SELECT count(*) FROM recent) AS total,
                COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY page.first_seen DESC,page.scope::text) FROM page),'[]'::jsonb) AS observations''',
                since.isoformat(),now.isoformat(),limit,offset)
        def stamp(value):return value.isoformat() if hasattr(value,'isoformat') else value
        return {'kind':kind,'scope':'all_retained_eve_records','identity_confirmed':False,
                'snapshot_at':now.isoformat(),'period':{'start':since.isoformat(),'end':now.isoformat()},
                'baseline':{key:stamp(value) for key,value in dict(baseline).items()},
                'total':result['total'],'offset':offset,'limit':limit,'observations':result['observations']}
