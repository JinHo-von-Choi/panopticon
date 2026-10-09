"""보존 사건의 처리 상태와 판정 기한을 일관된 시점에서 조회한다."""
from datetime import datetime
from netwatcher.investigation.reviews import BusinessReviews, ReviewConflict

MAX_RECHECK_REVIEWS = 1000
PREDICATES = {
    'unclosed': "COALESCE(w.status,'open')!='closed'",
    'unassigned': "COALESCE(w.status,'open')!='closed' AND COALESCE(w.owner,'')=''",
    'unreviewed': "COALESCE(w.status,'open')!='closed' AND b.event_id IS NULL",
    'expired': "b.decision IN ('expected_backup','approved_maintenance') AND b.expires_at<=transaction_timestamp()",
}
JOINS = '''FROM events e LEFT JOIN case_workflows w ON w.event_id=e.id
           LEFT JOIN business_reviews b ON b.event_id=e.id'''


class InvestigationPriorities:
    def __init__(self, db, *, proposals_available=False, proposal_sensor_id=None):
        self.db = db
        self.proposals_available = proposals_available
        self.proposal_sensor_id = proposal_sensor_id

    async def get(self, category='unclosed', *, offset=0, limit=50):
        predicate = PREDICATES.get(category)
        counters = ','.join(f'count(*) FILTER(WHERE {where}) AS {key}' for key,where in PREDICATES.items())
        async with self.db.pool.acquire() as conn, conn.transaction(isolation='repeatable_read', readonly=True):
            counts = dict(await conn.fetchrow(f'SELECT count(*) AS stored_events,{counters} {JOINS}'))
            pending = await conn.fetchval("SELECT count(*) FROM config_proposals WHERE status='pending' AND ($1::text IS NULL OR sensor_id=$1)",
                                          self.proposal_sensor_id) if self.proposals_available else None
            snapshot = await conn.fetchval('SELECT transaction_timestamp()')
            now = snapshot if isinstance(snapshot, datetime) else datetime.fromisoformat(snapshot)
            if category == 'recheck':
                candidates = await conn.fetchval("SELECT count(*) " + JOINS + " WHERE b.decision IN ('expected_backup','approved_maintenance')")
                if candidates > MAX_RECHECK_REVIEWS:
                    raise ReviewConflict('review_evaluation_capacity')
                rows = await conn.fetch(f'''SELECT e.id,e.timestamp,e.engine,e.severity,e.title,
                    e.source_ip::text,e.dest_ip::text,COALESCE(w.owner,'') AS owner,
                    COALESCE(w.status,'open') AS status,b.decision AS recorded_decision,b.expires_at
                    {JOINS} WHERE b.decision IN ('expected_backup','approved_maintenance') ORDER BY
                    CASE e.severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,
                    e.timestamp DESC,e.id DESC''')
                reviews = BusinessReviews(self.db)
                evaluated = []
                for row in rows:
                    current = await reviews.get(row['id'],connection=conn,now=now)
                    if current['state'] == 'needs_review':
                        evaluated.append(dict(row) | {'review_state':current['state'],'review_reason':current['reason']})
                counts['recheck'] = len(evaluated)
                rows = evaluated[offset:offset+limit]
            else:
                counts['recheck'] = None
                rows = await conn.fetch(f'''SELECT e.id,e.timestamp,e.engine,e.severity,e.title,
                e.source_ip::text,e.dest_ip::text,COALESCE(w.owner,'') AS owner,
                COALESCE(w.status,'open') AS status,b.decision AS recorded_decision,b.expires_at
                {JOINS} WHERE {predicate} ORDER BY
                CASE e.severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,
                e.timestamp DESC,e.id DESC LIMIT $1 OFFSET $2''',limit,offset)
        def stamp(value):
            return value.isoformat() if hasattr(value,'isoformat') else value
        return {'snapshot_at':stamp(snapshot),'scope':'all_retained_events','counts':counts,
                'recheck_evaluated':category=='recheck','pending_proposals':pending,'proposals_available':self.proposals_available,
                'category':category,'total':counts[category],'offset':offset,'limit':limit,
                'events':[{key:stamp(value) for key,value in dict(row).items()} for row in rows]}
