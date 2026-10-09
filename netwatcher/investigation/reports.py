"""발생 기간 내 보존 사건의 현재 처리 상태를 집계한다."""
from datetime import datetime, timezone
import csv
import io

from netwatcher.investigation.reviews import ReviewConflict

MAX_REPORT_EVENTS = 10000


def safe_cell(value):
    text = '' if value is None else str(value)
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def report_csv(report):
    fields = ['period_start', 'period_end', 'snapshot_at', 'event_id', 'observed_at', 'engine',
              'severity', 'title', 'source_ip', 'dest_ip', 'occurrence_count', 'owner', 'status',
              'updated_at', 'note', 'owner_id']
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for event in report['events']:
        row = {'period_start':report['period']['start'], 'period_end':report['period']['end'],
               'snapshot_at':report['snapshot_at']} | event
        writer.writerow({key:safe_cell(row.get(key)) for key in fields})
    return output.getvalue()


class CaseReports:
    def __init__(self, db):
        self.db = db

    async def report(self, start, end):
        async with self.db.pool.acquire() as conn, conn.transaction(isolation='repeatable_read', readonly=True):
            snapshot = await conn.fetchval('SELECT transaction_timestamp()')
            count = await conn.fetchval('SELECT count(*) FROM events WHERE timestamp>=$1 AND timestamp<$2',
                                        start.isoformat(), end.isoformat())
            if count > MAX_REPORT_EVENTS:
                raise ReviewConflict('report_capacity')
            rows = await conn.fetch('''SELECT e.id AS event_id,e.timestamp AS observed_at,e.engine,
                e.severity,e.title,e.source_ip::text,e.dest_ip::text,e.metadata,
                COALESCE(w.owner,'') AS owner,w.owner_id,COALESCE(w.status,'open') AS status,w.updated_at,h.note
                FROM events e LEFT JOIN case_workflows w ON w.event_id=e.id
                LEFT JOIN case_history h ON h.event_id=w.event_id AND h.version=w.version
                WHERE e.timestamp>=$1 AND e.timestamp<$2 ORDER BY e.timestamp DESC,e.id DESC''',
                start.isoformat(),end.isoformat())
        events = []
        statuses = {key:0 for key in ('open','investigating','closed')}
        severity = {}
        known_occurrences = 0
        unknown = 0
        for row in rows:
            event = dict(row)
            if event.get('owner_id') is not None:
                event['owner_id'] = str(event['owner_id'])
            metadata = event.pop('metadata') or {}
            aggregation = metadata.get('aggregation') if isinstance(metadata,dict) else {'count':None}
            occurrence = aggregation.get('count') if isinstance(aggregation,dict) else (1 if aggregation is None else None)
            if type(occurrence) is not int or not 1 <= occurrence <= 2**63-1:
                occurrence = None
            event['occurrence_count'] = occurrence
            known_occurrences += occurrence or 0
            unknown += occurrence is None
            statuses[event['status']] += 1
            severity[event['severity']] = severity.get(event['severity'],0)+1
            for key in ('observed_at','updated_at'):
                value = event[key]
                if value is not None:
                    value = value if isinstance(value,datetime) else datetime.fromisoformat(str(value))
                    event[key] = value.astimezone(timezone.utc).isoformat()
            events.append(event)
        snapshot = snapshot if isinstance(snapshot,datetime) else datetime.fromisoformat(str(snapshot))
        return {'period':{'start':start.isoformat(),'end':end.isoformat(),'end_exclusive':True},
                'snapshot_at':snapshot.astimezone(timezone.utc).isoformat(),
                'summary':{'stored_events':count,'known_occurrences':known_occurrences,
                           'unknown_occurrence_events':unknown,'occurrences_complete':unknown==0,
                           'by_status':statuses,'by_severity':severity}, 'events':events}
