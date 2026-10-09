#!/usr/bin/env python3
"""합성 EVE 파일에서 PostgreSQL 확정 저장까지 측정한다. 실제 NIC 시험은 아니다."""

import argparse
import asyncio
import bisect
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import asyncpg

from netwatcher.ingest.service import EveService
from netwatcher.ingest.repository import EveRepository
from netwatcher.storage.database import Database
from netwatcher.storage.schemas import ALL_SCHEMAS
from netwatcher.utils.config import Config


class Latencies:
    """유한 크기의 히스토그램으로 p95의 상한을 계산한다."""
    def __init__(self):
        edge = .001
        self.edges = []
        while edge < 86400:
            self.edges.append(edge)
            edge *= 1.1
        self.counts = [0] * (len(self.edges) + 1)
        self.total = self.clock_errors = 0

    def observe(self, seconds):
        if seconds < 0 or not math.isfinite(seconds):
            self.clock_errors += 1
            return
        self.counts[bisect.bisect_left(self.edges, seconds)] += 1
        self.total += 1

    def p95_upper_bound(self):
        if not self.total or self.clock_errors:
            return None
        needed = math.ceil(self.total * .95)
        for index, count in enumerate(self.counts):
            needed -= count
            if needed <= 0:
                return self.edges[index] if index < len(self.edges) else None


def validate(args):
    if not args.db_name.startswith('netwatcher_perf_'):
        raise ValueError('Use a dedicated netwatcher_perf_ database')
    if args.db_host not in {'127.0.0.1', 'localhost', '::1'}:
        raise ValueError('Only a local dedicated database is allowed')
    if not math.isfinite(args.duration_seconds) or not 0 < args.duration_seconds <= 7200:
        raise ValueError('Duration must be within (0, 7200] seconds')
    if not 1 <= args.events_per_second <= 20000:
        raise ValueError('Event rate must be within [1, 20000]')
    if not 1024 * 1024 <= args.max_source_bytes <= 2 * 1024**3:
        raise ValueError('Source budget must be within [1 MiB, 2 GiB]')
    EveRepository(None, max_records=args.max_retained_records, max_bytes=args.max_retained_bytes)
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents or output.exists():
        raise ValueError('Use a new output directory outside the repository')


def synthetic_line(sequence):
    return json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': 'alert', 'flow_id': sequence + 1,
        'src_ip': '198.18.0.2', 'dest_ip': '198.18.1.1', 'proto': 'TCP',
        'alert': {'signature_id': 1, 'severity': 2, 'signature': 'Synthetic benchmark',
                  'category': 'Synthetic'}}, separators=(',', ':')).encode() + b'\n'


async def produce(args, path, service):
    start = time.monotonic()
    emitted = size = 0
    limited = False
    with path.open('ab') as stream:
        while time.monotonic() - start < args.duration_seconds:
            if service.collectors[0].last_error:
                break
            due = min(int((time.monotonic() - start) * args.events_per_second) + 1,
                      math.ceil(args.duration_seconds * args.events_per_second))
            # 생성기도 유한 배치로 실행해 수집·종료 작업에 실행 기회를 준다.
            for sequence in range(emitted, min(due, emitted + 128)):
                line = synthetic_line(sequence)
                if size + len(line) > args.max_source_bytes:
                    limited = True
                    break
                stream.write(line)
                size += len(line)
                emitted += 1
            stream.flush()
            if limited:
                break
            await asyncio.sleep(.005)
    return emitted, size, time.monotonic() - start, limited


async def measure(args, db):
    source = args.output_dir / 'eve.json'
    source.touch()
    service = EveService(db, [{'directory': str(args.output_dir),
                             'sensor_id': 'synthetic-benchmark', 'source_id': 'synthetic-file'}],
                         retention={'max_records': args.max_retained_records,
                                    'max_bytes': args.max_retained_bytes})
    delays, transactions = Latencies(), Latencies()
    repository = service.collectors[0].repository
    original = repository.commit
    async def commit(*arguments):
        start = time.monotonic()
        result = await original(*arguments)
        transactions.observe(time.monotonic() - start)
        now = datetime.now(timezone.utc)
        for record in arguments[-1]:
            if record.get('observed_at'):
                delays.observe((now - datetime.fromisoformat(record['observed_at'])).total_seconds())
        return result
    repository.commit = commit
    collector = service.collectors[0]
    closed_snapshot = {}
    original_close = collector.close

    def close():
        closed_snapshot.update(collector.status())
        original_close()

    collector.close = close
    await service.start()
    cpu = time.process_time()
    start = time.monotonic()
    try:
        emitted, size, source_seconds, limited = await produce(args, source, service)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status = service.collectors[0].status()
            if status['committed_offset'] == size or status['error']:
                break
            await asyncio.sleep(.05)
        healthy_tasks = bool(service._tasks) and all(not task.done() for task in service._tasks)
        await service.stop()
        status = service._summarize([closed_snapshot], healthy_tasks)
        counts = await db.pool.fetchrow('SELECT (SELECT count(*) FROM eve_records) AS records, '
                                       '(SELECT count(*) FROM events) AS events')
        stored, events = counts['records'], counts['events']
        return {'emitted_records': emitted, 'source_bytes': size, 'stored_records': stored,
            'stored_events': events, 'source_seconds': source_seconds,
            'source_duration_completed': source_seconds >= args.duration_seconds,
            'actual_generated_events_per_second': emitted / source_seconds,
            'elapsed_with_drain_seconds': time.monotonic() - start,
            'source_to_committed_p95_seconds_upper_bound': delays.p95_upper_bound(),
            'transaction_p95_seconds_upper_bound': transactions.p95_upper_bound(),
            'latency_clock_errors': delays.clock_errors, 'source_budget_reached': limited,
            'process_cpu_seconds': time.process_time() - cpu,
            'process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'service': status, 'all_emitted_records_stored': stored == events == emitted}
    finally:
        await service.stop()


async def run(args):
    validate(args)
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    schema = 'perf_' + uuid.uuid4().hex
    pg = {'host': args.db_host, 'port': args.db_port, 'database': args.db_name,
          'username': args.db_user, 'password': os.environ.get('NETWATCHER_PERF_DB_PASSWORD', ''),
          'pool_size': 3, 'search_path': schema}
    admin = await asyncpg.connect(host=pg['host'], port=pg['port'], database=pg['database'],
                                  user=pg['username'], password=pg['password'], timeout=5)
    db = Database(Config({'postgresql': pg}))
    created = False
    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        created = True
        await db.connect(max_retries=1)
        async with db.pool.acquire() as conn:
            for sql in ALL_SCHEMAS:
                await conn.execute(sql)
        report = await measure(args, db)
        report.update(format_version=1, input_mode='synthetic_eve_alert_file',
            duration_requested_seconds=args.duration_seconds,
            max_retained_records=args.max_retained_records, max_retained_bytes=args.max_retained_bytes,
            requested_events_per_second=args.events_per_second, python=platform.python_version(),
            source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            working_tree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
            measured_kernel_drop=None, physical_link_test=False,
            cpu_scope='probe process including generator and instrumentation; HTTP/IDS/DB excluded',
            schema_bootstrap='current table definitions; deployment migrations not exercised',
            p95_method='all observations, bounded histogram, 10 percent geometric bins; reported upper bound',
            source_hashes={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in ['netwatcher/ingest/repository.py', 'netwatcher/ingest/tailer.py',
                             'netwatcher/storage/repositories.py', 'scripts/perf_eve.py']})
        (args.output_dir / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        return report
    finally:
        await db.close()
        try:
            if created:
                await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        finally:
            await admin.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--duration-seconds', type=float, default=30)
    parser.add_argument('--events-per-second', type=int, default=1000)
    parser.add_argument('--max-source-bytes', type=int, default=256 * 1024 * 1024)
    parser.add_argument('--max-retained-records', type=int, default=250000)
    parser.add_argument('--max-retained-bytes', type=int, default=256 * 1024 * 1024)
    parser.add_argument('--db-host', default='127.0.0.1')
    parser.add_argument('--db-port', type=int, default=5432)
    parser.add_argument('--db-name', required=True)
    parser.add_argument('--db-user', default='netwatcher')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR)
    try:
        report = asyncio.run(run(args))
    except Exception:
        print('EVE benchmark failed: check dedicated database and workload arguments.', file=sys.stderr)
        return 1
    print(json.dumps({'result': str(args.output_dir / 'result.json'),
                      'emitted': report['emitted_records'], 'stored': report['stored_records']}))
    healthy = report['service']['status'] == 'healthy' and not report['latency_clock_errors']
    return 0 if (report['emitted_records'] > 0 and report['all_emitted_records_stored']
                 and report['source_duration_completed']
                 and not report['source_budget_reached'] and healthy) else 1


if __name__ == '__main__':
    raise SystemExit(main())
