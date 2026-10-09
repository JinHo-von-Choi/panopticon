"""부하 도구가 운영 DB·기존 출력·무한 입력으로 진행하지 않게 한다."""

from argparse import Namespace

import pytest

from scripts.perf_eve import Latencies, run, ROOT


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"db_name": "netwatcher"}, {"db_host": "198.51.100.1"},
    {"duration_seconds": float("inf")}, {"duration_seconds": float("nan")},
    {"events_per_second": 20001}, {"max_source_bytes": 2**32},
    {"max_retained_records": 10000001}, {"max_retained_bytes": 1},
    {"output_dir": ROOT / "benchmark-output"},
])
async def test_invalid_probe_never_connects_or_creates_output(tmp_path, monkeypatch, change):
    args = Namespace(db_name="netwatcher_perf_test", db_host="127.0.0.1", db_port=5432,
                     db_user="netwatcher", duration_seconds=30, events_per_second=1000,
                     max_source_bytes=1024**2, output_dir=tmp_path / "result")
    args.max_retained_records = 250000
    args.max_retained_bytes = 256 * 1024**2
    vars(args).update(change)
    async def forbidden(*arguments, **keywords):
        raise AssertionError("Must reject before opening a database connection")
    monkeypatch.setattr("scripts.perf_eve.asyncpg.connect", forbidden)
    with pytest.raises(ValueError):
        await run(args)
    assert not (tmp_path / "result").exists()


def test_histogram_reports_upper_bound_with_fixed_memory():
    values = Latencies()
    buckets = len(values.counts)
    for index in range(100000):
        values.observe((index % 100 + 1) / 100)
    assert .95 <= values.p95_upper_bound() <= 1.045
    assert len(values.counts) == buckets
    values.observe(-1)
    assert values.clock_errors == 1
    assert values.p95_upper_bound() is None


@pytest.mark.asyncio
async def test_probe_reports_committed_counts_and_status_before_shutdown(db, tmp_path):
    from scripts.perf_eve import measure

    args = Namespace(output_dir=tmp_path, duration_seconds=.1, events_per_second=100,
                     max_source_bytes=1024**2, max_retained_records=250000,
                     max_retained_bytes=256 * 1024**2)
    report = await measure(args, db)
    assert report['emitted_records'] > 0
    assert report['stored_records'] == report['stored_events'] == report['emitted_records']
    assert report['all_emitted_records_stored']
    assert report['source_duration_completed']
    assert report['service']['status'] == 'healthy'
    assert report['service']['sources'][0]['pending_bytes'] == 0


def test_cli_rejects_early_input_stop_even_when_all_emitted_records_are_stored(monkeypatch, tmp_path):
    from scripts import perf_eve

    async def incomplete_run(args):
        return {'emitted_records': 1, 'stored_records': 1,
                'all_emitted_records_stored': True, 'source_duration_completed': False,
                'source_budget_reached': False, 'latency_clock_errors': 0,
                'service': {'status': 'healthy'}}

    monkeypatch.setattr(perf_eve, 'run', incomplete_run)
    monkeypatch.setattr('sys.argv', ['perf_eve.py', '--db-name', 'netwatcher_perf_test',
                                   '--output-dir', str(tmp_path)])
    assert perf_eve.main() == 1
