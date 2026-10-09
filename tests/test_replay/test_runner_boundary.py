"""Real spawned worker tests: budgets and cancellation reclaim the child."""
import asyncio
import time
from unittest.mock import AsyncMock

import pytest
from netwatcher.replay.contract import AnalysisContract
from netwatcher.replay.runner import ReplayRunner, ReplayBudgetError
from netwatcher.replay.runs import ReplayRunService, ReplayAdmissionError
from netwatcher.replay.trace import Trace


def source(count=30):
    return Trace('boundary', records=[
        {'src_ip': '192.0.2.1', 'dst_ip': '192.0.2.2', 'dst_port': i % 65000,
         'ip_proto': 'tcp', 'bytes': 120, 'ts': i / 100}
        for i in range(count)], engines=('port_scan',))


@pytest.mark.asyncio
async def test_worker_keeps_event_loop_responsive_and_reaped():
    runner = ReplayRunner()
    trace = source(20000)
    contract = AnalysisContract(engine_params={'threshold': 5})
    ticks = []
    task = asyncio.create_task(runner.run(trace, contract, contract, trace.size_bytes))
    while not task.done():
        ticks.append(time.monotonic())
        await asyncio.sleep(.01)
    result = await task
    assert result.comparable
    assert len(ticks) > 3
    assert max(b-a for a, b in zip(ticks, ticks[1:])) < .25
    assert not runner._processes


@pytest.mark.asyncio
async def test_timeout_kills_and_reaps_worker():
    runner = ReplayRunner(timeout=.001)
    trace = source(50000)
    contract = AnalysisContract(engine_params={'threshold': 5})
    with pytest.raises(ReplayBudgetError, match='wall_time'):
        await runner.run(trace, contract, contract, trace.size_bytes)
    assert not runner._processes


@pytest.mark.asyncio
async def test_result_limit_rejects_large_worker_output_and_reaps():
    runner = ReplayRunner(result_bytes=1024)
    trace = source(1000)
    for index, record in enumerate(trace.records):
        record['src_ip'] = f'192.0.2.{index // 10 + 1}'
    contract = AnalysisContract(engine_params={'threshold': 5})
    with pytest.raises(ReplayBudgetError, match='result_bytes'):
        await runner.run(trace, contract, contract, trace.size_bytes)
    assert not runner._processes


@pytest.mark.asyncio
async def test_cancellation_reaps_worker():
    runner = ReplayRunner()
    trace = source(50000)
    contract = AnalysisContract()
    task = asyncio.create_task(runner.run(trace, contract, contract, trace.size_bytes))
    await asyncio.sleep(.02)
    assert runner._processes
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not runner._processes


@pytest.mark.asyncio
async def test_admission_bounds_before_db_and_recovers_on_failure():
    repository = AsyncMock()
    service = ReplayRunService(repository, max_pending_runs=1, max_pending_bytes=1024)
    with pytest.raises(ReplayAdmissionError) as error:
        await service.submit(source(100), AnalysisContract(), AnalysisContract())
    assert error.value.status_code == 413
    repository.insert_trace.assert_not_awaited()
    repository.insert_trace.side_effect = RuntimeError('offline')
    with pytest.raises(RuntimeError, match='offline'):
        await service.submit(source(1), AnalysisContract(), AnalysisContract())
    assert service.status()['pending_runs'] == 0
    assert service.status()['pending_bytes'] == 0
