"""실제 지연·취소 지연에서도 전체 종료 예산이 누적되지 않는다."""
import asyncio
import threading
import time
from unittest.mock import MagicMock

import pytest

from netwatcher.services.shutdown import ShutdownBudget
from netwatcher.capture.pool import WorkerPool
from netwatcher.utils.config import Config


@pytest.mark.asyncio
async def test_shared_deadline_and_cancellation_cleanup_do_not_extend_budget():
    budget = ShutdownBudget(.08)
    started = time.monotonic()
    async def delayed_cleanup():
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            await asyncio.sleep(.15)
    assert not await budget.run('webhook', delayed_cleanup)
    assert not await budget.run('db', lambda: asyncio.sleep(10))
    assert time.monotonic() - started < .14
    assert budget.unconfirmed == ['webhook', 'db']
    await asyncio.sleep(.16)  # 취소 뒤 정리도 기다려 시험이 태스크를 남기지 않는다.


@pytest.mark.asyncio
async def test_blocked_thread_does_not_block_event_loop_or_claim_completion():
    release = threading.Event()
    budget = ShutdownBudget(.04)
    ticks = []
    async def heartbeat():
        for _ in range(3):
            await asyncio.sleep(.01)
            ticks.append(1)
    ticker = asyncio.create_task(heartbeat())
    try:
        assert not await budget.run('file_io', lambda: asyncio.to_thread(release.wait))
        await ticker
        assert len(ticks) == 3
        assert budget.unconfirmed == ['file_io']
    finally:
        release.set()


def test_worker_joins_share_one_deadline():
    pool = WorkerPool(Config({'workers': 2}), num_workers=2)
    pool._alive = True
    workers = [MagicMock() for _ in range(4)]
    for worker in workers:
        worker.join.side_effect = lambda timeout: time.sleep(timeout)
        worker.is_alive.return_value = False
    pool._workers = workers.copy()
    pool._input_queues = [MagicMock() for _ in workers]
    started = time.monotonic()
    pool.stop(timeout=.04)
    assert workers[0].join.call_args.kwargs['timeout'] <= .04
    assert workers[-1].join.call_args.kwargs['timeout'] < .01


@pytest.mark.asyncio
async def test_results_are_forwarded_while_worker_stop_waits():
    from netwatcher.services.shutdown import stop_workers
    from types import SimpleNamespace
    waiting = threading.Event()
    forwarded = []
    def stop(**kwargs):
        assert kwargs['preserve_results'] is True
        assert waiting.wait(.3)  # 결과 소비 없이는 feeder처럼 종료되지 않는다.
    def collect():
        if not forwarded:
            forwarded.append(1)
            waiting.set()
            return 1
        return 0
    pool = SimpleNamespace(is_multiprocess=True, stop=stop, close_results=MagicMock())
    await stop_workers(pool, SimpleNamespace(collect_worker_alerts=collect), .3)
    assert forwarded == [1]
    pool.close_results.assert_called_once()
