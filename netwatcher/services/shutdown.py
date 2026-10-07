"""종료 단계들이 공유하는 monotonic 예산. 취소 확인 대기는 시한을 늘리지 않는다."""
import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class ShutdownBudget:
    def __init__(self, seconds=10):
        self.deadline = time.monotonic() + max(0, seconds)
        self.unconfirmed = []

    @property
    def remaining(self):
        return max(0, self.deadline - time.monotonic())

    async def run(self, name, operation, limit=None):
        timeout = self.remaining if limit is None else min(self.remaining, max(0, limit))
        task = asyncio.create_task(operation())
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if task not in done:
            task.cancel()
            task.add_done_callback(self._consume)
            self.unconfirmed.append(name)
            logger.warning("Shutdown stage unconfirmed: %s", name)
            return False
        try:
            task.result()
            return True
        except asyncio.CancelledError:
            self.unconfirmed.append(name)
            return False
        except Exception as exc:
            self.unconfirmed.append(name)
            logger.warning("Shutdown stage failed: %s reason=%s", name, type(exc).__name__)
            return False

    @staticmethod
    def _consume(task):
        if not task.cancelled():
            task.exception()


async def stop_workers(pool, processor, timeout):
    """프로세스 join 중 결과 큐를 소비해 feeder 대기를 줄이고 확정 전 결과를 전달한다."""
    if not pool.is_multiprocess:
        pool.stop(timeout=timeout)
        return
    task = asyncio.create_task(asyncio.to_thread(pool.stop, timeout=timeout, preserve_results=True))
    collected = 0
    try:
        while not task.done():
            collected += processor.collect_worker_alerts()
            await asyncio.sleep(.01)
        await task
        # 워커 종료 후 남은 유한 결과 큐를 이벤트 루프에 양보하며 배출한다.
        while True:
            count = processor.collect_worker_alerts()
            collected += count
            if not count:
                break
            await asyncio.sleep(0)
    finally:
        if not task.done():
            task.cancel()
        pool.close_results()
        logger.info("Shutdown worker results forwarded: %d", collected)
