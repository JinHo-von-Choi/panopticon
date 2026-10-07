"""원격 알림 지연을 경보 커밋에서 분리하는 유한 우선순위 큐."""
import asyncio
import json
import logging
import time
from itertools import count

from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger(__name__)


class NotificationWriter:
    def __init__(self, send, max_jobs=128, max_bytes=2 * 1024 * 1024):
        self.send = send
        self.queue = asyncio.PriorityQueue(maxsize=max(1, max_jobs))
        self.max_bytes = max(1, max_bytes)
        self.bytes = 0
        self.rejected = 0
        self.unconfirmed = 0
        self.failed = 0
        self.inflight = 0
        self._sequence = count()
        self.task = None

    def status(self):
        return {"pending": self.queue.qsize(), "payload_bytes": self.bytes,
                "rejected": self.rejected, "shutdown_unconfirmed": self.unconfirmed, "failed": self.failed, "inflight": self.inflight}

    def start(self):
        if self.task is None:
            self.task = asyncio.create_task(self._loop())

    def submit(self, alert):
        payload = alert.to_json().encode()
        critical = alert.severity == Severity.CRITICAL
        jobs = self.queue.maxsize if critical else self.queue.maxsize - self.queue.maxsize // 4
        byte_limit = self.max_bytes if critical else self.max_bytes - self.max_bytes // 4
        if self.queue.qsize() >= jobs or self.bytes + len(payload) > byte_limit:
            self.rejected += 1
            return False
        self.queue.put_nowait((0 if critical else 1, next(self._sequence), time.monotonic(), payload))
        self.bytes += len(payload)
        return True

    async def _loop(self):
        while True:
            _, _, _, payload = await self.queue.get()
            self.inflight = 1
            try:
                data = json.loads(payload)
                data['severity'] = Severity(data['severity'])
                if await self.send(Alert(**data)) is False:
                    self.failed += 1
            except asyncio.CancelledError:
                self.unconfirmed += 1
                raise
            except Exception as exc:
                self.failed += 1
                logger.warning('Notification delivery unconfirmed: %s', type(exc).__name__)
            finally:
                self.inflight = 0
                self.bytes -= len(payload)
                self.queue.task_done()

    async def stop(self, timeout=1):
        if self.task is None:
            return
        deadline = time.monotonic() + max(0, timeout)
        try:
            await asyncio.wait_for(self.queue.join(), max(0, timeout))
        except TimeoutError:
            pass
        task = self.task
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=max(0, deadline - time.monotonic()))
        if task not in done:
            task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        elif not task.cancelled():
            task.result()
        self.task = None
        while not self.queue.empty():
            _, _, _, payload = self.queue.get_nowait()
            self.unconfirmed += 1
            self.bytes -= len(payload)
            self.queue.task_done()
        if self.unconfirmed or self.inflight:
            logger.warning('Notification shutdown unconfirmed: queued_cancelled=%d inflight=%d', self.unconfirmed, self.inflight)
