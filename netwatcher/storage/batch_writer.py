"""유한 이벤트 버퍼. 생산자 잠금 안에서 DB 완료를 기다리지 않는다."""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import deque

logger = logging.getLogger(__name__)


class BatchWriter:
    def __init__(self, event_repo, batch_size=100, flush_interval_ms=500,
                 max_pending=1000, max_bytes=8 * 1024 * 1024, max_age_seconds=300):
        self._event_repo = event_repo
        self._batch_size = max(1, batch_size)
        self._flush_interval = max(.01, flush_interval_ms / 1000)
        self._max_pending = max(1, max_pending)
        self._max_bytes = max(1, max_bytes)
        self._max_age = max(.01, max_age_seconds)
        self._buffer = deque()
        self._pending_batch = []
        self._bytes = 0
        self._lock = asyncio.Lock()
        self._flush_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._flush_task = None
        self._running = False
        self._next_retry = 0
        self.rejected = 0
        self.expired_unconfirmed = 0
        self._failed = False

    @property
    def pending(self):
        return len(self._buffer) + len(self._pending_batch)

    def status(self):
        items = list(self._buffer) + self._pending_batch
        return {"status": "degraded" if self._failed else "healthy", "pending": self.pending,
                "payload_bytes": self._bytes, "rejected": self.rejected,
                "expired_unconfirmed": self.expired_unconfirmed,
                "oldest_age_seconds": max((time.monotonic() - item[0] for item in items), default=0)}

    async def enqueue(self, event_data):
        """DB와 무관하게 진입 결과를 반환한다. 버퍼는 문자열 스냅샷만 소유한다."""
        data = {**event_data, "ingest_id": str(event_data.get("ingest_id") or uuid.uuid4())}
        encoded = json.dumps(data, ensure_ascii=False).encode()
        async with self._lock:
            if self.pending >= self._max_pending or self._bytes + len(encoded) > self._max_bytes:
                self.rejected += 1
                return False
            self._buffer.append((time.monotonic(), encoded))
            self._bytes += len(encoded)
            if self.pending >= self._batch_size:
                self._wake.set()
        return True

    async def flush(self):
        """한 소비자만 SQL을 실행하고 실패 스냅샷의 UUID를 유지한다."""
        async with self._flush_lock:
            now = time.monotonic()
            async with self._lock:
                for name in ("_pending_batch", "_buffer"):
                    items = getattr(self, name)
                    kept = []
                    for item in items:
                        if now - item[0] >= self._max_age:
                            self.expired_unconfirmed += 1
                            self._bytes -= len(item[1])
                        else:
                            kept.append(item)
                    setattr(self, name, kept if name == "_pending_batch" else deque(kept))
                if not self._pending_batch:
                    self._pending_batch = [self._buffer.popleft() for _ in range(min(self._batch_size, len(self._buffer)))]
                batch = self._pending_batch
            if not batch or now < self._next_retry:
                return 0
            try:
                async with asyncio.timeout(2):
                    count = await self._event_repo.insert_batch([json.loads(item[1]) for item in batch])
            except Exception:
                self._failed = True
                self._next_retry = time.monotonic() + min(.5, self._flush_interval)
                logger.warning("Event batch deferred: unconfirmed=%d", len(batch))
                return 0
            async with self._lock:
                self._bytes -= sum(len(item[1]) for item in batch)
                self._pending_batch = []
                self._failed = False
                self._next_retry = 0
                if self.pending >= self._batch_size:
                    self._wake.set()
            return count

    async def start(self):
        if self._running:
            return
        self._running = True
        self._flush_task = asyncio.create_task(self._periodic_flush_loop())

    async def stop(self, timeout=2):
        deadline = time.monotonic() + max(0, timeout)
        self._running = False
        if self._flush_task is not None:
            self._flush_task.cancel()
            task = self._flush_task
            done, _ = await asyncio.wait({task}, timeout=max(0, deadline - time.monotonic()))
            if task not in done:
                task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
                self._failed = True
                logger.warning("Event batch cancellation unconfirmed: pending=%d", self.pending)
                self._flush_task = None
                return
            if not task.cancelled():
                task.result()
            self._flush_task = None
        try:
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                while self.pending and time.monotonic() < deadline:
                    if not await self.flush():
                        await asyncio.sleep(min(.05, max(0, deadline - time.monotonic())))
        except TimeoutError:
            pass
        if self.pending:
            logger.warning("Event batch shutdown unconfirmed: pending=%d bytes=%d", self.pending, self._bytes)

    async def _periodic_flush_loop(self):
        while self._running:
            try:
                await asyncio.wait_for(self._wake.wait(), self._flush_interval)
            except TimeoutError:
                pass
            self._wake.clear()
            await self.flush()
