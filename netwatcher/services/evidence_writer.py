"""유한한 RAM 큐로 PCAP 파일 I/O를 이벤트 루프에서 분리한다."""

import asyncio
import hashlib
import logging
import time
from itertools import count
from netwatcher.detection.models import Severity


logger = logging.getLogger(__name__)


class EvidenceWriter:
    def __init__(self, writer, repository, max_jobs=32, max_bytes=8 * 1024 * 1024, cooldown=60):
        self.writer = writer
        self.repository = repository
        self.queue = asyncio.PriorityQueue(maxsize=max(1, max_jobs))
        self._sequence = count()
        self._reserved_jobs = max(0, max_jobs // 4)
        self.max_bytes = max(1, max_bytes)
        self._reserved_bytes = self.max_bytes // 4
        self.pending_bytes = 0
        self.cooldown = max(1, cooldown)
        self.recent = {}
        self.task = None
        self._shutdown_deadline = None

    def start(self):
        if self.task is None:
            self.task = asyncio.create_task(self._loop())

    def submit(self, event_id, alert):
        now = time.monotonic()
        key = (alert.engine, alert.source_mac or alert.source_ip, alert.dest_ip,
               alert.title_key or alert.metadata.get("detection_type"), alert.severity.value)
        if key in self.recent and now - self.recent[key] < self.cooldown:
            return {"state": "omitted", "reason": "cooldown", "policy_version": 1}
        if len(self.recent) >= 10000:
            self.recent = {k: t for k, t in self.recent.items() if now - t < self.cooldown}
            if len(self.recent) >= 10000:
                return {"state": "omitted", "reason": "policy_key_limit", "policy_version": 1}
        snapshot = self.writer.snapshot(alert.source_ip, alert.dest_ip)
        size = sum(len(raw) for _, raw, _ in snapshot)
        priority = alert.severity == Severity.CRITICAL or alert.metadata.get("evidence_requested") is True
        if not snapshot:
            return {"state": "omitted", "reason": "no_matching_packets", "policy_version": 1}
        jobs_limit = self.queue.maxsize if priority else self.queue.maxsize - self._reserved_jobs
        bytes_limit = self.max_bytes if priority else self.max_bytes - self._reserved_bytes
        if self.queue.qsize() >= jobs_limit or self.pending_bytes + size > bytes_limit:
            return {"state": "omitted", "reason": "evidence_queue_budget", "policy_version": 1}
        self.queue.put_nowait((0 if priority else 1, next(self._sequence), event_id, snapshot, size))
        self.pending_bytes += size
        self.recent[key] = now
        self.start()
        return {"state": "pending", "reason": "queued", "policy_version": 1, "context": "pre_alert_only"}

    async def _store_state(self, event_id, state):
        try:
            timeout = 2 if self._shutdown_deadline is None else max(0, min(2, self._shutdown_deadline - time.monotonic()))
            async with asyncio.timeout(timeout):
                await self.repository.update_pcap_state(event_id, state)
        except Exception:
            pass  # DB 상태는 pending으로 남는다. 영속화 성공을 꾸며내지 않는다.

    async def _loop(self):
        while True:
            _, _, event_id, snapshot, size = await self.queue.get()
            try:
                path = await asyncio.to_thread(self.writer.write_snapshot, event_id, snapshot)
                if path:
                    digest = hashlib.sha256()
                    # 해시는 실제 생성된 PCAP 파일 전체에 대해 계산한다.
                    def hash_file():
                        with open(path, "rb") as stream:
                            for block in iter(lambda: stream.read(65536), b""):
                                digest.update(block)
                        return digest.hexdigest()
                    state = {"state": "persisted", "path": path,
                             "sha256": await asyncio.to_thread(hash_file), "policy_version": 1,
                             "context": "pre_alert_only"}
                else:
                    state = {"state": "failed", "reason": "write_or_storage_budget", "policy_version": 1}
                await self._store_state(event_id, state)
            except asyncio.CancelledError:
                # 취소가 이미 실행 중인 파일 쓰기를 중단했다고 주장하지 않는다.
                await self._store_state(event_id, {"state": "volatile", "reason": "shutdown_unconfirmed", "policy_version": 1})
                raise
            except Exception:
                await self._store_state(event_id, {"state": "failed", "reason": "write_failed", "policy_version": 1})
            finally:
                self.pending_bytes -= size
                self.queue.task_done()

    async def stop(self, timeout=2):
        if self.task is None:
            return
        self._shutdown_deadline = time.monotonic() + max(0, timeout)
        try:
            await asyncio.wait_for(self.queue.join(), max(0, timeout))
        except TimeoutError:
            pass
        if self.pending_bytes:
            logger.warning("Evidence shutdown unconfirmed: queued=%d bytes=%d; active file thread may continue", self.queue.qsize(), self.pending_bytes)
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass
        self.task = None
        while not self.queue.empty():
            _, _, _, _, size = self.queue.get_nowait()
            self.pending_bytes -= size
            self.queue.task_done()
