"""Redis 기반 분산 리더 선출."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Awaitable, Callable

logger = logging.getLogger("netwatcher.ha.leader")


class LeaderElection:
    """Redis SET NX 기반 리더 선출.

    - 하나의 인스턴스만 리더가 될 수 있음
    - 리더는 TTL/2 간격으로 하트비트 갱신
    - TTL 만료 시 다른 인스턴스가 자동으로 리더 인수
    """

    def __init__(
        self,
        redis_client: Any,
        instance_id: str | None = None,
        lock_key: str = "ha:leader",
        ttl_seconds: int = 30,
    ) -> None:
        self._redis      = redis_client
        self._instance_id = instance_id or uuid.uuid4().hex
        self._lock_key    = lock_key
        self._ttl         = ttl_seconds
        self._is_leader   = False
        self._task: asyncio.Task[None] | None = None

        self.on_leader_acquired: Callable[[], Awaitable[None]] | None = None
        self.on_leader_lost: Callable[[], Awaitable[None]] | None = None

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    @property
    def instance_id(self) -> str:
        return self._instance_id

    async def start(self) -> None:
        """리더 선출 루프를 시작한다."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._election_loop(), name="leader-election")
        logger.info("Leader election started: instance=%s key=%s ttl=%ds",
                     self._instance_id, self._lock_key, self._ttl)

    async def stop(self) -> None:
        """리더 선출 루프를 중지하고 리더이면 락을 해제한다."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        if self._is_leader:
            # 자신이 리더인 경우에만 락 해제
            current = await self._redis.get(self._lock_key)
            if current is not None and current.decode() == self._instance_id:
                await self._redis.delete(self._lock_key)
                logger.info("Leader lock released: instance=%s", self._instance_id)

            self._is_leader = False
            if self.on_leader_lost is not None:
                try:
                    await self.on_leader_lost()
                except Exception:
                    logger.exception("on_leader_lost callback failed")

    async def _election_loop(self) -> None:
        """리더 선출/갱신 루프.

        - 리더가 아닌 경우: TTL/3 간격으로 SET NX 시도
        - 리더인 경우: TTL/2 간격으로 SET XX 갱신
        """
        try:
            while True:
                if self._is_leader:
                    await self._renew_leadership()
                    await asyncio.sleep(self._ttl / 2)
                else:
                    await self._try_acquire()
                    await asyncio.sleep(self._ttl / 3)
        except asyncio.CancelledError:
            raise

    async def _try_acquire(self) -> None:
        """SET NX로 리더 획득을 시도한다."""
        try:
            acquired = await self._redis.set_nx(
                self._lock_key,
                self._instance_id.encode(),
                self._ttl,
            )
            if acquired:
                self._is_leader = True
                logger.info("Leader acquired: instance=%s", self._instance_id)
                if self.on_leader_acquired is not None:
                    try:
                        await self.on_leader_acquired()
                    except Exception:
                        logger.exception("on_leader_acquired callback failed")
        except Exception:
            logger.warning("Leader acquisition attempt failed", exc_info=True)

    async def _renew_leadership(self) -> None:
        """SET XX로 리더 TTL을 갱신한다. 실패 시 리더 상실 처리."""
        try:
            # 자신이 여전히 리더인지 확인 후 갱신
            current = await self._redis.get(self._lock_key)
            if current is None or current.decode() != self._instance_id:
                # 다른 인스턴스가 리더가 되었거나 키가 만료됨
                self._is_leader = False
                logger.warning("Leader lost (key mismatch): instance=%s", self._instance_id)
                if self.on_leader_lost is not None:
                    try:
                        await self.on_leader_lost()
                    except Exception:
                        logger.exception("on_leader_lost callback failed")
                return

            renewed = await self._redis.set_xx(
                self._lock_key,
                self._instance_id.encode(),
                self._ttl,
            )
            if not renewed:
                self._is_leader = False
                logger.warning("Leader renewal failed: instance=%s", self._instance_id)
                if self.on_leader_lost is not None:
                    try:
                        await self.on_leader_lost()
                    except Exception:
                        logger.exception("on_leader_lost callback failed")
            else:
                logger.debug("Leader renewed: instance=%s ttl=%ds", self._instance_id, self._ttl)
        except Exception:
            logger.warning("Leader renewal error", exc_info=True)
            self._is_leader = False
            if self.on_leader_lost is not None:
                try:
                    await self.on_leader_lost()
                except Exception:
                    logger.exception("on_leader_lost callback failed")
