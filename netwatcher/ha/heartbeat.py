"""인스턴스 하트비트 및 클러스터 디스커버리."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("netwatcher.ha.heartbeat")


class InstanceRegistry:
    """Redis 기반 인스턴스 등록/해제/디스커버리.

    각 인스턴스는 Redis에 자신의 메타데이터(ID, 호스트, 포트, 역할, 시작 시각)를
    해시로 저장하고, TTL로 하트비트를 유지한다.
    """

    INSTANCES_SET_KEY = "ha:instances"
    INSTANCE_KEY_PREFIX = "ha:instance:"

    def __init__(
        self,
        redis_client: Any,
        instance_id: str,
        metadata: dict[str, str] | None = None,
        ttl_seconds: int = 30,
    ) -> None:
        self._redis      = redis_client
        self._instance_id = instance_id
        self._ttl         = ttl_seconds
        self._task: asyncio.Task[None] | None = None

        default_meta = {
            "host": socket.gethostname(),
            "pid": str(os.getpid()),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            default_meta.update(metadata)
        self._metadata = default_meta
        self._metadata["instance_id"] = instance_id

    @property
    def instance_id(self) -> str:
        return self._instance_id

    def _instance_key(self, iid: str | None = None) -> str:
        return f"{self.INSTANCE_KEY_PREFIX}{iid or self._instance_id}"

    async def register(self) -> bool:
        """인스턴스를 Redis에 등록한다. HSET + EXPIRE + SADD."""
        try:
            await self._redis.hset(self._instance_key(), self._metadata)
            await self._redis.expire(self._instance_key(), self._ttl)
            await self._redis.sadd(self.INSTANCES_SET_KEY, self._instance_id)
            logger.info("Instance registered: %s", self._instance_id)
            return True
        except Exception:
            logger.warning("Instance registration failed: %s", self._instance_id, exc_info=True)
            return False

    async def heartbeat(self) -> bool:
        """인스턴스 TTL을 갱신한다."""
        try:
            exists = await self._redis.expire(self._instance_key(), self._ttl)
            if not exists:
                # 키가 만료되었으면 재등록
                return await self.register()
            return True
        except Exception:
            logger.warning("Heartbeat failed: %s", self._instance_id, exc_info=True)
            return False

    async def deregister(self) -> bool:
        """인스턴스를 Redis에서 제거한다."""
        try:
            await self._redis.delete(self._instance_key())
            await self._redis.srem(self.INSTANCES_SET_KEY, self._instance_id)
            logger.info("Instance deregistered: %s", self._instance_id)
            return True
        except Exception:
            logger.warning("Instance deregistration failed: %s", self._instance_id, exc_info=True)
            return False

    async def list_instances(self) -> list[dict[str, str]]:
        """모든 활성 인스턴스를 조회한다. 만료된 인스턴스는 집합에서 정리한다."""
        instances: list[dict[str, str]] = []
        stale: list[str] = []

        try:
            member_set = await self._redis.smembers(self.INSTANCES_SET_KEY)
            for raw_id in member_set:
                iid = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                data = await self._redis.hgetall(self._instance_key(iid))
                if not data:
                    # 해시가 만료됨 -- 집합에서 제거 대상
                    stale.append(iid)
                    continue
                decoded = {
                    (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                    for k, v in data.items()
                }
                instances.append(decoded)

            # 만료된 인스턴스 정리
            for sid in stale:
                await self._redis.srem(self.INSTANCES_SET_KEY, sid)

        except Exception:
            logger.warning("list_instances failed", exc_info=True)

        return instances

    async def start(self) -> None:
        """등록 후 주기적 하트비트 태스크를 시작한다."""
        await self.register()
        if self._task is None:
            self._task = asyncio.create_task(self._heartbeat_loop(), name="instance-heartbeat")

    async def stop(self) -> None:
        """하트비트 태스크를 중지하고 인스턴스를 해제한다."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.deregister()

    async def _heartbeat_loop(self) -> None:
        """TTL/3 간격으로 하트비트를 갱신한다."""
        interval = max(1.0, self._ttl / 3)
        try:
            while True:
                await asyncio.sleep(interval)
                await self.heartbeat()
        except asyncio.CancelledError:
            raise
