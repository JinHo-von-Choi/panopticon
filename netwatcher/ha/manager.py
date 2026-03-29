"""HA 관리자 -- 리더 선출과 인스턴스 레지스트리를 통합한다."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from netwatcher.ha.heartbeat import InstanceRegistry
from netwatcher.ha.leader import LeaderElection

logger = logging.getLogger("netwatcher.ha.manager")


class HAManager:
    """고가용성 관리자.

    - Redis 비활성 시 standalone 모드로 동작 (항상 리더)
    - Redis 활성 시 리더 선출 + 인스턴스 레지스트리 활성화
    """

    def __init__(
        self,
        redis_client: Any,
        config: dict[str, Any] | None = None,
        instance_id: str | None = None,
    ) -> None:
        self._redis       = redis_client
        self._config      = config or {}
        self._instance_id = instance_id or uuid.uuid4().hex
        self._standalone  = True

        self._leader: LeaderElection | None = None
        self._registry: InstanceRegistry | None = None

        self.on_become_leader: Callable[[], Awaitable[None]] | None = None
        self.on_lose_leader: Callable[[], Awaitable[None]] | None = None

    @property
    def is_leader(self) -> bool:
        if self._standalone:
            return True
        return self._leader.is_leader if self._leader else False

    @property
    def instance_id(self) -> str:
        return self._instance_id

    async def start(self) -> None:
        """HA 시스템을 시작한다. Redis 비활성 시 standalone 모드."""
        if not self._redis.available:
            self._standalone = True
            logger.info("HA standalone mode (Redis unavailable): instance=%s", self._instance_id)
            # standalone에서는 즉시 리더 콜백 호출
            if self.on_become_leader is not None:
                try:
                    await self.on_become_leader()
                except Exception:
                    logger.exception("on_become_leader callback failed (standalone)")
            return

        self._standalone = False

        # 인스턴스 레지스트리 시작
        ha_cfg    = self._config.get("ha", {})
        ttl       = ha_cfg.get("ttl_seconds", 30)
        lock_key  = ha_cfg.get("lock_key", "ha:leader")

        web_cfg = self._config.get("web", {})
        metadata = {
            "port": str(web_cfg.get("port", 38585)),
            "role": "standby",
        }

        self._registry = InstanceRegistry(
            redis_client=self._redis,
            instance_id=self._instance_id,
            metadata=metadata,
            ttl_seconds=ttl,
        )
        await self._registry.start()

        # 리더 선출 시작
        self._leader = LeaderElection(
            redis_client=self._redis,
            instance_id=self._instance_id,
            lock_key=lock_key,
            ttl_seconds=ttl,
        )
        self._leader.on_leader_acquired = self._on_acquired
        self._leader.on_leader_lost = self._on_lost
        await self._leader.start()

        logger.info("HA cluster mode started: instance=%s", self._instance_id)

    async def stop(self) -> None:
        """HA 시스템을 정지한다."""
        if self._leader is not None:
            await self._leader.stop()
            self._leader = None

        if self._registry is not None:
            await self._registry.stop()
            self._registry = None

        logger.info("HA stopped: instance=%s", self._instance_id)

    async def cluster_status(self) -> dict[str, Any]:
        """클러스터 상태를 반환한다. API 응답용."""
        if self._standalone:
            return {
                "mode": "standalone",
                "instance_id": self._instance_id,
                "is_leader": True,
                "instances": [
                    {
                        "instance_id": self._instance_id,
                        "role": "leader",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }

        instances = []
        if self._registry is not None:
            instances = await self._registry.list_instances()

        # 리더 정보 표시
        leader_id = None
        if self._leader is not None:
            try:
                raw = await self._redis.get(self._leader._lock_key)
                if raw is not None:
                    leader_id = raw.decode()
            except Exception:
                pass

        return {
            "mode": "cluster",
            "instance_id": self._instance_id,
            "is_leader": self.is_leader,
            "leader_id": leader_id,
            "instances": instances,
        }

    async def _on_acquired(self) -> None:
        """리더 획득 시 콜백."""
        logger.info("Became leader: instance=%s", self._instance_id)
        if self.on_become_leader is not None:
            try:
                await self.on_become_leader()
            except Exception:
                logger.exception("on_become_leader callback failed")

    async def _on_lost(self) -> None:
        """리더 상실 시 콜백."""
        logger.warning("Lost leadership: instance=%s", self._instance_id)
        if self.on_lose_leader is not None:
            try:
                await self.on_lose_leader()
            except Exception:
                logger.exception("on_lose_leader callback failed")
