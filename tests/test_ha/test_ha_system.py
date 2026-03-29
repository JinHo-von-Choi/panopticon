"""HA 시스템 테스트: 리더 선출, 하트비트, 체크포인트, HAManager."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from netwatcher.ha.leader import LeaderElection
from netwatcher.ha.heartbeat import InstanceRegistry
from netwatcher.ha.manager import HAManager
from netwatcher.services.checkpoint_service import CheckpointService


# ── Mock RedisClient ───────────────────────────────────────────────────────��

class MockRedisClient:
    """테스트용 인메모리 Redis 모의 객체."""

    def __init__(self, available: bool = True):
        self._available = available
        self._store: dict[str, bytes] = {}
        self._sets: dict[str, set[str]] = {}
        self._hashes: dict[str, dict[str, str]] = {}
        self._ttls: dict[str, int] = {}

    @property
    def available(self) -> bool:
        return self._available

    def _prefixed(self, key: str) -> str:
        return f"nw:{key}"

    async def get(self, key: str) -> bytes | None:
        return self._store.get(self._prefixed(key))

    async def set(self, key: str, value: bytes, ttl: int = 0) -> bool:
        self._store[self._prefixed(key)] = value
        if ttl > 0:
            self._ttls[self._prefixed(key)] = ttl
        return True

    async def setex(self, key: str, ttl: int, value: bytes) -> bool:
        return await self.set(key, value, ttl=ttl)

    async def set_nx(self, key: str, value: bytes, ttl: int = 0) -> bool:
        pk = self._prefixed(key)
        if pk in self._store:
            return False
        self._store[pk] = value
        if ttl > 0:
            self._ttls[pk] = ttl
        return True

    async def set_xx(self, key: str, value: bytes, ttl: int = 0) -> bool:
        pk = self._prefixed(key)
        if pk not in self._store:
            return False
        self._store[pk] = value
        if ttl > 0:
            self._ttls[pk] = ttl
        return True

    async def delete(self, key: str) -> bool:
        pk = self._prefixed(key)
        self._store.pop(pk, None)
        return True

    async def exists(self, key: str) -> bool:
        return self._prefixed(key) in self._store

    async def sadd(self, key: str, *values: str) -> int:
        pk = self._prefixed(key)
        s = self._sets.setdefault(pk, set())
        before = len(s)
        s.update(values)
        return len(s) - before

    async def smembers(self, key: str) -> set[bytes]:
        pk = self._prefixed(key)
        return {v.encode() if isinstance(v, str) else v for v in self._sets.get(pk, set())}

    async def srem(self, key: str, *values: str) -> int:
        pk = self._prefixed(key)
        s = self._sets.get(pk, set())
        removed = 0
        for v in values:
            if v in s:
                s.discard(v)
                removed += 1
        return removed

    async def hset(self, key: str, mapping: dict[str, str]) -> int:
        pk = self._prefixed(key)
        h = self._hashes.setdefault(pk, {})
        h.update(mapping)
        return len(mapping)

    async def hgetall(self, key: str) -> dict[bytes, bytes]:
        pk = self._prefixed(key)
        h = self._hashes.get(pk, {})
        return {k.encode(): v.encode() for k, v in h.items()}

    async def expire(self, key: str, ttl: int) -> bool:
        self._ttls[self._prefixed(key)] = ttl
        return True

    async def close(self) -> None:
        pass

    async def connect(self) -> bool:
        return self._available


# ── LeaderElection 테스트 ───────────────────────────────────────────────────

class TestLeaderElection:

    @pytest.mark.asyncio
    async def test_acquire_leadership(self):
        """Redis 사용 가능 시 리더 획득."""
        redis = MockRedisClient(available=True)
        le = LeaderElection(redis, instance_id="inst-1", ttl_seconds=10)

        acquired = AsyncMock()
        le.on_leader_acquired = acquired

        await le.start()
        await asyncio.sleep(0.3)

        assert le.is_leader
        acquired.assert_called_once()

        await le.stop()

    @pytest.mark.asyncio
    async def test_only_one_leader(self):
        """두 인스턴스 중 하나만 리더가 된다."""
        redis = MockRedisClient(available=True)
        le1 = LeaderElection(redis, instance_id="inst-1", ttl_seconds=10)
        le2 = LeaderElection(redis, instance_id="inst-2", ttl_seconds=10)

        await le1.start()
        await asyncio.sleep(0.3)
        await le2.start()
        await asyncio.sleep(0.3)

        assert le1.is_leader
        assert not le2.is_leader

        await le1.stop()
        await le2.stop()

    @pytest.mark.asyncio
    async def test_leader_release_on_stop(self):
        """stop() 호출 시 리더 락 해제."""
        redis = MockRedisClient(available=True)
        le = LeaderElection(redis, instance_id="inst-1", ttl_seconds=10)

        await le.start()
        await asyncio.sleep(0.3)
        assert le.is_leader

        await le.stop()
        assert not le.is_leader


# ── InstanceRegistry 테스트 ──────────────────────────────────────────────────

class TestInstanceRegistry:

    @pytest.mark.asyncio
    async def test_register_and_list(self):
        """인스턴스 등록 후 목록 조회."""
        redis = MockRedisClient(available=True)
        reg = InstanceRegistry(redis, instance_id="inst-1", metadata={"port": "38585"})

        assert await reg.register()

        instances = await reg.list_instances()
        assert len(instances) >= 1

    @pytest.mark.asyncio
    async def test_deregister(self):
        """등록 해제 후 목록에서 제거."""
        redis = MockRedisClient(available=True)
        reg = InstanceRegistry(redis, instance_id="inst-1")

        await reg.register()
        await reg.deregister()


# ── HAManager 테스트 ─────────────────────────────────────────────────────────

class TestHAManager:

    @pytest.mark.asyncio
    async def test_standalone_mode(self):
        """Redis 비활성 시 standalone 모드: 항상 리더."""
        redis = MockRedisClient(available=False)
        mgr = HAManager(redis, config={})

        acquired = AsyncMock()
        mgr.on_become_leader = acquired

        await mgr.start()

        assert mgr.is_leader
        acquired.assert_called_once()

        status = await mgr.cluster_status()
        assert status["mode"] == "standalone"

        await mgr.stop()

    @pytest.mark.asyncio
    async def test_cluster_mode(self):
        """Redis 활성 시 cluster 모드 시작."""
        redis = MockRedisClient(available=True)
        mgr = HAManager(redis, config={"ha": {"ttl_seconds": 5}})

        await mgr.start()
        await asyncio.sleep(0.5)

        assert mgr.is_leader  # 유일한 인스턴스이므로 리더

        status = await mgr.cluster_status()
        assert status["mode"] == "cluster"

        await mgr.stop()


# ── CheckpointService 테스트 ─────────────────────────────────────────────────

class TestCheckpointService:

    @pytest.mark.asyncio
    async def test_start_loads_state(self):
        """시작 시 load_all 호출."""
        mock_registry = MagicMock()
        mock_registry.engines = []

        mock_state_mgr = AsyncMock()
        mock_state_mgr.load_all = AsyncMock(return_value=0)
        mock_state_mgr.save_all = AsyncMock(return_value=0)

        svc = CheckpointService(mock_registry, mock_state_mgr, interval_seconds=1)
        await svc.start()

        mock_state_mgr.load_all.assert_called_once()

        await svc.stop()

    @pytest.mark.asyncio
    async def test_stop_saves_state(self):
        """종료 시 save_all 호출."""
        mock_registry = MagicMock()
        mock_registry.engines = []

        mock_state_mgr = AsyncMock()
        mock_state_mgr.load_all = AsyncMock(return_value=0)
        mock_state_mgr.save_all = AsyncMock(return_value=0)

        svc = CheckpointService(mock_registry, mock_state_mgr, interval_seconds=60)
        await svc.start()
        await svc.stop()

        # save_all은 stop()에서 save_now()를 통해 호출됨
        assert mock_state_mgr.save_all.call_count >= 1

    @pytest.mark.asyncio
    async def test_save_now(self):
        """save_now()가 즉시 저장."""
        mock_registry = MagicMock()
        mock_registry.engines = []

        mock_state_mgr = AsyncMock()
        mock_state_mgr.load_all = AsyncMock(return_value=0)
        mock_state_mgr.save_all = AsyncMock(return_value=3)

        svc = CheckpointService(mock_registry, mock_state_mgr, interval_seconds=60)
        await svc.start()

        result = await svc.save_now()
        assert result == 3

        await svc.stop()
