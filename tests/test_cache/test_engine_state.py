"""EngineStateManager 단위 테스트 -- Redis 서버 불필요 (모킹)."""

from __future__ import annotations

import json
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import Any

from netwatcher.cache.redis_client import RedisClient
from netwatcher.cache.engine_state import EngineStateManager

# scapy가 설치되지 않은 환경에서도 테스트 가능하도록 모킹
_scapy_mocked = False
if "scapy" not in sys.modules:
    _scapy_mocked = True
    sys.modules["scapy"]     = MagicMock()
    sys.modules["scapy.all"] = MagicMock()

from netwatcher.detection.base import DetectionEngine

# 모킹 후 즉시 정리하여 다른 테스트 모듈의 scapy import를 오염시키지 않음
if _scapy_mocked:
    # DetectionEngine이 이미 로드되었으므로 모킹 모듈을 제거해도 안전
    del sys.modules["scapy.all"]
    del sys.modules["scapy"]


class DummyEngine(DetectionEngine):
    """테스트용 더미 엔진 (상태 영속성 미지원)."""

    name        = "dummy"
    description = "test engine"

    def analyze(self, packet: Any) -> None:
        return None


class StatefulEngine(DetectionEngine):
    """테스트용 상태 영속성 지원 엔진."""

    name        = "stateful"
    description = "test engine with state"

    def __init__(self) -> None:
        super().__init__({"enabled": True})
        self.counter = 0
        self.data: list[str] = []

    def analyze(self, packet: Any) -> None:
        return None

    def export_state(self) -> dict | None:
        return {"counter": self.counter, "data": self.data}

    def import_state(self, state: dict) -> None:
        self.counter = state.get("counter", 0)
        self.data    = state.get("data", [])


class FailingImportEngine(DetectionEngine):
    """import_state에서 예외를 발생시키는 엔진."""

    name        = "failing"
    description = "engine that fails on import"

    def __init__(self) -> None:
        super().__init__({"enabled": True})

    def analyze(self, packet: Any) -> None:
        return None

    def export_state(self) -> dict | None:
        return {"some": "state"}

    def import_state(self, state: dict) -> None:
        raise ValueError("bad state")


@pytest.fixture
def unavailable_redis() -> RedisClient:
    """비활성 RedisClient."""
    client = RedisClient(enabled=False)
    return client


@pytest.fixture
def mock_redis() -> RedisClient:
    """사용 가능 상태의 모킹된 RedisClient."""
    client = RedisClient(enabled=True, key_prefix="t:")
    client._available = True
    client.setex  = AsyncMock(return_value=True)
    client.get    = AsyncMock(return_value=None)
    client.delete = AsyncMock(return_value=True)
    return client


class TestEngineStateManagerUnavailable:
    """Redis 미사용 시 테스트."""

    @pytest.mark.asyncio
    async def test_save_returns_false(self, unavailable_redis: RedisClient) -> None:
        mgr = EngineStateManager(unavailable_redis)
        assert await mgr.save_state("test", {"k": "v"}) is False

    @pytest.mark.asyncio
    async def test_load_returns_none(self, unavailable_redis: RedisClient) -> None:
        mgr = EngineStateManager(unavailable_redis)
        assert await mgr.load_state("test") is None


class TestSaveState:
    """상태 저장 테스트."""

    @pytest.mark.asyncio
    async def test_save_state_success(self, mock_redis: RedisClient) -> None:
        mgr = EngineStateManager(mock_redis, interval_seconds=30)
        state = {"counter": 42, "items": ["a", "b"]}

        result = await mgr.save_state("my_engine", state)
        assert result is True
        mock_redis.setex.assert_called_once()

        # TTL = interval * 3
        call_args = mock_redis.setex.call_args
        assert call_args[0][1] == 90  # 30 * 3

    @pytest.mark.asyncio
    async def test_save_state_json_serialization(self, mock_redis: RedisClient) -> None:
        mgr   = EngineStateManager(mock_redis, interval_seconds=60)
        state = {"counter": 10, "name": "test"}

        await mgr.save_state("eng", state)

        call_args = mock_redis.setex.call_args
        saved_data = json.loads(call_args[0][2])
        assert saved_data["counter"] == 10
        assert saved_data["name"] == "test"

    @pytest.mark.asyncio
    async def test_save_state_exception_returns_false(self, mock_redis: RedisClient) -> None:
        mock_redis.setex = AsyncMock(side_effect=ConnectionError("broken"))
        mgr = EngineStateManager(mock_redis)

        result = await mgr.save_state("eng", {"k": "v"})
        assert result is False


class TestLoadState:
    """상태 로드 테스트."""

    @pytest.mark.asyncio
    async def test_load_state_success(self, mock_redis: RedisClient) -> None:
        state_data = {"counter": 42, "items": ["x"]}
        mock_redis.get = AsyncMock(return_value=json.dumps(state_data).encode())

        mgr    = EngineStateManager(mock_redis)
        result = await mgr.load_state("my_engine")
        assert result == state_data

    @pytest.mark.asyncio
    async def test_load_state_miss(self, mock_redis: RedisClient) -> None:
        mock_redis.get = AsyncMock(return_value=None)

        mgr    = EngineStateManager(mock_redis)
        result = await mgr.load_state("missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_load_state_invalid_json(self, mock_redis: RedisClient) -> None:
        mock_redis.get = AsyncMock(return_value=b"not-json{{{")

        mgr    = EngineStateManager(mock_redis)
        result = await mgr.load_state("broken")
        assert result is None

    @pytest.mark.asyncio
    async def test_load_state_exception_returns_none(self, mock_redis: RedisClient) -> None:
        mock_redis.get = AsyncMock(side_effect=ConnectionError("broken"))

        mgr    = EngineStateManager(mock_redis)
        result = await mgr.load_state("eng")
        assert result is None


class TestSaveAll:
    """save_all 테스트."""

    @pytest.mark.asyncio
    async def test_save_all_stateful_engines(self, mock_redis: RedisClient) -> None:
        dummy    = DummyEngine({"enabled": True})
        stateful = StatefulEngine()
        stateful.counter = 99

        mgr   = EngineStateManager(mock_redis)
        count = await mgr.save_all([dummy, stateful])

        # dummy는 export_state() -> None이므로 저장 안 됨
        assert count == 1

    @pytest.mark.asyncio
    async def test_save_all_no_stateful(self, mock_redis: RedisClient) -> None:
        dummy = DummyEngine({"enabled": True})
        mgr   = EngineStateManager(mock_redis)
        count = await mgr.save_all([dummy])
        assert count == 0


class TestLoadAll:
    """load_all 테스트."""

    @pytest.mark.asyncio
    async def test_load_all_restores_state(self, mock_redis: RedisClient) -> None:
        state_data = {"counter": 77, "data": ["restored"]}
        mock_redis.get = AsyncMock(return_value=json.dumps(state_data).encode())

        stateful = StatefulEngine()
        mgr      = EngineStateManager(mock_redis)
        count    = await mgr.load_all([stateful])

        assert count == 1
        assert stateful.counter == 77
        assert stateful.data == ["restored"]

    @pytest.mark.asyncio
    async def test_load_all_skips_non_stateful(self, mock_redis: RedisClient) -> None:
        dummy = DummyEngine({"enabled": True})
        mgr   = EngineStateManager(mock_redis)
        count = await mgr.load_all([dummy])
        assert count == 0

    @pytest.mark.asyncio
    async def test_load_all_handles_import_failure(self, mock_redis: RedisClient) -> None:
        state_data = {"some": "state"}
        mock_redis.get = AsyncMock(return_value=json.dumps(state_data).encode())

        failing = FailingImportEngine()
        mgr     = EngineStateManager(mock_redis)
        count   = await mgr.load_all([failing])

        assert count == 0  # import_state 실패


class TestBaseEngineStateMethods:
    """DetectionEngine base class의 export_state/import_state 테스트."""

    def test_default_export_state_returns_none(self) -> None:
        engine = DummyEngine({"enabled": True})
        assert engine.export_state() is None

    def test_default_import_state_noop(self) -> None:
        engine = DummyEngine({"enabled": True})
        engine.import_state({"any": "data"})  # should not raise

    def test_interval_property(self, mock_redis: RedisClient) -> None:
        mgr = EngineStateManager(mock_redis, interval_seconds=120)
        assert mgr.interval == 120
