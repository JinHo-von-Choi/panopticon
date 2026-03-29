"""AsyncEngineRegistry 테스트.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from scapy.all import IP, TCP, Ether, Packet

from netwatcher.detection.async_registry import AsyncEngineRegistry
from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.engine_sla import EngineSLAMonitor
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.registry import EngineRegistry
from netwatcher.detection.whitelist import Whitelist
from netwatcher.utils.config import Config


# ---------------------------------------------------------------------------
# 테스트용 엔진
# ---------------------------------------------------------------------------


class FastEngine(DetectionEngine):
    """fast 타입 테스트 엔진."""

    name        = "fast_test"
    engine_type = "fast"

    def analyze(self, packet: Packet) -> Alert | None:
        return Alert(
            engine=self.name,
            severity=Severity.INFO,
            title="Fast Alert",
        )


class CpuEngine(DetectionEngine):
    """cpu 타입 테스트 엔진."""

    name        = "cpu_test"
    engine_type = "cpu"

    def analyze(self, packet: Packet) -> Alert | None:
        return Alert(
            engine=self.name,
            severity=Severity.WARNING,
            title="CPU Alert",
        )


class IoEngine(DetectionEngine):
    """io 타입 테스트 엔진 (analyze_async 보유)."""

    name        = "io_test"
    engine_type = "io"

    def analyze(self, packet: Packet) -> Alert | None:
        return None

    async def analyze_async(self, packet: Packet) -> Alert | None:
        await asyncio.sleep(0)
        return Alert(
            engine=self.name,
            severity=Severity.CRITICAL,
            title="IO Alert",
        )


class FailingEngine(DetectionEngine):
    """항상 예외를 발생시키는 테스트 엔진."""

    name        = "failing_test"
    engine_type = "fast"

    def analyze(self, packet: Packet) -> Alert | None:
        raise RuntimeError("Engine failure")


class NoneEngine(DetectionEngine):
    """항상 None을 반환하는 엔진."""

    name        = "none_test"
    engine_type = "cpu"

    def analyze(self, packet: Packet) -> Alert | None:
        return None


# ---------------------------------------------------------------------------
# 픽스처
# ---------------------------------------------------------------------------


def _make_test_packet() -> Packet:
    """테스트용 패킷을 생성한다."""
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)


def _make_registry_with_engines(engines: list[DetectionEngine]) -> EngineRegistry:
    """엔진 목록을 가진 EngineRegistry를 생성한다."""
    config = Config.__new__(Config)
    config._data = {}
    registry = EngineRegistry(config)
    registry._engines = list(engines)
    registry._whitelist = Whitelist()
    return registry


# ---------------------------------------------------------------------------
# 테스트
# ---------------------------------------------------------------------------


class TestAsyncEngineRegistry:
    """AsyncEngineRegistry 비동기 디스패치 테스트."""

    @pytest.mark.asyncio
    async def test_fast_engine_runs_inline(self):
        engine   = FastEngine({})
        registry = _make_registry_with_engines([engine])
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 1
        assert alerts[0].engine == "fast_test"
        assert alerts[0].title == "Fast Alert"

    @pytest.mark.asyncio
    async def test_cpu_engine_runs_in_executor(self):
        engine   = CpuEngine({})
        registry = _make_registry_with_engines([engine])
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 1
        assert alerts[0].engine == "cpu_test"

    @pytest.mark.asyncio
    async def test_io_engine_runs_as_coroutine(self):
        engine   = IoEngine({})
        registry = _make_registry_with_engines([engine])
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 1
        assert alerts[0].engine == "io_test"
        assert alerts[0].title == "IO Alert"

    @pytest.mark.asyncio
    async def test_mixed_engine_types(self):
        engines  = [FastEngine({}), CpuEngine({}), IoEngine({})]
        registry = _make_registry_with_engines(engines)
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        engine_names = {a.engine for a in alerts}
        assert engine_names == {"fast_test", "cpu_test", "io_test"}

    @pytest.mark.asyncio
    async def test_failing_engine_does_not_crash(self):
        engines  = [FailingEngine({}), FastEngine({})]
        registry = _make_registry_with_engines(engines)
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 1
        assert alerts[0].engine == "fast_test"

    @pytest.mark.asyncio
    async def test_none_result_excluded(self):
        engines  = [NoneEngine({}), FastEngine({})]
        registry = _make_registry_with_engines(engines)
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 1
        assert alerts[0].engine == "fast_test"

    @pytest.mark.asyncio
    async def test_circuit_breaker_skips_engine(self):
        engine   = FastEngine({})
        registry = _make_registry_with_engines([engine])
        sla      = EngineSLAMonitor(sla_ms=0.001, breach_threshold=1, cooldown_seconds=60.0)
        # 사전에 SLA 위반 기록하여 서킷 오픈
        sla.record("fast_test", 100.0, True)
        async_reg = AsyncEngineRegistry(registry, sla_monitor=sla)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_disabled_engine_skipped(self):
        engine         = FastEngine({"enabled": False})
        engine.enabled = False
        registry       = _make_registry_with_engines([engine])
        async_reg      = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_sla_monitor_records_latency(self):
        engine   = FastEngine({})
        registry = _make_registry_with_engines([engine])
        sla      = EngineSLAMonitor()
        async_reg = AsyncEngineRegistry(registry, sla_monitor=sla)

        packet = _make_test_packet()
        await async_reg.process_packet_async(packet)

        stats = sla.get_stats("fast_test")
        assert stats["call_count"] == 1
        assert stats["success_count"] == 1

    @pytest.mark.asyncio
    async def test_sla_monitor_property(self):
        registry  = _make_registry_with_engines([])
        sla       = EngineSLAMonitor()
        async_reg = AsyncEngineRegistry(registry, sla_monitor=sla)
        assert async_reg.sla_monitor is sla

    @pytest.mark.asyncio
    async def test_whitelist_ip_skipped(self):
        engine   = FastEngine({})
        registry = _make_registry_with_engines([engine])
        wl       = Whitelist({"ips": ["10.0.0.1"]})
        registry._whitelist = wl
        async_reg = AsyncEngineRegistry(registry)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_custom_executor(self):
        engine   = CpuEngine({})
        registry = _make_registry_with_engines([engine])
        executor = ThreadPoolExecutor(max_workers=2)
        async_reg = AsyncEngineRegistry(registry, executor=executor)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 1
        executor.shutdown(wait=False)

    @pytest.mark.asyncio
    async def test_shutdown(self):
        registry  = _make_registry_with_engines([])
        async_reg = AsyncEngineRegistry(registry)
        # shutdown이 예외 없이 완료되는지 확인
        async_reg.shutdown()

    @pytest.mark.asyncio
    async def test_failing_cpu_engine_records_failure(self):
        """CPU 타입 실패 엔진의 SLA 기록 검증."""
        engine        = FailingEngine({})
        engine.engine_type = "cpu"
        registry      = _make_registry_with_engines([engine])
        sla           = EngineSLAMonitor()
        async_reg     = AsyncEngineRegistry(registry, sla_monitor=sla)

        packet = _make_test_packet()
        alerts = await async_reg.process_packet_async(packet)

        assert len(alerts) == 0
        stats = sla.get_stats("failing_test")
        assert stats["call_count"] == 1
        assert stats["failure_count"] == 1
