"""EngineSLAMonitor 단위 테스트.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatcher.detection.engine_sla import EngineSLAMonitor, EngineStats


class TestEngineStats:
    """EngineStats 데이터 클래스 테스트."""

    def test_percentile_empty(self):
        stats = EngineStats()
        assert stats.percentile(50) == 0.0
        assert stats.percentile(99) == 0.0

    def test_percentile_single_value(self):
        stats = EngineStats()
        stats._latencies.append(5.0)
        assert stats.percentile(50) == 5.0
        assert stats.percentile(99) == 5.0

    def test_percentile_multiple_values(self):
        stats = EngineStats()
        for v in range(1, 101):
            stats._latencies.append(float(v))
        p50 = stats.percentile(50)
        p99 = stats.percentile(99)
        assert 49.0 <= p50 <= 51.0
        assert 98.0 <= p99 <= 100.0


class TestEngineSLAMonitor:
    """EngineSLAMonitor 테스트."""

    def test_record_and_get_stats(self):
        monitor = EngineSLAMonitor(sla_ms=10.0)
        monitor.record("test_engine", 5.0, True)
        monitor.record("test_engine", 8.0, True)

        stats = monitor.get_stats("test_engine")
        assert stats["call_count"] == 2
        assert stats["success_count"] == 2
        assert stats["failure_count"] == 0
        assert stats["max_latency_ms"] == 8.0
        assert stats["consecutive_breaches"] == 0
        assert stats["circuit_open"] is False

    def test_get_stats_unknown_engine(self):
        monitor = EngineSLAMonitor()
        assert monitor.get_stats("nonexistent") == {}

    def test_sla_breach_increments_consecutive(self):
        monitor = EngineSLAMonitor(sla_ms=5.0, breach_threshold=3)
        monitor.record("eng", 6.0, True)  # breach
        monitor.record("eng", 7.0, True)  # breach

        stats = monitor.get_stats("eng")
        assert stats["consecutive_breaches"] == 2
        assert stats["circuit_open"] is False

    def test_sla_compliance_resets_breaches(self):
        monitor = EngineSLAMonitor(sla_ms=5.0, breach_threshold=10)
        monitor.record("eng", 6.0, True)  # breach
        monitor.record("eng", 6.0, True)  # breach
        monitor.record("eng", 3.0, True)  # OK -> reset

        stats = monitor.get_stats("eng")
        assert stats["consecutive_breaches"] == 0

    def test_circuit_opens_on_threshold(self):
        monitor = EngineSLAMonitor(sla_ms=5.0, breach_threshold=3, cooldown_seconds=60.0)
        for _ in range(3):
            monitor.record("eng", 10.0, True)

        assert monitor.is_circuit_open("eng") is True

    def test_circuit_closes_after_cooldown(self):
        monitor = EngineSLAMonitor(sla_ms=5.0, breach_threshold=2, cooldown_seconds=0.1)
        monitor.record("eng", 10.0, True)
        monitor.record("eng", 10.0, True)

        assert monitor.is_circuit_open("eng") is True

        # 쿨다운 경과 시뮬레이션
        time.sleep(0.15)
        assert monitor.is_circuit_open("eng") is False

    def test_failure_counts_as_breach(self):
        monitor = EngineSLAMonitor(sla_ms=100.0, breach_threshold=2)
        monitor.record("eng", 1.0, False)  # 빠르지만 실패 -> breach
        monitor.record("eng", 1.0, False)

        assert monitor.is_circuit_open("eng") is True
        stats = monitor.get_stats("eng")
        assert stats["failure_count"] == 2

    def test_get_all_stats(self):
        monitor = EngineSLAMonitor()
        monitor.record("a", 1.0, True)
        monitor.record("b", 2.0, True)

        all_stats = monitor.get_all_stats()
        assert "a" in all_stats
        assert "b" in all_stats
        assert all_stats["a"]["call_count"] == 1
        assert all_stats["b"]["call_count"] == 1

    def test_is_circuit_open_unknown_engine(self):
        monitor = EngineSLAMonitor()
        assert monitor.is_circuit_open("unknown") is False

    def test_avg_latency(self):
        monitor = EngineSLAMonitor()
        monitor.record("eng", 10.0, True)
        monitor.record("eng", 20.0, True)

        stats = monitor.get_stats("eng")
        assert stats["avg_latency_ms"] == 15.0

    def test_percentile_stats(self):
        monitor = EngineSLAMonitor()
        for i in range(100):
            monitor.record("eng", float(i + 1), True)

        stats = monitor.get_stats("eng")
        assert stats["p50_ms"] > 0
        assert stats["p95_ms"] > stats["p50_ms"]
        assert stats["p99_ms"] >= stats["p95_ms"]
