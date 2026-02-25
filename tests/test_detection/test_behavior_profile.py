"""Tests for multi-dimensional host behavior profiling engine.

작성자: 최진호
작성일: 2026-02-20
"""

import time

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw

from netwatcher.detection.engines.behavior_profile import (
    BehaviorProfileEngine,
    _HostProfile,
    _WelfordStats,
)
from netwatcher.detection.models import Severity


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_tcp_packet(
    src: str = "192.168.1.10",
    dst: str = "1.2.3.4",
    dport: int = 443,
    size: int = 500,
) -> Ether:
    """Build a TCP packet with specified payload size."""
    payload_size = max(0, size - 54)  # subtract IP+TCP header estimate
    return (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=12345, dport=dport)
        / Raw(load=b"X" * payload_size)
    )


def _make_dns_packet(
    src: str = "192.168.1.10",
    dst: str = "8.8.8.8",
) -> Ether:
    """Build a DNS query packet."""
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )


def _default_config(**overrides: object) -> dict:
    """Return a default engine config with optional overrides."""
    cfg = {
        "enabled": True,
        "warmup_ticks": 10,          # low for fast tests
        "z_threshold": 3.5,
        "max_tracked_hosts": 10000,
        "eviction_seconds": 86400,
    }
    cfg.update(overrides)
    return cfg


# ===========================================================================
# _WelfordStats unit tests
# ===========================================================================

class TestWelfordStats:
    def test_welford_single_value(self):
        """n=1: variance=0, z_score=0 for any value."""
        w = _WelfordStats()
        w.update(42.0)

        assert w.n == 1
        assert w.mean == 42.0
        assert w.variance == 0.0
        assert w.std_dev == 0.0
        assert w.z_score(100.0) == 0.0

    def test_welford_multiple_values(self):
        """n=5: mean and variance should be mathematically correct."""
        w = _WelfordStats()
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        for v in values:
            w.update(v)

        assert w.n == 5
        assert w.mean == pytest.approx(30.0)
        # sample variance of [10,20,30,40,50] = 250.0
        assert w.variance == pytest.approx(250.0)
        assert w.std_dev == pytest.approx(250.0 ** 0.5)

    def test_welford_z_score(self):
        """A value far from the mean should yield a high Z-score."""
        w = _WelfordStats()
        for v in [10.0, 20.0, 30.0, 40.0, 50.0]:
            w.update(v)

        # z_score of 100 = |100 - 30| / sqrt(250) ~ 4.43
        z = w.z_score(100.0)
        assert z == pytest.approx(70.0 / (250.0 ** 0.5), rel=1e-6)
        assert z > 3.5  # clearly anomalous

    def test_welford_z_score_zero_variance(self):
        """When all values are identical, variance=0; deviation yields inf, same value yields 0."""
        w = _WelfordStats()
        for _ in range(10):
            w.update(5.0)

        assert w.variance == pytest.approx(0.0)
        assert w.z_score(5.0) == 0.0           # same value: no anomaly
        assert w.z_score(999.0) == float("inf") # any deviation: anomalous


# ===========================================================================
# BehaviorProfileEngine tests
# ===========================================================================

class TestBehaviorProfileEngine:
    def setup_method(self):
        self.engine = BehaviorProfileEngine(_default_config())

    # -------------------------------------------------------------------
    # Warmup / baseline
    # -------------------------------------------------------------------

    def test_warmup_period_no_alert(self):
        """During warmup period, even anomalous traffic should NOT alert."""
        warmup = self.engine._warmup_ticks  # 10

        for tick in range(warmup):
            # Send consistent traffic during warmup
            for _ in range(5):
                self.engine.analyze(_make_tcp_packet(size=500))
            alerts = self.engine.on_tick(float(tick))
            assert alerts == [], f"Should not alert during warmup (tick {tick})"

    def test_normal_traffic_no_alert(self):
        """Consistent traffic after warmup should NOT produce alerts."""
        warmup = self.engine._warmup_ticks

        # Build up baseline
        for tick in range(warmup + 20):
            for _ in range(5):
                self.engine.analyze(_make_tcp_packet(dst="1.2.3.4", dport=443, size=500))
            alerts = self.engine.on_tick(float(tick))

        # After warmup: keep sending the same pattern
        for tick in range(warmup + 20, warmup + 30):
            for _ in range(5):
                self.engine.analyze(_make_tcp_packet(dst="1.2.3.4", dport=443, size=500))
            alerts = self.engine.on_tick(float(tick))
            assert alerts == [], f"Normal traffic should not alert (tick {tick})"

    # -------------------------------------------------------------------
    # Anomaly detection
    # -------------------------------------------------------------------

    def test_sudden_behavior_change_alerts(self):
        """After establishing a baseline, a drastic change should trigger an alert."""
        warmup = self.engine._warmup_ticks

        # Phase 1: stable baseline with natural jitter so std_dev > 0
        # Vary packet count (2-4) and size (80-120) per tick
        for tick in range(warmup + 20):
            pkt_count = 2 + (tick % 3)           # 2, 3, 4 rotating
            pkt_size = 80 + (tick % 5) * 10      # 80, 90, 100, 110, 120
            for _ in range(pkt_count):
                self.engine.analyze(_make_tcp_packet(dst="1.2.3.4", dport=443, size=pkt_size))
            self.engine.on_tick(float(tick))

        # Phase 2: sudden burst -- 100 packets to many different IPs/ports
        for i in range(100):
            self.engine.analyze(
                _make_tcp_packet(
                    dst=f"10.0.{i // 256}.{i % 256}",
                    dport=8000 + i,
                    size=5000,
                )
            )
        alerts = self.engine.on_tick(float(warmup + 20))

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.engine == "behavior_profile"
        assert alert.title == "Host Behavior Anomaly"
        assert alert.source_ip == "192.168.1.10"
        assert alert.severity in (Severity.WARNING, Severity.CRITICAL)
        assert "anomalous_dimensions" in alert.metadata

    def test_multiple_dimensions_critical(self):
        """Changes in 3+ dimensions should produce CRITICAL severity."""
        warmup = self.engine._warmup_ticks

        # Phase 1: stable baseline with natural jitter for non-zero std_dev
        for tick in range(warmup + 30):
            pkt_count = 2 + (tick % 3)           # 2, 3, 4
            pkt_size = 80 + (tick % 5) * 10      # 80..120
            for _ in range(pkt_count):
                self.engine.analyze(_make_tcp_packet(dst="1.2.3.4", dport=443, size=pkt_size))
            self.engine.on_tick(float(tick))

        # Phase 2: massively different on every dimension
        for i in range(200):
            self.engine.analyze(
                _make_tcp_packet(
                    dst=f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}",
                    dport=1024 + i,
                    size=10000,
                )
            )
        # Also inject DNS queries (changes dns_queries_per_tick dimension)
        for _ in range(50):
            self.engine.analyze(_make_dns_packet())

        alerts = self.engine.on_tick(float(warmup + 30))
        assert len(alerts) >= 1

        alert = alerts[0]
        assert alert.severity == Severity.CRITICAL
        anomalous = alert.metadata["anomalous_dimensions"]
        assert len(anomalous) >= 3, (
            f"Expected 3+ anomalous dimensions, got {len(anomalous)}: "
            f"{[d['dimension'] for d in anomalous]}"
        )

    # -------------------------------------------------------------------
    # Eviction
    # -------------------------------------------------------------------

    def test_eviction(self):
        """Hosts unseen for longer than eviction_seconds should be evicted."""
        engine = BehaviorProfileEngine(_default_config(eviction_seconds=10))

        # Send a packet so the host is tracked
        engine.analyze(_make_tcp_packet())
        engine.on_tick(0.0)
        assert "192.168.1.10" in engine._profiles

        # Simulate passage of time beyond eviction threshold
        profile = engine._profiles["192.168.1.10"]
        profile.last_seen = time.time() - 20  # 20 seconds ago

        # on_tick should evict the stale host
        engine.on_tick(1.0)
        assert "192.168.1.10" not in engine._profiles

    # -------------------------------------------------------------------
    # Config & schema
    # -------------------------------------------------------------------

    def test_config_schema(self):
        """All expected config_schema keys must exist."""
        expected_keys = {"warmup_ticks", "z_threshold", "max_tracked_hosts", "eviction_seconds"}
        assert set(self.engine.config_schema.keys()) == expected_keys

    # -------------------------------------------------------------------
    # Shutdown
    # -------------------------------------------------------------------

    def test_shutdown_clears_state(self):
        """shutdown() should clear all tracked profiles."""
        for _ in range(5):
            self.engine.analyze(_make_tcp_packet())
        self.engine.on_tick(0.0)
        assert len(self.engine._profiles) > 0

        self.engine.shutdown()
        assert len(self.engine._profiles) == 0

    # -------------------------------------------------------------------
    # Max tracked hosts / LRU eviction
    # -------------------------------------------------------------------

    def test_max_tracked_hosts(self):
        """New hosts beyond the limit should trigger LRU eviction of the oldest."""
        engine = BehaviorProfileEngine(_default_config(max_tracked_hosts=3))

        # Add 4 hosts
        for i in range(4):
            engine.analyze(_make_tcp_packet(src=f"10.0.0.{i}"))

        assert len(engine._profiles) == 3
        # The first host (10.0.0.0) should have been evicted (LRU)
        assert "10.0.0.0" not in engine._profiles
        # The last three should remain
        assert "10.0.0.1" in engine._profiles
        assert "10.0.0.2" in engine._profiles
        assert "10.0.0.3" in engine._profiles

    # -------------------------------------------------------------------
    # analyze() always returns None
    # -------------------------------------------------------------------

    def test_analyze_returns_none(self):
        """analyze() should always return None (alerts come from on_tick)."""
        pkt = _make_tcp_packet()
        result = self.engine.analyze(pkt)
        assert result is None

    # -------------------------------------------------------------------
    # DNS query counting
    # -------------------------------------------------------------------

    def test_dns_query_counted(self):
        """DNS query packets should increment tick_dns_count."""
        self.engine.analyze(_make_dns_packet())
        profile = self.engine._profiles["192.168.1.10"]
        assert profile.tick_dns_count == 1

    # -------------------------------------------------------------------
    # Accumulator reset
    # -------------------------------------------------------------------

    def test_accumulators_reset_after_tick(self):
        """Tick accumulators should be zeroed after on_tick processes them."""
        for _ in range(3):
            self.engine.analyze(_make_tcp_packet())
        self.engine.analyze(_make_dns_packet())

        profile = self.engine._profiles["192.168.1.10"]
        assert profile.tick_packets == 4
        assert profile.tick_dns_count == 1

        self.engine.on_tick(0.0)

        assert profile.tick_packets == 0
        assert profile.tick_bytes == 0
        assert profile.tick_dns_count == 0
        assert len(profile.tick_dst_ips) == 0
        assert len(profile.tick_dst_ports) == 0
        assert profile.tick_pkt_size_sum == 0
        assert profile.tick_pkt_size_count == 0

    def test_zero_variance_baseline_still_alerts(self):
        """Uniform baseline must not permanently suppress anomaly detection."""
        engine = BehaviorProfileEngine(_default_config(warmup_ticks=10))

        # Phase 1: perfectly uniform traffic (zero variance)
        for tick in range(15):
            for _ in range(5):
                engine.analyze(_make_tcp_packet(dst="1.2.3.4", dport=443, size=500))
            engine.on_tick(float(tick))

        # Phase 2: massive burst on many different IPs/ports
        for i in range(500):
            engine.analyze(
                _make_tcp_packet(
                    dst=f"10.0.{i // 256}.{i % 256}",
                    dport=8000 + i,
                    size=9000,
                )
            )
        alerts = engine.on_tick(15.0)
        assert len(alerts) >= 1, "Zero-variance baseline must not permanently blind the engine"
