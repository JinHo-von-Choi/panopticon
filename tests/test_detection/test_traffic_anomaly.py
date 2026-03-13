"""Tests for traffic anomaly detection engine."""

import time
from unittest.mock import patch

from scapy.all import ARP, IP, TCP, Ether

import pytest
from netwatcher.detection.engines.traffic_anomaly import (
    TrafficAnomalyEngine,
)
from netwatcher.detection.models import Severity
from netwatcher.detection.whitelist import Whitelist


def _make_tcp_packet(
    src_mac: str = "aa:bb:cc:dd:ee:01",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "1.2.3.4",
    size: int = 100,
) -> Ether:
    payload_size = max(0, size - 54)  # Ether(14) + IP(20) + TCP(20)
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=80, flags="PA")
        / (b"\x00" * payload_size)
    )


def _make_arp_packet(src_mac: str, src_ip: str) -> Ether:
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=src_mac, psrc=src_ip)
    )


@pytest.mark.skip(reason="internal symbol _WelfordStats removed in refactor")
class TestWelfordStats:
    def test_initial_state(self):
        pass

    def test_single_value(self):
        pass

    def test_multiple_values(self):
        pass

    def test_constant_values_zero_variance(self):
        pass


def _make_engine_with_whitelist(engine_cfg: dict, wl_cfg: dict | None = None) -> TrafficAnomalyEngine:
    """whitelist가 주입된 엔진 인스턴스를 생성한다."""
    engine = TrafficAnomalyEngine(engine_cfg)
    if wl_cfg is not None:
        wl = Whitelist(wl_cfg)
    else:
        # 빈 whitelist: 모든 MAC이 미등록 상태로 간주됨
        wl = Whitelist({"ips": [], "ip_ranges": [], "macs": [], "domains": [], "domain_suffixes": []})
    engine.set_whitelist(wl)
    return engine


class TestTrafficAnomalyEngine:
    def setup_method(self):
        self.engine = _make_engine_with_whitelist({
            "enabled": True,
            "zscore_threshold": 3.0,
            "window_seconds": 60,
            "min_data_points": 10,
        })

    def test_new_device_alert(self):
        """whitelist가 설정되어 있고, 미등록 MAC이면 New Device 알림을 발생시킨다."""
        pkt = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01", src_ip="192.168.1.10")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "New Device" in alert.title or "New" in alert.title
        assert alert.source_mac == "aa:bb:cc:dd:ee:01"

    def test_known_device_no_alert(self):
        """동일 MAC은 두 번째 이후 알림을 발생시키지 않는다."""
        pkt = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01")
        self.engine.analyze(pkt)  # First time: alert

        pkt2 = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01")
        alert = self.engine.analyze(pkt2)
        assert alert is None

    def test_broadcast_mac_ignored(self):
        pkt = Ether(src="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="1.2.3.4") / TCP()
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_arp_device_detection(self):
        """ARP 패킷의 src MAC도 신규 장치로 탐지한다."""
        pkt = _make_arp_packet("aa:bb:cc:dd:ee:02", "192.168.1.20")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "New Device" in alert.title or "New" in alert.title

    def test_volume_anomaly_z_score(self):
        """min_data_points 이상 이력이 쌓인 후, 트래픽 급증 시 Z-score 기반 이상 탐지."""
        engine = _make_engine_with_whitelist({
            "enabled": True,
            "zscore_threshold": 2.0,
            "window_seconds": 60,
            "min_data_points": 10,
        })

        base_time = 1000.0
        with patch("netwatcher.detection.engines.traffic_anomaly.time") as mock_time:
            # 10개 윈도우 동안 정상 트래픽 기록 (약간의 변동 포함, stdev > 0 보장)
            normal_counts = [2, 3, 2, 3, 2, 3, 2, 3, 2, 3]
            for i in range(10):
                mock_time.time.return_value = base_time + i * 60
                engine._last_window_end = base_time + i * 60
                for _ in range(normal_counts[i]):
                    pkt = _make_tcp_packet(size=200)
                    engine.analyze(pkt)
                # 윈도우 종료 트리거
                mock_time.time.return_value = base_time + (i + 1) * 60
                engine.on_tick(0)

            # 11번째 윈도우에서 트래픽 급증 (100패킷)
            mock_time.time.return_value = base_time + 10 * 60
            engine._last_window_end = base_time + 10 * 60
            for _ in range(100):
                pkt = _make_tcp_packet(size=2000)
                engine.analyze(pkt)

            mock_time.time.return_value = base_time + 11 * 60
            alerts = engine.on_tick(0)

        anomaly_alerts = [a for a in alerts if "Volume" in a.title]
        assert len(anomaly_alerts) >= 1
        assert anomaly_alerts[0].severity == Severity.WARNING
        assert anomaly_alerts[0].metadata["z_score"] > 2.0

    def test_no_anomaly_during_warmup(self):
        """min_data_points 미만 이력에서는 트래픽 급증이 있어도 알림을 발생시키지 않는다."""
        engine = _make_engine_with_whitelist({
            "enabled": True,
            "zscore_threshold": 3.0,
            "window_seconds": 60,
            "min_data_points": 10,
        })

        base_time = 1000.0
        with patch("netwatcher.detection.engines.traffic_anomaly.time") as mock_time:
            # 2개 윈도우만 기록 (min_data_points=10 미만)
            for i in range(2):
                mock_time.time.return_value = base_time + i * 60
                engine._last_window_end = base_time + i * 60
                pkt = _make_tcp_packet(size=200)
                engine.analyze(pkt)
                mock_time.time.return_value = base_time + (i + 1) * 60
                engine.on_tick(0)

            # 3번째 윈도우에서 급증
            mock_time.time.return_value = base_time + 2 * 60
            engine._last_window_end = base_time + 2 * 60
            for _ in range(50):
                pkt = _make_tcp_packet(size=5000)
                engine.analyze(pkt)

            mock_time.time.return_value = base_time + 3 * 60
            alerts = engine.on_tick(0)

        anomaly_alerts = [a for a in alerts if "Volume" in a.title]
        assert len(anomaly_alerts) == 0

    def test_normal_traffic_no_anomaly(self):
        """일정한 트래픽은 이상 알림을 발생시키지 않는다."""
        engine = _make_engine_with_whitelist({
            "enabled": True,
            "zscore_threshold": 3.0,
            "window_seconds": 60,
            "min_data_points": 10,
        })

        base_time = 1000.0
        with patch("netwatcher.detection.engines.traffic_anomaly.time") as mock_time:
            for i in range(15):
                mock_time.time.return_value = base_time + i * 60
                engine._last_window_end = base_time + i * 60
                for _ in range(5):
                    pkt = _make_tcp_packet(size=500)
                    engine.analyze(pkt)
                mock_time.time.return_value = base_time + (i + 1) * 60
                alerts = engine.on_tick(0)
                anomaly_alerts = [a for a in alerts if "Volume" in a.title]
                assert len(anomaly_alerts) == 0

    def test_global_bytes_tracked(self):
        """패킷 분석 시 글로벌 바이트 카운터가 증가한다."""
        pkt = _make_tcp_packet(src_ip="192.168.1.10", size=500)
        self.engine.analyze(pkt)
        assert self.engine._current_bytes > 0

    def test_global_counters_reset_on_window_end(self):
        """윈도우 종료 시 글로벌 카운터가 리셋된다."""
        engine = _make_engine_with_whitelist({
            "enabled": True,
            "zscore_threshold": 3.0,
            "window_seconds": 60,
            "min_data_points": 10,
        })

        base_time = 1000.0
        with patch("netwatcher.detection.engines.traffic_anomaly.time") as mock_time:
            mock_time.time.return_value = base_time
            engine._last_window_end = base_time
            pkt = _make_tcp_packet(size=500)
            engine.analyze(pkt)
            assert engine._current_packets == 1

            # 윈도우 종료
            mock_time.time.return_value = base_time + 60
            engine.on_tick(0)
            assert engine._current_packets == 0
            assert engine._current_bytes == 0

    @pytest.mark.skip(reason="per-host eviction 로직이 글로벌 볼륨 추적으로 대체됨")
    def test_eviction_of_stale_hosts(self):
        pass

    def test_shutdown_clears_state(self):
        pkt = _make_tcp_packet()
        self.engine.analyze(pkt)
        self.engine.on_tick(0)

        self.engine.shutdown()
        assert len(self.engine._history) == 0
        assert len(self.engine._new_devices_alerted) == 0
