"""Tests for HTTP suspicious traffic detection engine."""

import time
from unittest.mock import patch

from scapy.all import IP, TCP, Raw, Ether

from netwatcher.detection.engines.http_suspicious import HTTPSuspiciousEngine
from netwatcher.detection.models import Severity


def _make_http_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "1.2.3.4",
    dport: int = 80,
    payload: bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
) -> Ether:
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=dport, flags="PA")
        / Raw(load=payload)
    )


class TestHTTPSuspiciousEngine:
    def setup_method(self):
        self.engine = HTTPSuspiciousEngine({
            "enabled": True,
            "beacon_interval_tolerance": 0.15,
            "min_beacon_count": 5,
            "beacon_window_seconds": 3600,
            "max_tracked_pairs": 5000,
        })

    def test_no_alert_on_normal_http(self):
        pkt = _make_http_packet(payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_no_alert_on_non_http_port(self):
        pkt = _make_http_packet(dport=443, payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_no_alert_on_non_raw_packet(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="1.2.3.4") / TCP(dport=80)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_no_alert_on_non_http_payload(self):
        pkt = _make_http_packet(payload=b"\x00\x01\x02binary data")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_detects_suspicious_domain_adware(self):
        pkt = _make_http_packet(
            payload=b"GET /ad HTTP/1.1\r\nHost: evil-adserv.example.com\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Suspicious HTTP Request" in alert.title
        assert "adserv" in alert.metadata["host"]

    def test_detects_suspicious_domain_tracking(self):
        pkt = _make_http_packet(
            payload=b"GET /px HTTP/1.1\r\nHost: clicktracking.example.com\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING

    def test_detects_suspicious_domain_malware(self):
        pkt = _make_http_packet(
            payload=b"GET /c2 HTTP/1.1\r\nHost: malware-c2.example.com\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None

    def test_port_8080_detected(self):
        pkt = _make_http_packet(
            dport=8080,
            payload=b"GET /px HTTP/1.1\r\nHost: adserv.example.com\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None

    def test_beacon_detection(self):
        """Regular-interval connections to the same host trigger beacon alert."""
        base_time = 1000000.0
        interval  = 60.0  # 60s interval

        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for i in range(6):
                mock_time.time.return_value = base_time + i * interval
                pkt = _make_http_packet(
                    payload=b"GET / HTTP/1.1\r\nHost: c2.evil.com\r\n\r\n",
                )
                self.engine.analyze(pkt)

            # on_tick should detect the beacon
            mock_time.time.return_value = base_time + 6 * interval
            alerts = self.engine.on_tick(0)

        assert len(alerts) >= 1
        beacon_alert = alerts[0]
        assert beacon_alert.severity == Severity.CRITICAL
        assert "Beacon" in beacon_alert.title
        assert beacon_alert.metadata["host"] == "c2.evil.com"
        assert beacon_alert.metadata["connection_count"] == 6

    def test_beacon_not_triggered_below_min_count(self):
        """Fewer connections than min_beacon_count should not alert."""
        base_time = 1000000.0
        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for i in range(3):  # Below min_beacon_count=5
                mock_time.time.return_value = base_time + i * 60.0
                pkt = _make_http_packet(
                    payload=b"GET / HTTP/1.1\r\nHost: c2.evil.com\r\n\r\n",
                )
                self.engine.analyze(pkt)

            mock_time.time.return_value = base_time + 300
            alerts = self.engine.on_tick(0)

        assert len(alerts) == 0

    def test_beacon_not_triggered_irregular_intervals(self):
        """Irregular intervals should not trigger beacon detection."""
        base_time = 1000000.0
        irregular_offsets = [0, 10, 50, 200, 201, 500]

        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for offset in irregular_offsets:
                mock_time.time.return_value = base_time + offset
                pkt = _make_http_packet(
                    payload=b"GET / HTTP/1.1\r\nHost: normal.example.com\r\n\r\n",
                )
                self.engine.analyze(pkt)

            mock_time.time.return_value = base_time + 600
            alerts = self.engine.on_tick(0)

        assert len(alerts) == 0

    def test_known_periodic_domain_skipped(self):
        """Known OS connectivity-check domains should not trigger beacon."""
        base_time = 1000000.0
        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for i in range(10):
                mock_time.time.return_value = base_time + i * 30.0
                pkt = _make_http_packet(
                    payload=b"GET / HTTP/1.1\r\nHost: connectivity-check.ubuntu.com\r\n\r\n",
                )
                self.engine.analyze(pkt)

            mock_time.time.return_value = base_time + 400
            alerts = self.engine.on_tick(0)

        assert len(alerts) == 0

    def test_max_tracked_pairs_limit(self):
        """Engine respects max_tracked_pairs to bound memory usage."""
        engine = HTTPSuspiciousEngine({
            "enabled": True,
            "max_tracked_pairs": 3,
            "min_beacon_count": 5,
        })

        # Fill up tracked pairs
        for i in range(5):
            pkt = _make_http_packet(
                src_ip=f"10.0.0.{i}",
                payload=f"GET / HTTP/1.1\r\nHost: host{i}.com\r\n\r\n".encode(),
            )
            engine.analyze(pkt)

        # Should have capped at 3
        assert engine._total_pairs <= 3

    def test_shutdown_clears_state(self):
        pkt = _make_http_packet(
            payload=b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
        )
        self.engine.analyze(pkt)
        assert self.engine._total_pairs > 0

        self.engine.shutdown()
        assert self.engine._total_pairs == 0
        assert len(self.engine._host_times) == 0
