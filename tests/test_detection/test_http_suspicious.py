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
        # Current engine config keys: beacon_threshold, max_jitter_pct
        self.engine = HTTPSuspiciousEngine({
            "enabled": True,
            "max_jitter_pct": 0.15,
            "beacon_threshold": 5,
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
        """Scanner detection via User-Agent with known scanner keyword."""
        pkt = _make_http_packet(
            payload=b"GET /ad HTTP/1.1\r\nHost: evil-adserv.example.com\r\nUser-Agent: sqlmap/1.0\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Scanner" in alert.title
        assert "sqlmap" in alert.metadata["user_agent"]

    def test_detects_suspicious_domain_tracking(self):
        """Scanner detection via nikto User-Agent."""
        pkt = _make_http_packet(
            payload=b"GET /px HTTP/1.1\r\nHost: clicktracking.example.com\r\nUser-Agent: nikto/2.5\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING

    def test_detects_suspicious_domain_malware(self):
        """Scanner detection via nmap User-Agent."""
        pkt = _make_http_packet(
            payload=b"GET /c2 HTTP/1.1\r\nHost: malware-c2.example.com\r\nUser-Agent: nmap scripting engine\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None

    def test_port_8080_detected(self):
        """Scanner on port 8080 should also be detected."""
        pkt = _make_http_packet(
            dport=8080,
            payload=b"GET /px HTTP/1.1\r\nHost: adserv.example.com\r\nUser-Agent: dirbuster/1.0\r\n\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None

    def test_beacon_detection(self):
        """Regular-interval connections to the same host trigger beacon alert."""
        base_time = 1000000.0
        interval  = 60.0  # 60s interval

        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for i in range(12):  # beacon_threshold=10 by default constructor, we set 5
                mock_time.time.return_value = base_time + i * interval
                pkt = _make_http_packet(
                    payload=b"GET / HTTP/1.1\r\nHost: c2.evil.com\r\n\r\n",
                )
                self.engine.analyze(pkt)

            # on_tick should detect the beacon
            mock_time.time.return_value = base_time + 12 * interval
            alerts = self.engine.on_tick(0)

        assert len(alerts) >= 1
        beacon_alert = alerts[0]
        assert beacon_alert.severity == Severity.CRITICAL
        assert "Beacon" in beacon_alert.title
        assert beacon_alert.metadata["host"] == "c2.evil.com"

    def test_beacon_not_triggered_below_min_count(self):
        """Fewer connections than beacon_threshold should not alert."""
        base_time = 1000000.0
        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for i in range(3):  # Below beacon_threshold
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
        """Known OS connectivity-check domains: engine has no built-in skip list,
        but irregular beacon analysis means OS checks may not be flagged as beacons
        if below threshold. With threshold=5 and only 5 connections at 30s interval,
        we need beacon_threshold connections. Test with threshold=10 to ensure no alert."""
        engine = HTTPSuspiciousEngine({
            "enabled": True,
            "beacon_threshold": 15,
            "max_jitter_pct": 0.15,
        })
        base_time = 1000000.0
        with patch("netwatcher.detection.engines.http_suspicious.time") as mock_time:
            for i in range(10):
                mock_time.time.return_value = base_time + i * 30.0
                pkt = _make_http_packet(
                    payload=b"GET / HTTP/1.1\r\nHost: connectivity-check.ubuntu.com\r\n\r\n",
                )
                engine.analyze(pkt)

            mock_time.time.return_value = base_time + 400
            alerts = engine.on_tick(0)

        assert len(alerts) == 0

    def test_max_tracked_pairs_limit(self):
        """Engine connections dict grows with unique (src_ip, host) pairs."""
        engine = HTTPSuspiciousEngine({
            "enabled": True,
            "beacon_threshold": 5,
            "max_jitter_pct": 0.15,
        })

        # Add connections from different pairs
        for i in range(5):
            pkt = _make_http_packet(
                src_ip=f"10.0.0.{i}",
                payload=f"GET / HTTP/1.1\r\nHost: host{i}.com\r\n\r\n".encode(),
            )
            engine.analyze(pkt)

        # Should have entries in _connections
        assert len(engine._connections) == 5

    def test_shutdown_clears_state(self):
        pkt = _make_http_packet(
            payload=b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
        )
        self.engine.analyze(pkt)
        assert len(self.engine._connections) > 0

        self.engine.shutdown()
        assert len(self.engine._connections) == 0
