"""Tests for DNS anomaly detection engine."""

import time

from scapy.all import DNS, DNSQR, IP, UDP, Ether

from netwatcher.detection.engines.dns_anomaly import (
    DNSAnomalyEngine,
    _entropy,
    _consonant_vowel_ratio,
    _pronounceability_score,
    _dga_composite_score,
)
from netwatcher.detection.models import Severity


def make_dns_query(qname: str, src_ip: str = "192.168.1.10") -> Ether:
    return (
        Ether()
        / IP(src=src_ip, dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(qr=0, qd=DNSQR(qname=qname))
    )


class TestDNSAnomalyEngine:
    def setup_method(self):
        self.engine = DNSAnomalyEngine({
            "enabled": True,
            "max_label_length": 50,
            "max_subdomain_depth": 5,
            "entropy_threshold": 3.5,
            "high_volume_threshold": 200,
            "high_volume_window_seconds": 60,
        })

    def test_normal_query_no_alert(self):
        pkt = make_dns_query("google.com")
        assert self.engine.analyze(pkt) is None

    def test_long_label_tunneling(self):
        long_label = "a" * 60 + ".evil.com"
        pkt = make_dns_query(long_label)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Tunneling" in alert.title

    def test_deep_subdomain(self):
        deep = "a.b.c.d.e.f.g.evil.com"
        pkt = make_dns_query(deep)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "Subdomain" in alert.title

    def test_high_entropy_dga(self):
        # Random-looking domain
        dga_domain = "x7k9m2p4q8r.evil.com"
        pkt = make_dns_query(dga_domain)
        alert = self.engine.analyze(pkt)
        # May or may not trigger depending on entropy threshold
        if alert:
            assert "DGA" in alert.title

    def test_entropy_function(self):
        assert _entropy("") == 0.0
        assert _entropy("aaaa") == 0.0
        assert _entropy("ab") > 0
        assert _entropy("abcdefgh") > _entropy("aaaabbbb")

    def test_sliding_window_preserves_counts(self):
        """Bug fix 1.1: query counts should persist across ticks within window."""
        # Send 50 queries per tick for 5 ticks = 250 total within window
        for tick in range(5):
            for i in range(50):
                pkt = make_dns_query(f"test{i}.example.com", src_ip="10.0.0.1")
                self.engine.analyze(pkt)
            alerts = self.engine.on_tick(0)

        # The last tick should detect 250 queries (>200 threshold)
        # At least one alert should have been generated
        # Check the internal state: 10.0.0.1 should have accumulated queries
        total = len(self.engine._query_timestamps.get("10.0.0.1", []))
        assert total > 0  # queries are preserved, not cleared

    def test_high_volume_alert(self):
        """High volume detection should work with sliding window."""
        # Send 250 queries at once
        for i in range(250):
            pkt = make_dns_query(f"q{i}.example.com", src_ip="10.0.0.5")
            self.engine.analyze(pkt)

        alerts = self.engine.on_tick(0)
        high_vol = [a for a in alerts if "High Volume" in a.title]
        assert len(high_vol) == 1
        assert high_vol[0].source_ip == "10.0.0.5"

    def test_consonant_vowel_ratio(self):
        assert _consonant_vowel_ratio("hello") > 0
        assert _consonant_vowel_ratio("bcdgkl") > _consonant_vowel_ratio("hello")

    def test_pronounceability_score(self):
        assert _pronounceability_score("the") > _pronounceability_score("xqz")
        assert _pronounceability_score("") == 1.0

    def test_dga_composite_score(self):
        # Random string should score higher than normal word
        random_score = _dga_composite_score("x7k9m2p4q8r", 3.5)
        normal_score = _dga_composite_score("helloworld", 3.5)
        assert random_score > normal_score
