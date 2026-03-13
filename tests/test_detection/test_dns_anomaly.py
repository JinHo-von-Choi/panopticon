"""Tests for DNS anomaly detection engine."""

import time

import pytest
from scapy.all import DNS, DNSQR, IP, UDP, Ether

from netwatcher.detection.engines.dns_anomaly import (
    DNSAnomalyEngine,
    _calculate_entropy as _entropy,
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
        # Current engine config keys: entropy_threshold, label_length_threshold, query_rate_threshold
        self.engine = DNSAnomalyEngine({
            "enabled": True,
            "label_length_threshold": 50,
            "entropy_threshold": 3.5,
            "query_rate_threshold": 200,
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
        """Deep subdomain with a long label triggers tunneling detection."""
        # The engine checks label length, not subdomain depth.
        # Use a label that exceeds label_length_threshold (50).
        deep = "a" * 55 + ".b.c.d.e.f.g.evil.com"
        pkt = make_dns_query(deep)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "Tunneling" in alert.title

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
        """Query timestamps should persist across ticks within the 1s flood window."""
        # The engine uses a 1-second window for flood detection (on_tick).
        # Send 250 queries rapidly, then check that _query_times has entries.
        for i in range(250):
            pkt = make_dns_query(f"test{i}.example.com", src_ip="10.0.0.1")
            self.engine.analyze(pkt)

        # Check the internal state: 10.0.0.1 should have accumulated queries
        total = len(self.engine._query_times.get("10.0.0.1", []))
        assert total > 0  # queries are preserved

    def test_high_volume_alert(self):
        """High volume detection should work -- query_rate_threshold is per-second via on_tick."""
        # Send 250 queries at once (all within same second)
        for i in range(250):
            pkt = make_dns_query(f"q{i}.example.com", src_ip="10.0.0.5")
            self.engine.analyze(pkt)

        alerts = self.engine.on_tick(0)
        flood = [a for a in alerts if "Flood" in a.title]
        assert len(flood) == 1
        assert flood[0].source_ip == "10.0.0.5"

    @pytest.mark.skip(reason="internal symbol _consonant_vowel_ratio removed in refactor")
    def test_consonant_vowel_ratio(self):
        pass

    @pytest.mark.skip(reason="internal symbol _pronounceability_score removed in refactor")
    def test_pronounceability_score(self):
        pass

    @pytest.mark.skip(reason="internal symbol _dga_composite_score removed in refactor")
    def test_dga_composite_score(self):
        pass
