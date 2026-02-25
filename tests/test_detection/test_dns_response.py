"""Tests for DNS response analysis engine (fast-flux + NXDOMAIN DGA burst)."""

import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether

from netwatcher.detection.engines.dns_response import DNSResponseEngine
from netwatcher.detection.models import Severity


def make_dns_response(
    qname: str,
    rdata: str = "1.2.3.4",
    ttl: int = 300,
    rcode: int = 0,
    src_ip: str = "8.8.8.8",
    dst_ip: str = "192.168.1.10",
    ancount: int = 1,
) -> Ether:
    """Build a DNS response packet with A record answer."""
    if rcode == 3:  # NXDOMAIN
        return (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=53, dport=12345)
            / DNS(
                qr=1,
                rcode=rcode,
                qd=DNSQR(qname=qname),
                ancount=0,
            )
        )

    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=53, dport=12345)
        / DNS(
            qr=1,
            rcode=rcode,
            qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, type=1, rdata=rdata, ttl=ttl),
        )
    )


def make_multi_answer_response(
    qname: str,
    answers: list[tuple[str, int]],
    dst_ip: str = "192.168.1.10",
) -> Ether:
    """Build a DNS response with multiple A record answers."""
    an = DNSRR(rrname=qname, type=1, rdata=answers[0][0], ttl=answers[0][1])
    for ip, ttl in answers[1:]:
        an = an / DNSRR(rrname=qname, type=1, rdata=ip, ttl=ttl)

    return (
        Ether()
        / IP(src="8.8.8.8", dst=dst_ip)
        / UDP(sport=53, dport=12345)
        / DNS(
            qr=1,
            rcode=0,
            qd=DNSQR(qname=qname),
            an=an,
        )
    )


class TestDNSResponseEngine:
    def setup_method(self):
        self.engine = DNSResponseEngine({
            "enabled": True,
            "flux_min_ips": 5,       # lower threshold for testing
            "flux_max_ttl": 300,
            "flux_window_seconds": 3600,
            "nxdomain_threshold": 5,  # lower threshold for testing
            "nxdomain_window_seconds": 60,
        })

    def test_dns_query_ignored(self):
        """DNS queries (qr=0) should be ignored."""
        pkt = (
            Ether()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(qr=0, qd=DNSQR(qname="google.com"))
        )
        assert self.engine.analyze(pkt) is None

    def test_non_dns_ignored(self):
        """Non-DNS packets should be ignored."""
        from scapy.all import TCP
        pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        assert self.engine.analyze(pkt) is None

    def test_normal_response_no_alert(self):
        """Normal DNS response should not trigger alert."""
        pkt = make_dns_response("google.com", rdata="142.250.80.46", ttl=300)
        assert self.engine.analyze(pkt) is None
        # on_tick shouldn't generate fast-flux alert for 1 IP
        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_safe_domain_nxdomain_ignored(self):
        """NXDOMAIN for safe domains should not count toward burst."""
        for i in range(10):
            pkt = make_dns_response(
                f"host{i}.cloudfront.net",
                rcode=3,
                dst_ip="192.168.1.10",
            )
            self.engine.analyze(pkt)

        # No alert because cloudfront.net is safe
        # The last analyze() should not have returned an alert
        # (safe domains are filtered before tracking)

    def test_nxdomain_burst_detection(self):
        """Many NXDOMAIN responses should trigger DGA burst alert."""
        for i in range(5):
            pkt = make_dns_response(
                f"xr7k{i}m2p.evil.com",
                rcode=3,
                dst_ip="192.168.1.50",
            )
            alert = self.engine.analyze(pkt)

        # The 5th packet should trigger alert (threshold=5)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "NXDOMAIN" in alert.title
        assert "DGA" in alert.title
        assert alert.source_ip == "192.168.1.50"
        assert alert.confidence == 0.70

    def test_nxdomain_below_threshold_no_alert(self):
        """NXDOMAIN count below threshold should not trigger alert."""
        for i in range(4):  # threshold is 5
            pkt = make_dns_response(
                f"test{i}.evil.com",
                rcode=3,
                dst_ip="192.168.1.60",
            )
            alert = self.engine.analyze(pkt)

        assert alert is None

    def test_nxdomain_different_hosts_separate(self):
        """NXDOMAIN tracking should be per-host."""
        for i in range(3):
            pkt = make_dns_response(
                f"a{i}.evil.com", rcode=3, dst_ip="192.168.1.70"
            )
            self.engine.analyze(pkt)

        for i in range(3):
            pkt = make_dns_response(
                f"b{i}.evil.com", rcode=3, dst_ip="192.168.1.71"
            )
            self.engine.analyze(pkt)

        # Neither host should trigger (3 < 5 threshold)
        assert "192.168.1.70" not in self.engine._nxdomain_alerted
        assert "192.168.1.71" not in self.engine._nxdomain_alerted

    def test_fast_flux_detection(self):
        """Domain resolving to many IPs with low TTL triggers fast-flux alert."""
        domain = "flux.evil.com"
        for i in range(6):  # threshold is 5
            pkt = make_dns_response(
                domain,
                rdata=f"10.0.{i}.1",
                ttl=60,  # low TTL
            )
            self.engine.analyze(pkt)

        alerts = self.engine.on_tick(time.time())
        flux_alerts = [a for a in alerts if "Fast-flux" in a.title]
        assert len(flux_alerts) == 1
        assert flux_alerts[0].severity == Severity.WARNING
        assert flux_alerts[0].confidence == 0.75
        assert flux_alerts[0].metadata["unique_ips"] >= 5

    def test_fast_flux_high_ttl_no_alert(self):
        """Domain with many IPs but high TTL should not trigger fast-flux."""
        domain = "cdn.example.com"
        for i in range(6):
            pkt = make_dns_response(
                domain,
                rdata=f"10.0.{i}.1",
                ttl=3600,  # high TTL
            )
            self.engine.analyze(pkt)

        alerts = self.engine.on_tick(time.time())
        flux_alerts = [a for a in alerts if "Fast-flux" in a.title]
        assert len(flux_alerts) == 0

    def test_fast_flux_few_ips_no_alert(self):
        """Domain with few IPs should not trigger fast-flux."""
        domain = "normal.example.com"
        for i in range(3):  # below threshold of 5
            pkt = make_dns_response(
                domain,
                rdata=f"10.0.0.{i}",
                ttl=60,
            )
            self.engine.analyze(pkt)

        alerts = self.engine.on_tick(time.time())
        flux_alerts = [a for a in alerts if "Fast-flux" in a.title]
        assert len(flux_alerts) == 0

    def test_nxdomain_alert_not_duplicated(self):
        """After alerting once per host, should not alert again until reset."""
        for i in range(10):
            pkt = make_dns_response(
                f"dga{i}.evil.com",
                rcode=3,
                dst_ip="192.168.1.80",
            )
            self.engine.analyze(pkt)

        # The host should be in the alerted set
        assert "192.168.1.80" in self.engine._nxdomain_alerted

    def test_fast_flux_alert_not_duplicated(self):
        """Fast-flux alert should fire only once per domain."""
        domain = "flux2.evil.com"
        for i in range(6):
            pkt = make_dns_response(
                domain, rdata=f"10.1.{i}.1", ttl=60,
            )
            self.engine.analyze(pkt)

        alerts1 = self.engine.on_tick(time.time())
        assert len([a for a in alerts1 if "Fast-flux" in a.title]) == 1

        # Add more IPs
        for i in range(6, 12):
            pkt = make_dns_response(
                domain, rdata=f"10.1.{i}.1", ttl=60,
            )
            self.engine.analyze(pkt)

        alerts2 = self.engine.on_tick(time.time())
        assert len([a for a in alerts2 if "Fast-flux" in a.title]) == 0

    def test_on_tick_cleanup(self):
        """Expired entries should be cleaned up on tick."""
        domain = "old.evil.com"
        # Set first_seen to far in the past
        self.engine._domain_records[domain] = {
            "ips": {f"10.0.0.{i}" for i in range(10)},
            "min_ttl": 60,
            "first_seen": time.time() - 7200,  # 2 hours ago
        }

        self.engine.on_tick(time.time())
        assert domain not in self.engine._domain_records
