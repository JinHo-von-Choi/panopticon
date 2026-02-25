"""Tests for TLS fingerprint detection engine (JA3 + SNI)."""

import hashlib

from scapy.all import IP, TCP, UDP, Ether
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
    ServerName,
)
from scapy.layers.tls.record import TLS

from netwatcher.detection.engines.tls_fingerprint import (
    TLSFingerprintEngine,
    compute_ja3,
    extract_sni,
)
from netwatcher.detection.models import Severity


def make_tls_client_hello(
    sni: str = "example.com",
    ciphers: list[int] | None = None,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "93.184.216.34",
    dport: int = 443,
) -> Ether:
    """Build a packet with a TLS ClientHello layer."""
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02C]

    exts = [
        TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())]),
        TLS_Ext_SupportedGroups(groups=[0x0017, 0x0018]),
        TLS_Ext_SupportedPointFormat(ecpl=[0x00]),
    ]

    ch = TLSClientHello(
        version=0x0303,
        ciphers=ciphers,
        ext=exts,
    )

    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=dport)
        / TLS(msg=[ch])
    )


class TestComputeJA3:
    def test_basic_ja3_hash(self):
        """JA3 hash should match manual computation."""
        ch = TLSClientHello(
            version=0x0303,
            ciphers=[0x1301, 0x1302, 0x1303, 0xC02C],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername=b"test.com")]),
                TLS_Ext_SupportedGroups(groups=[0x0017, 0x0018]),
                TLS_Ext_SupportedPointFormat(ecpl=[0x00]),
            ],
        )

        ja3 = compute_ja3(ch)
        assert ja3 is not None

        # Manual: 771,4865-4866-4867-49196,0-10-11,23-24,0
        expected_str = "771,4865-4866-4867-49196,0-10-11,23-24,0"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3 == expected_hash

    def test_grease_filtered(self):
        """GREASE values should be filtered from JA3 computation."""
        ch = TLSClientHello(
            version=0x0303,
            ciphers=[0x0A0A, 0x1301, 0x1A1A, 0xC02C],
            ext=[
                TLS_Ext_SupportedGroups(groups=[0x0017]),
                TLS_Ext_SupportedPointFormat(ecpl=[0x00]),
            ],
        )

        ja3 = compute_ja3(ch)
        assert ja3 is not None

        # GREASE 0x0A0A and 0x1A1A should be filtered
        expected_str = "771,4865-49196,10-11,23,0"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3 == expected_hash

    def test_no_extensions(self):
        """JA3 should work with no extensions."""
        ch = TLSClientHello(
            version=0x0303,
            ciphers=[0x1301],
            ext=[],
        )

        ja3 = compute_ja3(ch)
        assert ja3 is not None
        expected_str = "771,4865,,,"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3 == expected_hash


class TestExtractSNI:
    def test_basic_sni(self):
        ch = TLSClientHello(
            version=0x0303,
            ciphers=[0x1301],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername=b"evil.com")]),
            ],
        )
        assert extract_sni(ch) == "evil.com"

    def test_no_sni(self):
        ch = TLSClientHello(
            version=0x0303,
            ciphers=[0x1301],
            ext=[
                TLS_Ext_SupportedGroups(groups=[0x0017]),
            ],
        )
        assert extract_sni(ch) is None

    def test_no_extensions(self):
        ch = TLSClientHello(
            version=0x0303,
            ciphers=[0x1301],
            ext=[],
        )
        assert extract_sni(ch) is None


class TestTLSFingerprintEngine:
    def setup_method(self):
        self.engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": True,
            "check_sni": True,
        })

    def test_non_tls_packet_ignored(self):
        """Non-TCP packets should be ignored."""
        from scapy.all import DNS, DNSQR, UDP
        pkt = (
            Ether()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(qr=0, qd=DNSQR(qname="google.com"))
        )
        assert self.engine.analyze(pkt) is None

    def test_non_443_tcp_ignored(self):
        """TCP packets to non-TLS ports should be ignored."""
        pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        assert self.engine.analyze(pkt) is None

    def test_tcp_443_without_tls_ignored(self):
        """TCP 443 without TLS ClientHello should be ignored."""
        pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=443)
        assert self.engine.analyze(pkt) is None

    def test_ja3_blocklist_match(self):
        """Blocked JA3 hash should trigger CRITICAL alert."""
        pkt = make_tls_client_hello(sni="legit.com")

        # Compute the JA3 for our test packet and add to blocklist
        ch = pkt[TLSClientHello]
        ja3_hash = compute_ja3(ch)
        assert ja3_hash is not None

        self.engine._blocked_ja3 = {ja3_hash}
        self.engine._ja3_to_malware = {ja3_hash: "TestMalware"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "JA3" in alert.title
        assert alert.confidence == 0.90
        assert alert.metadata["malware"] == "TestMalware"

    def test_ja3_no_match_no_alert(self):
        """Non-blocked JA3 hash should not trigger alert."""
        pkt = make_tls_client_hello(sni="legit.com")

        self.engine._blocked_ja3 = {"deadbeef" * 4}
        self.engine._blocked_domains = set()

        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_sni_blocklist_match(self):
        """SNI matching blocked domain should trigger CRITICAL alert."""
        pkt = make_tls_client_hello(sni="malware.evil.com")

        self.engine._blocked_ja3 = set()
        self.engine._blocked_domains = {"evil.com"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "SNI" in alert.title
        assert alert.confidence == 0.95
        assert alert.metadata["sni"] == "malware.evil.com"
        assert alert.metadata["matched_domain"] == "evil.com"

    def test_sni_exact_match(self):
        """Exact SNI domain match should work."""
        pkt = make_tls_client_hello(sni="evil.com")

        self.engine._blocked_ja3 = set()
        self.engine._blocked_domains = {"evil.com"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "SNI" in alert.title

    def test_clean_tls_no_alert(self):
        """Clean TLS handshake should produce no alert."""
        pkt = make_tls_client_hello(sni="google.com")

        self.engine._blocked_ja3 = set()
        self.engine._blocked_domains = {"evil.com"}

        assert self.engine.analyze(pkt) is None

    def test_ja3_check_disabled(self):
        """When check_ja3 is disabled, JA3 match should not trigger alert."""
        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": False,
            "check_sni": True,
        })

        pkt = make_tls_client_hello(sni="safe.com")
        ch = pkt[TLSClientHello]
        ja3_hash = compute_ja3(ch)

        engine._blocked_ja3 = {ja3_hash}
        engine._ja3_to_malware = {ja3_hash: "TestMalware"}
        engine._blocked_domains = set()

        assert engine.analyze(pkt) is None

    def test_sni_check_disabled(self):
        """When check_sni is disabled, SNI match should not trigger alert."""
        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": True,
            "check_sni": False,
        })

        engine._blocked_ja3 = set()
        engine._blocked_domains = {"evil.com"}

        pkt = make_tls_client_hello(sni="evil.com")
        assert engine.analyze(pkt) is None

    def test_alternative_tls_port(self):
        """TLS on port 8443 should also be inspected."""
        pkt = make_tls_client_hello(sni="malware.evil.com", dport=8443)

        self.engine._blocked_ja3 = set()
        self.engine._blocked_domains = {"evil.com"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "SNI" in alert.title
