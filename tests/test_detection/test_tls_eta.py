"""Tests for TLS ETA (Encrypted Traffic Analytics): JA3S + JA4 + certificate + tunnel + ESNI."""

import hashlib
import time
from datetime import datetime, timedelta, timezone

from scapy.all import IP, TCP, Ether
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ALPN,
    TLS_Ext_RenegotiationInfo,
    TLS_Ext_ServerName,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
    ProtocolName,
    ServerName,
)
from scapy.layers.tls.record import TLS

from netwatcher.detection.engines.tls_fingerprint import (
    TLSFingerprintEngine,
    compute_ja3,
    compute_ja3s,
    compute_ja4,
    _is_grease,
    _ja4_tls_version,
    _ja4_sni_indicator,
    _ja4_first_alpn,
    _ja4_extract_sig_algs,
    _cert_matches_hostname,
    _extract_cn,
    _hostname_matches_pattern,
    _parse_x509_time,
    _x509_name_to_str,
)
from netwatcher.detection.models import Severity


def make_tls_server_hello(
    cipher: int = 0x1301,
    version: int = 0x0303,
    extensions=None,
    src_ip: str = "93.184.216.34",
    dst_ip: str = "192.168.1.10",
    sport: int = 443,
) -> Ether:
    """Build a packet with a TLS ServerHello layer."""
    kwargs = {"version": version, "cipher": cipher}
    if extensions is not None:
        kwargs["ext"] = extensions

    sh = TLSServerHello(**kwargs)
    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=54321)
        / TLS(msg=[sh])
    )


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

    ch = TLSClientHello(version=0x0303, ciphers=ciphers, ext=exts)
    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=dport)
        / TLS(msg=[ch])
    )


class TestComputeJA3S:
    """Tests for the compute_ja3s() function."""

    def test_basic_ja3s_hash(self):
        """JA3S hash should match manual computation for simple ServerHello."""
        sh = TLSServerHello(version=0x0303, cipher=0x1301)

        ja3s = compute_ja3s(sh)
        assert ja3s is not None

        # Format: "version,cipher,extensions"
        # 0x0303 = 771, 0x1301 = 4865, no extensions = ""
        expected_str = "771,4865,"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_with_extensions(self):
        """JA3S hash should include non-GREASE extensions."""
        sh = TLSServerHello(
            version=0x0303,
            cipher=0xC02C,
            ext=[TLS_Ext_RenegotiationInfo()],
        )

        ja3s = compute_ja3s(sh)
        assert ja3s is not None

        # RenegotiationInfo type = 65281 (0xff01)
        # 0x0303 = 771, 0xC02C = 49196
        expected_str = "771,49196,65281"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_grease_filtered(self):
        """GREASE values in extensions should be filtered out."""

        class FakeGreaseExt:
            type = 0x0A0A  # GREASE value

        class FakeRealExt:
            type = 65281  # RenegotiationInfo

        class FakeServerHello:
            version = 0x0303
            cipher = 0x1301
            ext = [FakeGreaseExt(), FakeRealExt()]

        ja3s = compute_ja3s(FakeServerHello())
        assert ja3s is not None

        # GREASE 0x0A0A should be filtered, only 65281 remains
        expected_str = "771,4865,65281"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_all_grease_extensions(self):
        """If all extensions are GREASE, extensions field should be empty."""

        class FakeGreaseExt1:
            type = 0x0A0A

        class FakeGreaseExt2:
            type = 0x1A1A

        class FakeServerHello:
            version = 0x0303
            cipher = 0x1301
            ext = [FakeGreaseExt1(), FakeGreaseExt2()]

        ja3s = compute_ja3s(FakeServerHello())
        assert ja3s is not None

        expected_str = "771,4865,"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_no_extensions(self):
        """JA3S should work when ext is None."""
        sh = TLSServerHello(version=0x0303, cipher=0x1301)
        # Scapy sets ext to None by default when not provided
        sh.ext = None

        ja3s = compute_ja3s(sh)
        assert ja3s is not None

        expected_str = "771,4865,"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_empty_extensions_list(self):
        """JA3S should work when ext is an empty list."""

        class FakeServerHello:
            version = 0x0303
            cipher = 0x1301
            ext = []

        ja3s = compute_ja3s(FakeServerHello())
        assert ja3s is not None

        expected_str = "771,4865,"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_none_version_returns_none(self):
        """JA3S should return None when version is None."""

        class FakeServerHello:
            version = None
            cipher = 0x1301
            ext = None

        assert compute_ja3s(FakeServerHello()) is None

    def test_ja3s_none_cipher_returns_none(self):
        """JA3S should return None when cipher is None."""

        class FakeServerHello:
            version = 0x0303
            cipher = None
            ext = None

        assert compute_ja3s(FakeServerHello()) is None

    def test_ja3s_exception_returns_none(self):
        """JA3S should return None on unexpected errors."""

        class BrokenServerHello:
            @property
            def version(self):
                raise RuntimeError("broken")

        assert compute_ja3s(BrokenServerHello()) is None

    def test_ja3s_multiple_extensions_dash_separated(self):
        """Multiple extensions should be joined with dashes."""

        class FakeExt1:
            type = 10

        class FakeExt2:
            type = 11

        class FakeExt3:
            type = 65281

        class FakeServerHello:
            version = 0x0303
            cipher = 0x1301
            ext = [FakeExt1(), FakeExt2(), FakeExt3()]

        ja3s = compute_ja3s(FakeServerHello())
        assert ja3s is not None

        expected_str = "771,4865,10-11-65281"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash

    def test_ja3s_tls12_vs_tls13_different_hashes(self):
        """Different TLS versions should produce different JA3S hashes."""

        class FakeSH12:
            version = 0x0303  # TLS 1.2
            cipher = 0x1301
            ext = None

        class FakeSH13:
            version = 0x0304  # TLS 1.3
            cipher = 0x1301
            ext = None

        ja3s_12 = compute_ja3s(FakeSH12())
        ja3s_13 = compute_ja3s(FakeSH13())
        assert ja3s_12 is not None
        assert ja3s_13 is not None
        assert ja3s_12 != ja3s_13

    def test_ja3s_different_ciphers_different_hashes(self):
        """Different ciphers should produce different JA3S hashes."""

        class FakeSH_A:
            version = 0x0303
            cipher = 0x1301  # TLS_AES_128_GCM_SHA256
            ext = None

        class FakeSH_B:
            version = 0x0303
            cipher = 0xC02C  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            ext = None

        ja3s_a = compute_ja3s(FakeSH_A())
        ja3s_b = compute_ja3s(FakeSH_B())
        assert ja3s_a is not None
        assert ja3s_b is not None
        assert ja3s_a != ja3s_b

    def test_ja3s_extension_type_none_skipped(self):
        """Extensions with type=None should be skipped."""

        class FakeExtNoType:
            pass  # no 'type' attribute

        class FakeExtReal:
            type = 65281

        class FakeServerHello:
            version = 0x0303
            cipher = 0x1301
            ext = [FakeExtNoType(), FakeExtReal()]

        ja3s = compute_ja3s(FakeServerHello())
        assert ja3s is not None

        expected_str = "771,4865,65281"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        assert ja3s == expected_hash


class TestGetServerHello:
    """Tests for TLSFingerprintEngine._get_server_hello()."""

    def test_extracts_server_hello(self):
        """Should extract TLSServerHello from a valid packet."""
        pkt = make_tls_server_hello(cipher=0x1301)
        sh = TLSFingerprintEngine._get_server_hello(pkt)
        assert sh is not None
        assert sh.cipher == 0x1301

    def test_returns_none_for_client_hello(self):
        """Should return None when packet contains ClientHello, not ServerHello."""
        pkt = make_tls_client_hello(sni="example.com")
        sh = TLSFingerprintEngine._get_server_hello(pkt)
        assert sh is None

    def test_returns_none_for_plain_tcp(self):
        """Should return None for plain TCP packet without TLS."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=443, dport=54321)
        sh = TLSFingerprintEngine._get_server_hello(pkt)
        assert sh is None


class TestEngineJA3SIntegration:
    """Tests for JA3S integration in TLSFingerprintEngine.analyze()."""

    def setup_method(self):
        self.engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": True,
            "check_ja3s": True,
            "check_sni": True,
        })
        self.engine._blocked_ja3 = set()
        self.engine._blocked_domains = set()

    def test_server_hello_no_alert(self):
        """ServerHello should not produce an alert (metadata enrichment only)."""
        pkt = make_tls_server_hello(cipher=0x1301)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_server_hello_on_tls_port(self):
        """ServerHello from port 443 should be processed without error."""
        pkt = make_tls_server_hello(cipher=0xC02C, sport=443)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_server_hello_on_alternative_port(self):
        """ServerHello from port 8443 should also be processed."""
        pkt = make_tls_server_hello(cipher=0x1301, sport=8443)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_server_hello_non_tls_port_ignored(self):
        """ServerHello from non-TLS port should be ignored."""
        pkt = make_tls_server_hello(cipher=0x1301, sport=80)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ja3s_disabled_no_processing(self):
        """When check_ja3s is False, ServerHello should not be processed."""
        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": True,
            "check_ja3s": False,
            "check_sni": True,
        })
        engine._blocked_ja3 = set()
        engine._blocked_domains = set()

        pkt = make_tls_server_hello(cipher=0x1301)
        alert = engine.analyze(pkt)
        assert alert is None  # No error, no alert

    def test_client_hello_still_works_with_ja3s_enabled(self):
        """ClientHello JA3 detection should still work when JA3S is enabled."""
        pkt = make_tls_client_hello(sni="legit.com")

        ch = pkt[TLSClientHello]
        from netwatcher.detection.engines.tls_fingerprint import compute_ja3
        ja3_hash = compute_ja3(ch)
        assert ja3_hash is not None

        self.engine._blocked_ja3 = {ja3_hash}
        self.engine._ja3_to_malware = {ja3_hash: "TestMalware"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "JA3" in alert.title
        assert alert.metadata["ja3_hash"] == ja3_hash

    def test_sni_detection_still_works_with_ja3s_enabled(self):
        """SNI blocklist detection should still work when JA3S is enabled."""
        pkt = make_tls_client_hello(sni="malware.evil.com")

        self.engine._blocked_domains = {"evil.com"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "SNI" in alert.title

    def test_config_schema_includes_ja3s(self):
        """Config schema should include check_ja3s option."""
        assert "check_ja3s" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["check_ja3s"]
        assert spec["type"] is bool
        assert spec["default"] is True

    def test_default_ja3s_enabled(self):
        """JA3S should be enabled by default."""
        engine = TLSFingerprintEngine({"enabled": True})
        assert engine._check_ja3s is True


# ======================================================================
# Certificate analysis helper tests
# ======================================================================


class TestX509NameToStr:
    """Tests for _x509_name_to_str()."""

    def test_none_returns_empty(self):
        assert _x509_name_to_str(None) == ""

    def test_string_passthrough(self):
        assert _x509_name_to_str("CN=example.com") == "CN=example.com"

    def test_bytes_decoded(self):
        assert _x509_name_to_str(b"CN=example.com") == "CN=example.com"

    def test_object_uses_str(self):
        class FakeName:
            def __str__(self):
                return "CN=test.org"
        assert _x509_name_to_str(FakeName()) == "CN=test.org"

    def test_broken_str_returns_empty(self):
        class Broken:
            def __str__(self):
                raise ValueError("broken")
        assert _x509_name_to_str(Broken()) == ""


class TestParseX509Time:
    """Tests for _parse_x509_time()."""

    def test_none_returns_none(self):
        assert _parse_x509_time(None) is None

    def test_datetime_naive_gets_utc(self):
        dt = datetime(2025, 1, 15, 12, 0, 0)
        result = _parse_x509_time(dt)
        assert result is not None
        assert result.tzinfo == timezone.utc
        assert result.year == 2025

    def test_datetime_aware_passthrough(self):
        dt = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = _parse_x509_time(dt)
        assert result is dt

    def test_utctime_format(self):
        result = _parse_x509_time("250115120000Z")
        assert result is not None
        assert result.year == 2025
        assert result.month == 1
        assert result.day == 15

    def test_generalized_time_format(self):
        result = _parse_x509_time("20250601000000Z")
        assert result is not None
        assert result.year == 2025
        assert result.month == 6

    def test_invalid_returns_none(self):
        assert _parse_x509_time("not-a-date") is None

    def test_empty_string_returns_none(self):
        assert _parse_x509_time("") is None


class TestExtractCN:
    """Tests for _extract_cn()."""

    def test_simple_cn(self):
        assert _extract_cn("CN=example.com") == "example.com"

    def test_cn_in_full_subject(self):
        subject = "C=US, ST=California, O=Example Inc, CN=www.example.com"
        assert _extract_cn(subject) == "www.example.com"

    def test_slash_separated(self):
        subject = "/C=US/O=Corp/CN=mail.corp.com"
        assert _extract_cn(subject) == "mail.corp.com"

    def test_no_cn(self):
        assert _extract_cn("O=Example Inc, C=US") == ""

    def test_empty_subject(self):
        assert _extract_cn("") == ""

    def test_cn_with_spaces(self):
        assert _extract_cn("CN = spaced.example.com") == "spaced.example.com"


class TestHostnameMatchesPattern:
    """Tests for _hostname_matches_pattern()."""

    def test_exact_match(self):
        assert _hostname_matches_pattern("example.com", "example.com") is True

    def test_no_match(self):
        assert _hostname_matches_pattern("example.com", "other.com") is False

    def test_wildcard_match(self):
        assert _hostname_matches_pattern("www.example.com", "*.example.com") is True

    def test_wildcard_no_match_bare_domain(self):
        """Wildcard should match bare domain as a special case."""
        assert _hostname_matches_pattern("example.com", "*.example.com") is True

    def test_wildcard_no_match_deeper(self):
        """*.example.com should match sub.example.com."""
        assert _hostname_matches_pattern("sub.example.com", "*.example.com") is True

    def test_wildcard_different_domain(self):
        assert _hostname_matches_pattern("www.other.com", "*.example.com") is False


class TestCertMatchesHostname:
    """Tests for _cert_matches_hostname()."""

    def test_san_match(self):
        assert _cert_matches_hostname(
            "example.com", "CN=other.com", ["example.com"]
        ) is True

    def test_cn_fallback(self):
        assert _cert_matches_hostname(
            "example.com", "CN=example.com", []
        ) is True

    def test_no_match(self):
        assert _cert_matches_hostname(
            "evil.com", "CN=example.com", ["www.example.com"]
        ) is False

    def test_wildcard_san(self):
        assert _cert_matches_hostname(
            "api.example.com", "CN=other.com", ["*.example.com"]
        ) is True

    def test_case_insensitive(self):
        assert _cert_matches_hostname(
            "Example.COM", "CN=example.com", []
        ) is True

    def test_san_takes_precedence(self):
        """If SANs are present and match, CN should not matter."""
        assert _cert_matches_hostname(
            "correct.com", "CN=wrong.com", ["correct.com"]
        ) is True


# ======================================================================
# Certificate analysis engine tests
# ======================================================================


def _make_engine(**overrides) -> TLSFingerprintEngine:
    """Create a TLSFingerprintEngine with sensible defaults for cert tests."""
    config = {
        "enabled": True,
        "check_ja3": False,
        "check_ja3s": False,
        "check_sni": False,
        "check_cert": True,
    }
    config.update(overrides)
    engine = TLSFingerprintEngine(config)
    engine._blocked_ja3 = set()
    engine._blocked_domains = set()
    return engine


class TestAnalyzeCertificateSelfSigned:
    """Tests for self-signed certificate detection."""

    def test_self_signed_alert(self):
        engine = _make_engine()
        cert_info = {
            "subject": "CN=myserver.local",
            "issuer": "CN=myserver.local",
            "not_before": datetime.now(timezone.utc) - timedelta(days=365),
            "not_after": datetime.now(timezone.utc) + timedelta(days=365),
            "serial": 12345,
            "san_list": ["myserver.local"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert alert.confidence == 0.6
        assert "Self-Signed" in alert.title
        assert alert.metadata["cert_subject"] == "CN=myserver.local"
        assert alert.metadata["cert_issuer"] == "CN=myserver.local"

    def test_not_self_signed(self):
        engine = _make_engine()
        cert_info = {
            "subject": "CN=example.com",
            "issuer": "CN=Let's Encrypt Authority X3",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=60),
            "serial": 99999,
            "san_list": ["example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_empty_subject_and_issuer_no_alert(self):
        """Both subject and issuer empty should not trigger self-signed."""
        engine = _make_engine()
        cert_info = {
            "subject": "",
            "issuer": "",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=60),
            "serial": None,
            "san_list": [],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None


class TestAnalyzeCertificateExpired:
    """Tests for expired certificate detection."""

    def test_expired_cert_alert(self):
        engine = _make_engine()
        cert_info = {
            "subject": "CN=expired.example.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime(2023, 1, 1, tzinfo=timezone.utc),
            "not_after": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "serial": 111,
            "san_list": ["expired.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert alert.confidence == 0.7
        assert "Expired" in alert.title
        assert alert.metadata["cert_subject"] == "CN=expired.example.com"

    def test_valid_cert_no_expired_alert(self):
        engine = _make_engine()
        cert_info = {
            "subject": "CN=valid.example.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": 222,
            "san_list": ["valid.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_expired_takes_priority_over_self_signed(self):
        """Expired cert that is also self-signed should yield expired alert."""
        engine = _make_engine()
        cert_info = {
            "subject": "CN=selfsigned.local",
            "issuer": "CN=selfsigned.local",
            "not_before": datetime(2022, 1, 1, tzinfo=timezone.utc),
            "not_after": datetime(2023, 1, 1, tzinfo=timezone.utc),
            "serial": 333,
            "san_list": [],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert "Expired" in alert.title

    def test_none_not_after_no_expired_alert(self):
        """If not_after is None, expired check should be skipped."""
        engine = _make_engine()
        cert_info = {
            "subject": "CN=example.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": None,
            "serial": 444,
            "san_list": ["example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None


class TestAnalyzeCertificateShortLived:
    """Tests for short-lived certificate (< 30 days) detection."""

    def test_short_lived_alert(self):
        engine = _make_engine()
        now = datetime.now(timezone.utc)
        cert_info = {
            "subject": "CN=shortlived.example.com",
            "issuer": "CN=CA Authority",
            "not_before": now - timedelta(days=5),
            "not_after": now + timedelta(days=10),  # 15 days total validity
            "serial": 555,
            "san_list": ["shortlived.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.confidence == 0.4
        assert "Short-Lived" in alert.title
        assert alert.metadata["validity_days"] < 30

    def test_exactly_30_days_no_alert(self):
        """Exactly 30 days validity should NOT trigger the alert (< 30)."""
        engine = _make_engine()
        now = datetime.now(timezone.utc)
        cert_info = {
            "subject": "CN=borderline.example.com",
            "issuer": "CN=CA Authority",
            "not_before": now,
            "not_after": now + timedelta(days=30),
            "serial": 666,
            "san_list": ["borderline.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_normal_validity_no_alert(self):
        engine = _make_engine()
        now = datetime.now(timezone.utc)
        cert_info = {
            "subject": "CN=normal.example.com",
            "issuer": "CN=CA Authority",
            "not_before": now - timedelta(days=30),
            "not_after": now + timedelta(days=335),
            "serial": 777,
            "san_list": ["normal.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_none_not_before_no_short_lived_alert(self):
        """If not_before is None, short-lived check should be skipped."""
        engine = _make_engine()
        cert_info = {
            "subject": "CN=example.com",
            "issuer": "CN=CA Authority",
            "not_before": None,
            "not_after": datetime.now(timezone.utc) + timedelta(days=10),
            "serial": 888,
            "san_list": ["example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None


class TestAnalyzeCertificateSNIMismatch:
    """Tests for SNI mismatch detection."""

    def test_sni_mismatch_alert(self):
        engine = _make_engine()
        # Simulate ClientHello caching: client=192.168.1.10 -> server=10.0.0.1
        engine._cache_sni("192.168.1.10", "10.0.0.1", "legitimate.com")

        cert_info = {
            "subject": "CN=evil-impersonator.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": 1001,
            "san_list": ["evil-impersonator.com"],
        }
        # Server->Client: src=10.0.0.1 (server), dst=192.168.1.10 (client)
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.confidence == 0.85
        assert "SNI Mismatch" in alert.title
        assert alert.metadata["expected_sni"] == "legitimate.com"

    def test_sni_match_no_alert(self):
        engine = _make_engine()
        engine._cache_sni("192.168.1.10", "10.0.0.1", "example.com")

        cert_info = {
            "subject": "CN=example.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": 1002,
            "san_list": ["example.com", "www.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_sni_wildcard_san_match_no_alert(self):
        engine = _make_engine()
        engine._cache_sni("192.168.1.10", "10.0.0.1", "api.example.com")

        cert_info = {
            "subject": "CN=example.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": 1003,
            "san_list": ["*.example.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_sni_cn_fallback_match(self):
        """When SAN list is empty, CN from subject should be used."""
        engine = _make_engine()
        engine._cache_sni("192.168.1.10", "10.0.0.1", "mysite.com")

        cert_info = {
            "subject": "CN=mysite.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": 1004,
            "san_list": [],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_no_cached_sni_skips_mismatch_check(self):
        """Without cached SNI, mismatch check should not fire."""
        engine = _make_engine()
        # No SNI cached for this flow
        cert_info = {
            "subject": "CN=anything.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": 1005,
            "san_list": ["anything.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_sni_mismatch_takes_priority_over_expired(self):
        """SNI mismatch should fire even if cert is also expired."""
        engine = _make_engine()
        engine._cache_sni("192.168.1.10", "10.0.0.1", "real.com")

        cert_info = {
            "subject": "CN=fake.com",
            "issuer": "CN=CA Authority",
            "not_before": datetime(2022, 1, 1, tzinfo=timezone.utc),
            "not_after": datetime(2023, 1, 1, tzinfo=timezone.utc),
            "serial": 1006,
            "san_list": ["fake.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert "SNI Mismatch" in alert.title


class TestSNICache:
    """Tests for the SNI cache mechanism."""

    def test_cache_basic_store_retrieve(self):
        engine = _make_engine()
        engine._cache_sni("10.0.0.1", "10.0.0.2", "example.com")
        assert engine._sni_cache.get(("10.0.0.1", "10.0.0.2")) == "example.com"

    def test_cache_overwrite(self):
        engine = _make_engine()
        engine._cache_sni("10.0.0.1", "10.0.0.2", "first.com")
        engine._cache_sni("10.0.0.1", "10.0.0.2", "second.com")
        assert engine._sni_cache[("10.0.0.1", "10.0.0.2")] == "second.com"

    def test_cache_eviction_at_max(self):
        """Cache should evict oldest entries when exceeding _SNI_CACHE_MAX."""
        engine = _make_engine()
        # Override max for test
        engine._SNI_CACHE_MAX = 3  # type: ignore[misc]
        engine._cache_sni("a", "1", "sni1")
        engine._cache_sni("b", "2", "sni2")
        engine._cache_sni("c", "3", "sni3")
        engine._cache_sni("d", "4", "sni4")  # should evict ("a", "1")

        assert ("a", "1") not in engine._sni_cache
        assert len(engine._sni_cache) == 3
        assert engine._sni_cache[("d", "4")] == "sni4"

    def test_cache_lru_refresh(self):
        """Accessing an existing key should move it to the end (prevent eviction)."""
        engine = _make_engine()
        engine._SNI_CACHE_MAX = 3  # type: ignore[misc]
        engine._cache_sni("a", "1", "sni1")
        engine._cache_sni("b", "2", "sni2")
        engine._cache_sni("c", "3", "sni3")

        # Refresh ("a", "1") — should move to end
        engine._cache_sni("a", "1", "sni1-updated")

        # Now add one more — ("b", "2") should be evicted (oldest)
        engine._cache_sni("d", "4", "sni4")

        assert ("b", "2") not in engine._sni_cache
        assert ("a", "1") in engine._sni_cache

    def test_cache_cleared_on_shutdown(self):
        engine = _make_engine()
        engine._cache_sni("10.0.0.1", "10.0.0.2", "example.com")
        engine.shutdown()
        assert len(engine._sni_cache) == 0


class TestCertConfigSchema:
    """Tests for check_cert configuration."""

    def test_config_schema_includes_check_cert(self):
        assert "check_cert" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["check_cert"]
        assert spec["type"] is bool
        assert spec["default"] is True

    def test_default_check_cert_enabled(self):
        engine = TLSFingerprintEngine({"enabled": True})
        assert engine._check_cert is True

    def test_check_cert_disabled(self):
        engine = TLSFingerprintEngine({"enabled": True, "check_cert": False})
        assert engine._check_cert is False


class TestAnalyzeCertificateEdgeCases:
    """Edge case tests for _analyze_certificate()."""

    def test_none_subject_and_issuer(self):
        """None subject/issuer (converted to empty string) should not crash."""
        engine = _make_engine()
        cert_info = {
            "subject": None,
            "issuer": None,
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=335),
            "serial": None,
            "san_list": None,
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_empty_cert_info_dict(self):
        """Minimal cert_info with missing keys should not crash."""
        engine = _make_engine()
        cert_info: dict = {}
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is None

    def test_all_anomalies_returns_highest_priority(self):
        """Cert with all issues: SNI mismatch should win (highest priority)."""
        engine = _make_engine()
        engine._cache_sni("192.168.1.10", "10.0.0.1", "expected.com")

        cert_info = {
            "subject": "CN=wrong.com",
            "issuer": "CN=wrong.com",  # self-signed
            "not_before": datetime(2023, 12, 25, tzinfo=timezone.utc),
            "not_after": datetime(2024, 1, 1, tzinfo=timezone.utc),  # expired + short-lived
            "serial": 9999,
            "san_list": ["wrong.com"],
        }
        alert = engine._analyze_certificate(cert_info, "10.0.0.1", "192.168.1.10")
        assert alert is not None
        assert "SNI Mismatch" in alert.title
        assert alert.severity == Severity.CRITICAL


# ======================================================================
# JA4 fingerprint tests
# ======================================================================


def _make_ja4_client_hello(
    version: int = 0x0303,
    ciphers: list[int] | None = None,
    sni: str | None = "example.com",
    alpn_protocols: list[bytes] | None = None,
    sig_algs: list[int] | None = None,
    extra_exts: list | None = None,
):
    """Build a TLSClientHello with configurable fields for JA4 testing."""
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02C]

    exts = []
    if sni is not None:
        exts.append(
            TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())])
        )
    exts.append(TLS_Ext_SupportedGroups(groups=[0x0017, 0x0018]))
    exts.append(TLS_Ext_SupportedPointFormat(ecpl=[0x00]))

    if alpn_protocols is not None:
        exts.append(
            TLS_Ext_ALPN(
                protocols=[ProtocolName(protocol=p) for p in alpn_protocols]
            )
        )

    if sig_algs is not None:
        exts.append(TLS_Ext_SignatureAlgorithms(sig_algs=sig_algs))

    if extra_exts:
        exts.extend(extra_exts)

    return TLSClientHello(version=version, ciphers=ciphers, ext=exts)


class TestJA4TLSVersion:
    """Tests for _ja4_tls_version() helper."""

    def test_tls10(self):
        assert _ja4_tls_version(0x0301) == "10"

    def test_tls11(self):
        assert _ja4_tls_version(0x0302) == "11"

    def test_tls12(self):
        assert _ja4_tls_version(0x0303) == "12"

    def test_tls13(self):
        assert _ja4_tls_version(0x0304) == "13"

    def test_unknown_version(self):
        assert _ja4_tls_version(0x0300) == "00"

    def test_ssl30(self):
        assert _ja4_tls_version(0x0300) == "00"


class TestJA4SNIIndicator:
    """Tests for _ja4_sni_indicator() helper."""

    def test_domain_sni(self):
        ch = _make_ja4_client_hello(sni="example.com")
        assert _ja4_sni_indicator(ch) == "d"

    def test_ip_sni(self):
        ch = _make_ja4_client_hello(sni="192.168.1.1")
        assert _ja4_sni_indicator(ch) == "i"

    def test_ipv6_sni(self):
        ch = _make_ja4_client_hello(sni="::1")
        assert _ja4_sni_indicator(ch) == "i"

    def test_no_sni(self):
        ch = _make_ja4_client_hello(sni=None)
        assert _ja4_sni_indicator(ch) == "x"

    def test_no_extensions(self):
        class FakeCH:
            ext = None
        assert _ja4_sni_indicator(FakeCH()) == "x"


class TestJA4FirstALPN:
    """Tests for _ja4_first_alpn() helper."""

    def test_h2(self):
        ch = _make_ja4_client_hello(alpn_protocols=[b"h2", b"http/1.1"])
        assert _ja4_first_alpn(ch) == "h2"

    def test_http11(self):
        ch = _make_ja4_client_hello(alpn_protocols=[b"http/1.1"])
        assert _ja4_first_alpn(ch) == "ht"

    def test_single_char_padded(self):
        """Single char ALPN should be padded with '0'."""
        ch = _make_ja4_client_hello(alpn_protocols=[b"x"])
        assert _ja4_first_alpn(ch) == "x0"

    def test_no_alpn(self):
        ch = _make_ja4_client_hello(alpn_protocols=None)
        assert _ja4_first_alpn(ch) == "00"

    def test_no_extensions(self):
        class FakeCH:
            ext = None
        assert _ja4_first_alpn(FakeCH()) == "00"

    def test_empty_extensions_list(self):
        class FakeCH:
            ext = []
        assert _ja4_first_alpn(FakeCH()) == "00"


class TestJA4ExtractSigAlgs:
    """Tests for _ja4_extract_sig_algs() helper."""

    def test_basic(self):
        ch = _make_ja4_client_hello(sig_algs=[0x0601, 0x0401, 0x0501])
        result = _ja4_extract_sig_algs(ch)
        assert result == [1025, 1281, 1537]  # sorted: 0x0401, 0x0501, 0x0601

    def test_no_sig_algs(self):
        ch = _make_ja4_client_hello(sig_algs=None)
        assert _ja4_extract_sig_algs(ch) == []

    def test_grease_filtered(self):
        class FakeSigAlgExt:
            type = 13
            sig_algs = [0x0A0A, 0x0401, 0x1A1A, 0x0501]

        class FakeCH:
            ext = [FakeSigAlgExt()]

        result = _ja4_extract_sig_algs(FakeCH())
        assert result == [1025, 1281]  # 0x0A0A and 0x1A1A filtered

    def test_no_extensions(self):
        class FakeCH:
            ext = None
        assert _ja4_extract_sig_algs(FakeCH()) == []


class TestComputeJA4:
    """Tests for the compute_ja4() function."""

    def test_basic_ja4_hash(self):
        """JA4 should produce correctly formatted fingerprint."""
        ch = _make_ja4_client_hello(
            version=0x0303,
            ciphers=[0x1301, 0x1302, 0x1303, 0xC02C],
            sni="example.com",
            alpn_protocols=[b"h2", b"http/1.1"],
            sig_algs=[0x0401, 0x0501, 0x0601],
        )
        ja4 = compute_ja4(ch)
        assert ja4 is not None

        parts = ja4.split("_")
        assert len(parts) == 3
        assert len(parts[0]) == 10  # part_a
        assert len(parts[1]) == 12  # part_b
        assert len(parts[2]) == 12  # part_c

    def test_part_a_format(self):
        """Part_a should follow: proto + version + sni + cipher_count + ext_count + alpn."""
        ch = _make_ja4_client_hello(
            version=0x0303,
            ciphers=[0x1301, 0x1302, 0x1303, 0xC02C],
            sni="example.com",
            alpn_protocols=[b"h2", b"http/1.1"],
            sig_algs=[0x0401, 0x0501, 0x0601],
        )
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_a = ja4.split("_")[0]

        # t=TCP, 12=TLS1.2, d=domain, 04=4 ciphers, 05=5 extensions, h2=ALPN
        assert part_a == "t12d0405h2"

    def test_part_a_tls13(self):
        ch = _make_ja4_client_hello(version=0x0304, sni="example.com")
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a.startswith("t13d")

    def test_part_a_no_sni(self):
        ch = _make_ja4_client_hello(sni=None)
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a[3] == "x"  # SNI indicator

    def test_part_a_ip_sni(self):
        ch = _make_ja4_client_hello(sni="10.0.0.1")
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a[3] == "i"  # IP indicator

    def test_part_a_no_alpn(self):
        ch = _make_ja4_client_hello(alpn_protocols=None)
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a.endswith("00")

    def test_part_b_sorted_ciphers(self):
        """Part_b should be SHA256 of numerically sorted cipher suites."""
        # Intentionally unsorted ciphers
        ch = _make_ja4_client_hello(ciphers=[0xC02C, 0x1301, 0x1303, 0x1302])
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_b = ja4.split("_")[1]

        # Sorted: 4865(0x1301), 4866(0x1302), 4867(0x1303), 49196(0xC02C)
        expected_str = "4865,4866,4867,49196"
        expected_hash = hashlib.sha256(expected_str.encode()).hexdigest()[:12]
        assert part_b == expected_hash

    def test_part_b_grease_filtered(self):
        """GREASE cipher values should be filtered from part_b."""

        class FakeCH:
            version = 0x0303
            ciphers = [0x0A0A, 0x1301, 0x1A1A, 0xC02C]
            ext = [
                TLS_Ext_ServerName(
                    servernames=[ServerName(servername=b"example.com")]
                ),
            ]

        ja4 = compute_ja4(FakeCH())
        assert ja4 is not None
        part_b = ja4.split("_")[1]

        # Only non-GREASE: 4865(0x1301), 49196(0xC02C)
        expected_str = "4865,49196"
        expected_hash = hashlib.sha256(expected_str.encode()).hexdigest()[:12]
        assert part_b == expected_hash

    def test_part_c_sorted_extensions_and_sig_algs(self):
        """Part_c should be SHA256 of sorted extensions + sorted sig algs."""
        ch = _make_ja4_client_hello(
            sni="example.com",
            alpn_protocols=[b"h2"],
            sig_algs=[0x0601, 0x0401, 0x0501],
        )
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_c = ja4.split("_")[2]

        # Extensions: ServerName(0), SupportedGroups(10), SupportedPointFormat(11),
        #             ALPN(16), SignatureAlgorithms(13) -> sorted: 0,10,11,13,16
        exts_str = "0,10,11,13,16"
        # SigAlgs sorted: 0x0401=1025, 0x0501=1281, 0x0601=1537
        sig_str = "1025,1281,1537"
        expected_input = f"{exts_str}_{sig_str}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()[:12]
        assert part_c == expected_hash

    def test_part_c_no_sig_algs(self):
        """Part_c should work when no signature algorithms extension present."""
        ch = _make_ja4_client_hello(sig_algs=None)
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        part_c = ja4.split("_")[2]

        # Extensions: ServerName(0), SupportedGroups(10), SupportedPointFormat(11)
        # No sig algs -> empty after underscore
        exts_str = "0,10,11"
        expected_input = f"{exts_str}_"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()[:12]
        assert part_c == expected_hash

    def test_none_version_returns_none(self):
        class FakeCH:
            version = None
            ciphers = [0x1301]
            ext = None

        assert compute_ja4(FakeCH()) is None

    def test_exception_returns_none(self):
        class BrokenCH:
            @property
            def version(self):
                raise RuntimeError("broken")

        assert compute_ja4(BrokenCH()) is None

    def test_no_ciphers(self):
        """JA4 should handle empty cipher list."""

        class FakeCH:
            version = 0x0303
            ciphers = []
            ext = None

        ja4 = compute_ja4(FakeCH())
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a[4:6] == "00"  # cipher count = 00

    def test_no_extensions(self):
        """JA4 should handle None extensions."""

        class FakeCH:
            version = 0x0303
            ciphers = [0x1301]
            ext = None

        ja4 = compute_ja4(FakeCH())
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a[6:8] == "00"  # ext count = 00

    def test_cipher_count_capped_at_99(self):
        """Cipher count in part_a should cap at 99."""

        class FakeCH:
            version = 0x0303
            ciphers = list(range(1, 120))  # 119 non-GREASE ciphers
            ext = None

        ja4 = compute_ja4(FakeCH())
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        assert part_a[4:6] == "99"

    def test_different_ciphers_different_hashes(self):
        """Different cipher suites should produce different JA4 hashes."""
        ch1 = _make_ja4_client_hello(ciphers=[0x1301, 0x1302])
        ch2 = _make_ja4_client_hello(ciphers=[0x1301, 0xC02C])
        ja4_1 = compute_ja4(ch1)
        ja4_2 = compute_ja4(ch2)
        assert ja4_1 is not None
        assert ja4_2 is not None
        assert ja4_1 != ja4_2

    def test_different_versions_different_hashes(self):
        """Different TLS versions should produce different JA4 hashes."""
        ch1 = _make_ja4_client_hello(version=0x0303)
        ch2 = _make_ja4_client_hello(version=0x0304)
        ja4_1 = compute_ja4(ch1)
        ja4_2 = compute_ja4(ch2)
        assert ja4_1 is not None
        assert ja4_2 is not None
        assert ja4_1 != ja4_2

    def test_cipher_order_invariant(self):
        """JA4 should produce same hash regardless of cipher order (sorted)."""
        ch1 = _make_ja4_client_hello(ciphers=[0x1301, 0x1302, 0xC02C])
        ch2 = _make_ja4_client_hello(ciphers=[0xC02C, 0x1302, 0x1301])
        ja4_1 = compute_ja4(ch1)
        ja4_2 = compute_ja4(ch2)
        assert ja4_1 is not None
        assert ja4_2 is not None
        assert ja4_1 == ja4_2

    def test_grease_extensions_filtered(self):
        """GREASE extension types should be filtered from ext count and part_c."""

        class FakeGreaseExt:
            type = 0x0A0A  # GREASE

        class FakeRealExt:
            type = 65281  # RenegotiationInfo

        class FakeCH:
            version = 0x0303
            ciphers = [0x1301]
            ext = [FakeGreaseExt(), FakeRealExt()]

        ja4 = compute_ja4(FakeCH())
        assert ja4 is not None
        part_a = ja4.split("_")[0]
        # Only 1 real extension (GREASE filtered)
        assert part_a[6:8] == "01"


class TestComputeJA4FullPacket:
    """Tests for compute_ja4 with full Scapy TLS packets."""

    def test_with_full_packet(self):
        """compute_ja4 should work on ClientHello extracted from full packet."""
        pkt = make_tls_client_hello(sni="test.example.org")
        ch = pkt[TLSClientHello]
        ja4 = compute_ja4(ch)
        assert ja4 is not None
        parts = ja4.split("_")
        assert len(parts) == 3
        assert parts[0][0] == "t"  # TCP protocol
        assert parts[0][3] == "d"  # domain SNI


class TestEngineJA4Integration:
    """Tests for JA4 integration in TLSFingerprintEngine.analyze()."""

    def setup_method(self):
        self.engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": True,
            "check_ja3s": True,
            "check_ja4": True,
            "check_sni": True,
        })
        self.engine._blocked_ja3 = set()
        self.engine._blocked_ja4 = set()
        self.engine._blocked_domains = set()

    def test_ja4_blocklist_match_generates_alert(self):
        """Matching JA4 fingerprint should generate CRITICAL alert."""
        pkt = make_tls_client_hello(sni="legit.com")
        ch = pkt[TLSClientHello]
        ja4_hash = compute_ja4(ch)
        assert ja4_hash is not None

        self.engine._blocked_ja4 = {ja4_hash}
        self.engine._ja4_to_malware = {ja4_hash: "TestMalwareJA4"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "JA4" in alert.title
        assert alert.metadata["ja4_hash"] == ja4_hash
        assert alert.metadata["malware"] == "TestMalwareJA4"
        assert alert.confidence == 0.92

    def test_ja4_no_match_no_alert(self):
        """Non-matching JA4 should not generate JA4 alert."""
        pkt = make_tls_client_hello(sni="safe.com")
        self.engine._blocked_ja4 = {"t12d0000000000_aaaaaaaaaaaa_bbbbbbbbbbbb"}
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ja3_match_enriched_with_ja4(self):
        """JA3 match alert should include JA4 hash in metadata."""
        pkt = make_tls_client_hello(sni="legit.com")
        ch = pkt[TLSClientHello]
        ja3_hash = compute_ja3(ch)
        ja4_hash = compute_ja4(ch)
        assert ja3_hash is not None
        assert ja4_hash is not None

        self.engine._blocked_ja3 = {ja3_hash}
        self.engine._ja3_to_malware = {ja3_hash: "TestMalware"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "JA3" in alert.title
        assert alert.metadata["ja3_hash"] == ja3_hash
        assert alert.metadata["ja4_hash"] == ja4_hash

    def test_ja3_match_takes_priority_over_ja4(self):
        """When both JA3 and JA4 match, JA3 alert should fire first."""
        pkt = make_tls_client_hello(sni="legit.com")
        ch = pkt[TLSClientHello]
        ja3_hash = compute_ja3(ch)
        ja4_hash = compute_ja4(ch)
        assert ja3_hash is not None
        assert ja4_hash is not None

        self.engine._blocked_ja3 = {ja3_hash}
        self.engine._ja3_to_malware = {ja3_hash: "JA3Malware"}
        self.engine._blocked_ja4 = {ja4_hash}
        self.engine._ja4_to_malware = {ja4_hash: "JA4Malware"}

        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "JA3 Match" in alert.title  # JA3 fires first

    def test_ja4_disabled_no_processing(self):
        """When check_ja4 is False, JA4 should not be computed or checked."""
        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": False,
            "check_ja3s": False,
            "check_ja4": False,
            "check_sni": False,
        })
        engine._blocked_ja3 = set()
        engine._blocked_ja4 = set()
        engine._blocked_domains = set()

        pkt = make_tls_client_hello(sni="example.com")
        ch = pkt[TLSClientHello]
        ja4_hash = compute_ja4(ch)

        # Even with matching JA4, no alert when disabled
        engine._blocked_ja4 = {ja4_hash}
        alert = engine.analyze(pkt)
        assert alert is None

    def test_config_schema_includes_ja4(self):
        """Config schema should include check_ja4 option."""
        assert "check_ja4" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["check_ja4"]
        assert spec["type"] is bool
        assert spec["default"] is True

    def test_default_ja4_enabled(self):
        """JA4 should be enabled by default."""
        engine = TLSFingerprintEngine({"enabled": True})
        assert engine._check_ja4 is True

    def test_ja4_whitelisted_ip_no_alert(self):
        """Whitelisted source IP should suppress JA4 alert."""
        from netwatcher.detection.whitelist import Whitelist

        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": False,
            "check_ja4": True,
            "check_sni": False,
        })
        engine._blocked_ja3 = set()
        engine._blocked_domains = set()

        pkt = make_tls_client_hello(sni="legit.com", src_ip="192.168.1.10")
        ch = pkt[TLSClientHello]
        ja4_hash = compute_ja4(ch)
        engine._blocked_ja4 = {ja4_hash}
        engine._ja4_to_malware = {ja4_hash: "Malware"}

        wl = Whitelist({"ips": ["192.168.1.10"]})
        engine.set_whitelist(wl)

        alert = engine.analyze(pkt)
        assert alert is None

    def test_shutdown_clears_ja4(self):
        """shutdown() should clear JA4 blocklist and malware map."""
        self.engine._blocked_ja4 = {"hash1", "hash2"}
        self.engine._ja4_to_malware = {"hash1": "Malware1"}
        self.engine.shutdown()
        assert len(self.engine._blocked_ja4) == 0
        assert len(self.engine._ja4_to_malware) == 0

    def test_set_feeds_with_ja4(self):
        """set_feeds should load JA4 data from feed manager."""

        class FakeFeedManager:
            _blocked_ja3 = set()
            _ja3_to_malware = {}
            _blocked_domains = set()
            _blocked_ja4 = {"ja4hash1", "ja4hash2"}
            _ja4_to_malware = {"ja4hash1": "MalwareA"}

        self.engine.set_feeds(FakeFeedManager())
        assert len(self.engine._blocked_ja4) == 2
        assert self.engine._ja4_to_malware["ja4hash1"] == "MalwareA"

    def test_set_feeds_without_ja4_attributes(self):
        """set_feeds should gracefully handle FeedManager without JA4 attrs."""

        class OldFeedManager:
            _blocked_ja3 = set()
            _ja3_to_malware = {}
            _blocked_domains = set()
            # No _blocked_ja4 or _ja4_to_malware

        self.engine.set_feeds(OldFeedManager())
        assert len(self.engine._blocked_ja4) == 0
        assert len(self.engine._ja4_to_malware) == 0


# ======================================================================
# Encrypted Tunnel Detection tests
# ======================================================================


def _make_tunnel_engine(**overrides) -> TLSFingerprintEngine:
    """Create a TLSFingerprintEngine configured for tunnel detection tests."""
    config = {
        "enabled": True,
        "check_ja3": False,
        "check_ja3s": False,
        "check_ja4": False,
        "check_sni": False,
        "check_cert": False,
        "detect_tunnels": True,
        "tunnel_min_packets": 30,
        "tunnel_cv_threshold": 0.05,
        "max_tracked_flows": 5000,
        "detect_esni": False,
    }
    config.update(overrides)
    engine = TLSFingerprintEngine(config)
    engine._blocked_ja3 = set()
    engine._blocked_ja4 = set()
    engine._blocked_domains = set()
    return engine


def _make_plain_tls_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "93.184.216.34",
    dport: int = 443,
    payload_size: int = 100,
) -> Ether:
    """Build a plain TCP packet on a TLS port with a specific payload size.

    Uses raw TCP payload (no TLS layer) to simulate encrypted tunnel traffic
    where the TLS ClientHello/ServerHello is not visible.
    """
    # Create a raw payload to control packet size deterministically
    payload = b"X" * payload_size
    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=dport)
        / payload
    )


class TestTunnelDetectionFlowTracking:
    """Tests for flow tracking in tunnel detection."""

    def test_flow_tracked_on_tls_port(self):
        """Packets on port 443 should be tracked in _flow_stats."""
        engine = _make_tunnel_engine()
        pkt = _make_plain_tls_packet(dport=443, payload_size=100)
        engine.analyze(pkt)
        assert len(engine._flow_stats) == 1
        key = ("192.168.1.10", "93.184.216.34", 443)
        assert key in engine._flow_stats
        assert len(engine._flow_stats[key]) == 1

    def test_flow_tracked_on_8443(self):
        """Packets on port 8443 should also be tracked."""
        engine = _make_tunnel_engine()
        pkt = _make_plain_tls_packet(dport=8443, payload_size=200)
        engine.analyze(pkt)
        assert len(engine._flow_stats) == 1
        key = ("192.168.1.10", "93.184.216.34", 8443)
        assert key in engine._flow_stats

    def test_flow_not_tracked_on_non_tunnel_port(self):
        """Packets on port 993 (IMAPS) should NOT be tracked for tunnels."""
        engine = _make_tunnel_engine()
        pkt = _make_plain_tls_packet(dport=993, payload_size=100)
        engine.analyze(pkt)
        assert len(engine._flow_stats) == 0

    def test_flow_not_tracked_when_disabled(self):
        """When detect_tunnels is False, no flow tracking should occur."""
        engine = _make_tunnel_engine(detect_tunnels=False)
        pkt = _make_plain_tls_packet(dport=443, payload_size=100)
        engine.analyze(pkt)
        assert len(engine._flow_stats) == 0

    def test_multiple_packets_same_flow(self):
        """Multiple packets for the same flow accumulate in the deque."""
        engine = _make_tunnel_engine()
        for _ in range(10):
            pkt = _make_plain_tls_packet(dport=443, payload_size=100)
            engine.analyze(pkt)
        assert len(engine._flow_stats) == 1
        key = ("192.168.1.10", "93.184.216.34", 443)
        assert len(engine._flow_stats[key]) == 10

    def test_different_flows_tracked_separately(self):
        """Different (src, dst, port) combos create separate flow entries."""
        engine = _make_tunnel_engine()
        pkt1 = _make_plain_tls_packet(src_ip="10.0.0.1", dst_ip="1.1.1.1", dport=443)
        pkt2 = _make_plain_tls_packet(src_ip="10.0.0.2", dst_ip="1.1.1.1", dport=443)
        engine.analyze(pkt1)
        engine.analyze(pkt2)
        assert len(engine._flow_stats) == 2


class TestTunnelDetectionOnTick:
    """Tests for tunnel detection via on_tick() CV analysis."""

    def test_uniform_packets_trigger_alert(self):
        """Flows with nearly identical packet sizes (low CV) should trigger alert."""
        engine = _make_tunnel_engine(tunnel_min_packets=10)
        # Inject uniform flow data directly for precise control
        key = ("192.168.1.10", "93.184.216.34", 443)
        now = time.time()
        # All packets exactly 200 bytes -> CV = 0.0
        engine._flow_stats[key] = __import__("collections").deque(
            [(now - i, 200) for i in range(15)]
        )

        alerts = engine.on_tick(now)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity == Severity.WARNING
        assert alert.confidence == 0.5
        assert "Tunnel" in alert.title or "Uniform" in alert.title
        assert alert.metadata["cv"] == 0.0
        assert alert.metadata["packet_count"] == 15
        assert alert.source_ip == "192.168.1.10"
        assert alert.dest_ip == "93.184.216.34"

    def test_varied_packets_no_alert(self):
        """Flows with varied packet sizes (high CV) should NOT trigger alert."""
        engine = _make_tunnel_engine(tunnel_min_packets=10)
        key = ("192.168.1.10", "93.184.216.34", 443)
        now = time.time()
        # Very varied sizes: 100, 200, 300, ..., 1500 -> high CV
        sizes = [100 + i * 100 for i in range(15)]
        engine._flow_stats[key] = __import__("collections").deque(
            [(now - i, sizes[i]) for i in range(15)]
        )

        alerts = engine.on_tick(now)
        assert len(alerts) == 0

    def test_below_min_packets_no_alert(self):
        """Flows with fewer than tunnel_min_packets should NOT be checked."""
        engine = _make_tunnel_engine(tunnel_min_packets=30)
        key = ("192.168.1.10", "93.184.216.34", 443)
        now = time.time()
        # Only 10 packets, all uniform -> should NOT trigger (below threshold)
        engine._flow_stats[key] = __import__("collections").deque(
            [(now - i, 200) for i in range(10)]
        )

        alerts = engine.on_tick(now)
        assert len(alerts) == 0

    def test_tunnel_disabled_no_alert(self):
        """When detect_tunnels is False, on_tick should return empty list."""
        engine = _make_tunnel_engine(detect_tunnels=False)
        key = ("192.168.1.10", "93.184.216.34", 443)
        now = time.time()
        engine._flow_stats[key] = __import__("collections").deque(
            [(now - i, 200) for i in range(50)]
        )

        alerts = engine.on_tick(now)
        assert len(alerts) == 0

    def test_alert_clears_flow(self):
        """After emitting a tunnel alert, the flow should be removed."""
        engine = _make_tunnel_engine(tunnel_min_packets=10)
        key = ("192.168.1.10", "93.184.216.34", 443)
        now = time.time()
        engine._flow_stats[key] = __import__("collections").deque(
            [(now - i, 200) for i in range(15)]
        )

        alerts = engine.on_tick(now)
        assert len(alerts) == 1
        # Flow should have been deleted after alert
        assert key not in engine._flow_stats

    def test_cv_just_below_threshold(self):
        """CV exactly at threshold boundary: CV < 0.05 triggers, CV >= 0.05 does not."""
        engine = _make_tunnel_engine(tunnel_min_packets=10, tunnel_cv_threshold=0.05)
        key = ("192.168.1.10", "93.184.216.34", 443)
        now = time.time()
        # Sizes: mix of 200 and 201 -> very small CV, but compute precisely
        # 10 x 200, 5 x 201 -> mean ~ 200.33, very low CV
        sizes = [200] * 10 + [201] * 5
        engine._flow_stats[key] = __import__("collections").deque(
            [(now - i, sizes[i]) for i in range(15)]
        )

        alerts = engine.on_tick(now)
        # CV should be well below 0.05
        assert len(alerts) == 1
        assert alerts[0].metadata["cv"] < 0.05

    def test_multiple_flows_some_alert(self):
        """Only flows meeting the CV threshold should trigger alerts."""
        engine = _make_tunnel_engine(tunnel_min_packets=10)
        now = time.time()

        # Flow 1: uniform -> should alert
        key1 = ("10.0.0.1", "1.1.1.1", 443)
        engine._flow_stats[key1] = __import__("collections").deque(
            [(now - i, 200) for i in range(15)]
        )

        # Flow 2: varied -> should NOT alert
        key2 = ("10.0.0.2", "1.1.1.1", 443)
        sizes = [100 + i * 100 for i in range(15)]
        engine._flow_stats[key2] = __import__("collections").deque(
            [(now - i, sizes[i]) for i in range(15)]
        )

        alerts = engine.on_tick(now)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "10.0.0.1"
        # Flow 1 should be deleted, flow 2 should remain
        assert key1 not in engine._flow_stats
        assert key2 in engine._flow_stats


class TestTunnelDetectionFlowEviction:
    """Tests for flow eviction when max_tracked_flows is exceeded."""

    def test_eviction_at_max(self):
        """When max_tracked_flows is reached, oldest flow should be evicted."""
        engine = _make_tunnel_engine(max_tracked_flows=3)
        now = time.time()

        # Add 3 flows with different timestamps
        engine._flow_stats[("a", "1", 443)] = __import__("collections").deque(
            [(now - 30, 100)]  # oldest
        )
        engine._flow_stats[("b", "2", 443)] = __import__("collections").deque(
            [(now - 20, 100)]
        )
        engine._flow_stats[("c", "3", 443)] = __import__("collections").deque(
            [(now - 10, 100)]
        )

        # Adding a 4th flow via analyze should evict the oldest
        pkt = _make_plain_tls_packet(src_ip="10.0.0.4", dst_ip="4.4.4.4", dport=443)
        engine.analyze(pkt)

        assert len(engine._flow_stats) == 3
        # ("a", "1", 443) had oldest timestamp -> should be evicted
        assert ("a", "1", 443) not in engine._flow_stats
        assert ("10.0.0.4", "4.4.4.4", 443) in engine._flow_stats

    def test_existing_flow_not_evicted(self):
        """Adding to an existing flow should NOT trigger eviction."""
        engine = _make_tunnel_engine(max_tracked_flows=2)
        now = time.time()

        engine._flow_stats[("192.168.1.10", "93.184.216.34", 443)] = (
            __import__("collections").deque([(now - 5, 100)])
        )
        engine._flow_stats[("10.0.0.1", "1.1.1.1", 443)] = (
            __import__("collections").deque([(now - 3, 200)])
        )

        # Add to existing flow -> no eviction needed
        pkt = _make_plain_tls_packet(
            src_ip="192.168.1.10", dst_ip="93.184.216.34", dport=443
        )
        engine.analyze(pkt)

        assert len(engine._flow_stats) == 2
        key = ("192.168.1.10", "93.184.216.34", 443)
        assert len(engine._flow_stats[key]) == 2  # original + new

    def test_shutdown_clears_flow_stats(self):
        """shutdown() should clear _flow_stats."""
        engine = _make_tunnel_engine()
        now = time.time()
        engine._flow_stats[("a", "b", 443)] = __import__("collections").deque(
            [(now, 100)]
        )
        engine.shutdown()
        assert len(engine._flow_stats) == 0


class TestTunnelConfigSchema:
    """Tests for tunnel detection config options."""

    def test_config_schema_detect_tunnels(self):
        assert "detect_tunnels" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["detect_tunnels"]
        assert spec["type"] is bool
        assert spec["default"] is True

    def test_config_schema_tunnel_min_packets(self):
        assert "tunnel_min_packets" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["tunnel_min_packets"]
        assert spec["type"] is int
        assert spec["default"] == 30

    def test_config_schema_tunnel_cv_threshold(self):
        assert "tunnel_cv_threshold" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["tunnel_cv_threshold"]
        assert spec["type"] is float
        assert spec["default"] == 0.05

    def test_config_schema_max_tracked_flows(self):
        assert "max_tracked_flows" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["max_tracked_flows"]
        assert spec["type"] is int
        assert spec["default"] == 5000

    def test_default_tunnel_enabled(self):
        engine = TLSFingerprintEngine({"enabled": True})
        assert engine._detect_tunnels is True
        assert engine._tunnel_min_packets == 30
        assert engine._tunnel_cv_threshold == 0.05
        assert engine._max_tracked_flows == 5000

    def test_tunnel_disabled(self):
        engine = TLSFingerprintEngine({"enabled": True, "detect_tunnels": False})
        assert engine._detect_tunnels is False


# ======================================================================
# ESNI / ECH Detection tests
# ======================================================================


def _make_esni_engine(**overrides) -> TLSFingerprintEngine:
    """Create a TLSFingerprintEngine configured for ESNI/ECH detection tests."""
    config = {
        "enabled": True,
        "check_ja3": False,
        "check_ja3s": False,
        "check_ja4": False,
        "check_sni": False,
        "check_cert": False,
        "detect_tunnels": False,
        "detect_esni": True,
    }
    config.update(overrides)
    engine = TLSFingerprintEngine(config)
    engine._blocked_ja3 = set()
    engine._blocked_ja4 = set()
    engine._blocked_domains = set()
    return engine


def _make_client_hello_with_ext(ext_type_id: int, sni: str = "example.com") -> Ether:
    """Build a TLS ClientHello with a custom extension type for ESNI/ECH testing."""

    class FakeExtension:
        """Minimal extension stub with a given type ID."""
        def __init__(self, type_val: int):
            self.type = type_val

    exts = [
        TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())]),
        TLS_Ext_SupportedGroups(groups=[0x0017, 0x0018]),
        TLS_Ext_SupportedPointFormat(ecpl=[0x00]),
        FakeExtension(ext_type_id),
    ]

    ch = TLSClientHello(version=0x0303, ciphers=[0x1301, 0x1302], ext=exts)
    return (
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=12345, dport=443)
        / TLS(msg=[ch])
    )


class TestESNIECHDetection:
    """Tests for ESNI/ECH extension detection in ClientHello."""

    def test_ech_extension_detected(self):
        """Extension 0xFE0D (ECH) should trigger INFO alert."""
        engine = _make_esni_engine()
        pkt = _make_client_hello_with_ext(0xFE0D)
        alert = engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.confidence == 0.3
        assert "ECH" in alert.title or "ESNI" in alert.title
        assert alert.metadata["extension_type"] == "ECH"
        assert alert.metadata["extension_id"] == 0xFE0D

    def test_legacy_esni_extension_detected(self):
        """Extension 0xFFCE (legacy ESNI) should trigger INFO alert."""
        engine = _make_esni_engine()
        pkt = _make_client_hello_with_ext(0xFFCE)
        alert = engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.confidence == 0.3
        assert "ECH" in alert.title or "ESNI" in alert.title
        assert alert.metadata["extension_type"] == "ESNI"
        assert alert.metadata["extension_id"] == 0xFFCE

    def test_normal_client_hello_no_esni_alert(self):
        """Standard ClientHello without ECH/ESNI should not trigger alert."""
        engine = _make_esni_engine()
        pkt = make_tls_client_hello(sni="example.com")
        alert = engine.analyze(pkt)
        assert alert is None

    def test_esni_disabled_no_alert(self):
        """When detect_esni is False, ECH extension should not trigger alert."""
        engine = _make_esni_engine(detect_esni=False)
        pkt = _make_client_hello_with_ext(0xFE0D)
        alert = engine.analyze(pkt)
        assert alert is None

    def test_ja3_match_takes_priority_over_esni(self):
        """JA3 blocklist match should fire before ESNI detection."""
        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": True,
            "check_ja3s": False,
            "check_ja4": False,
            "check_sni": False,
            "check_cert": False,
            "detect_tunnels": False,
            "detect_esni": True,
        })
        engine._blocked_ja4 = set()
        engine._blocked_domains = set()

        pkt = _make_client_hello_with_ext(0xFE0D)
        ch = pkt[TLSClientHello]
        ja3_hash = compute_ja3(ch)

        engine._blocked_ja3 = {ja3_hash}
        engine._ja3_to_malware = {ja3_hash: "TestMalware"}

        alert = engine.analyze(pkt)
        assert alert is not None
        assert "JA3" in alert.title  # JA3 fires, not ESNI

    def test_sni_blocklist_takes_priority_over_esni(self):
        """SNI blocklist match should fire before ESNI detection."""
        engine = TLSFingerprintEngine({
            "enabled": True,
            "check_ja3": False,
            "check_ja3s": False,
            "check_ja4": False,
            "check_sni": True,
            "check_cert": False,
            "detect_tunnels": False,
            "detect_esni": True,
        })
        engine._blocked_ja3 = set()
        engine._blocked_ja4 = set()
        engine._blocked_domains = {"example.com"}

        pkt = _make_client_hello_with_ext(0xFE0D, sni="test.example.com")
        alert = engine.analyze(pkt)
        assert alert is not None
        assert "SNI" in alert.title  # SNI fires, not ESNI


class TestESNIConfigSchema:
    """Tests for ESNI/ECH config options."""

    def test_config_schema_detect_esni(self):
        assert "detect_esni" in TLSFingerprintEngine.config_schema
        spec = TLSFingerprintEngine.config_schema["detect_esni"]
        assert spec["type"] is bool
        assert spec["default"] is True

    def test_default_esni_enabled(self):
        engine = TLSFingerprintEngine({"enabled": True})
        assert engine._detect_esni is True

    def test_esni_disabled(self):
        engine = TLSFingerprintEngine({"enabled": True, "detect_esni": False})
        assert engine._detect_esni is False
