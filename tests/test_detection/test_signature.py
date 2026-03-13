"""Tests for YARA-based signature detection engine."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from netwatcher.detection.engines.signature import SignatureEngine
from netwatcher.detection.models import Severity


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------
def make_tcp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    sport: int = 54321,
    dport: int = 80,
    flags: str = "S",
    payload: bytes = b"",
) -> Ether:
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def make_udp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    sport: int = 54321,
    dport: int = 53,
    payload: bytes = b"",
) -> Ether:
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def make_icmp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
) -> Ether:
    return Ether() / IP(src=src_ip, dst=dst_ip) / ICMP()


def _make_yara_match(rule: str, tags: list[str] | None = None) -> SimpleNamespace:
    """scan_data가 반환하는 yara match 객체를 흉내낸다."""
    return SimpleNamespace(rule=rule, tags=tags or [])


# ---------------------------------------------------------------------------
# RuleParser tests (removed -- YAML rule parser no longer exists)
# ---------------------------------------------------------------------------
@pytest.mark.skip(reason="internal symbol RuleParser removed in refactor")
class TestRuleParser:
    pass


# ---------------------------------------------------------------------------
# SignatureEngine tests
# ---------------------------------------------------------------------------
class TestSignatureEngine:

    def _engine(self, *, enable_yara: bool = True) -> SignatureEngine:
        """Helper to create engine with default config."""
        return SignatureEngine({"enabled": True, "enable_yara": enable_yara})

    def _engine_with_scanner(
        self,
        scan_data_return: list | None = None,
    ) -> tuple[SignatureEngine, MagicMock]:
        """Helper to create engine with a mock YaraScanner."""
        engine = self._engine()
        scanner = MagicMock()
        scanner.scan_data.return_value = scan_data_return or []
        engine.set_yara_scanner(scanner)
        return engine, scanner

    # -- basic packet filtering --

    def test_non_tcp_udp_returns_none(self):
        """ICMP 등 TCP/UDP가 아닌 패킷은 무시한다."""
        engine = self._engine()
        assert engine.analyze(make_icmp()) is None

    def test_empty_payload_returns_none(self):
        """페이로드가 없는 TCP 패킷은 무시한다."""
        engine, _ = self._engine_with_scanner()
        pkt = make_tcp(payload=b"")
        assert engine.analyze(pkt) is None

    def test_empty_payload_udp_returns_none(self):
        """페이로드가 없는 UDP 패킷은 무시한다."""
        engine, _ = self._engine_with_scanner()
        pkt = make_udp(payload=b"")
        assert engine.analyze(pkt) is None

    # -- YARA scanning --

    def test_yara_match_returns_alert(self):
        """YARA 매치 시 CRITICAL Alert를 반환한다."""
        matches = [_make_yara_match("EvilPayload", ["malware", "exploit"])]
        engine, scanner = self._engine_with_scanner(scan_data_return=matches)

        alert = engine.analyze(make_tcp(payload=b"malicious content here"))
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.title == "YARA Signature Match"
        assert alert.confidence == 1.0
        assert "EvilPayload" in alert.metadata["rules"]
        assert "malware" in alert.metadata["tags"]
        assert "exploit" in alert.metadata["tags"]

    def test_yara_no_match_returns_none(self):
        """YARA 매치가 없으면 None을 반환한다."""
        engine, scanner = self._engine_with_scanner(scan_data_return=[])
        assert engine.analyze(make_tcp(payload=b"benign traffic")) is None

    def test_yara_multiple_rules_match(self):
        """여러 YARA 규칙이 매치되면 모든 규칙명이 metadata에 포함된다."""
        matches = [
            _make_yara_match("Rule_A", ["tag_a"]),
            _make_yara_match("Rule_B", ["tag_b"]),
        ]
        engine, _ = self._engine_with_scanner(scan_data_return=matches)

        alert = engine.analyze(make_tcp(payload=b"payload matching both"))
        assert alert is not None
        assert set(alert.metadata["rules"]) == {"Rule_A", "Rule_B"}
        assert "tag_a" in alert.metadata["tags"]
        assert "tag_b" in alert.metadata["tags"]

    def test_yara_match_description_contains_rule_names(self):
        """Alert description에 매칭된 규칙명이 포함된다."""
        matches = [_make_yara_match("Exploit_CVE_2025")]
        engine, _ = self._engine_with_scanner(scan_data_return=matches)

        alert = engine.analyze(make_tcp(payload=b"exploit payload"))
        assert "Exploit_CVE_2025" in alert.description

    def test_scanner_receives_tcp_payload(self):
        """TCP 페이로드가 scan_data에 전달된다."""
        engine, scanner = self._engine_with_scanner()
        payload = b"GET /malware HTTP/1.1"
        engine.analyze(make_tcp(payload=payload))
        scanner.scan_data.assert_called_once_with(payload)

    def test_scanner_receives_udp_payload(self):
        """UDP 페이로드가 scan_data에 전달된다."""
        engine, scanner = self._engine_with_scanner()
        payload = b"\x00\x01dns-query-payload"
        engine.analyze(make_udp(payload=payload))
        scanner.scan_data.assert_called_once_with(payload)

    # -- enable_yara config --

    def test_yara_disabled_skips_scanning(self):
        """enable_yara=False이면 scanner가 있어도 스캔하지 않는다."""
        engine = SignatureEngine({"enabled": True, "enable_yara": False})
        scanner = MagicMock()
        engine.set_yara_scanner(scanner)

        result = engine.analyze(make_tcp(payload=b"malicious"))
        assert result is None
        scanner.scan_data.assert_not_called()

    def test_no_scanner_injected_returns_none(self):
        """YaraScanner가 주입되지 않으면 매치 없이 None을 반환한다."""
        engine = self._engine()
        # scanner를 주입하지 않음
        assert engine.analyze(make_tcp(payload=b"any payload")) is None

    # -- set_yara_scanner --

    def test_set_yara_scanner(self):
        """set_yara_scanner로 스캐너를 주입할 수 있다."""
        engine = self._engine()
        scanner = MagicMock()
        engine.set_yara_scanner(scanner)
        assert engine._yara_scanner is scanner

    # -- config_schema --

    def test_config_schema_has_enable_yara(self):
        """config_schema에 enable_yara 항목이 있다."""
        assert "enable_yara" in SignatureEngine.config_schema
        schema = SignatureEngine.config_schema["enable_yara"]
        assert schema["type"] is bool
        assert schema["default"] is True

    # -- engine identity --

    def test_engine_name(self):
        engine = self._engine()
        assert engine.name == "signature"

    def test_alert_engine_field(self):
        """Alert의 engine 필드가 'signature'이다."""
        matches = [_make_yara_match("TestRule")]
        engine, _ = self._engine_with_scanner(scan_data_return=matches)
        alert = engine.analyze(make_tcp(payload=b"test"))
        assert alert.engine == "signature"

    # -- i18n keys --

    def test_alert_has_i18n_keys(self):
        """Alert에 title_key와 description_key가 설정된다."""
        matches = [_make_yara_match("TestRule")]
        engine, _ = self._engine_with_scanner(scan_data_return=matches)
        alert = engine.analyze(make_tcp(payload=b"test"))
        assert alert.title_key == "engines.signature.alerts.yara_match.title"
        assert alert.description_key == "engines.signature.alerts.yara_match.description"

    # -- tags aggregation --

    def test_tags_aggregated_from_multiple_matches(self):
        """여러 매치의 tags가 하나의 리스트로 합쳐진다."""
        matches = [
            _make_yara_match("R1", ["a", "b"]),
            _make_yara_match("R2", ["c"]),
            _make_yara_match("R3", []),
        ]
        engine, _ = self._engine_with_scanner(scan_data_return=matches)
        alert = engine.analyze(make_tcp(payload=b"multi"))
        assert alert.metadata["tags"] == ["a", "b", "c"]

    def test_empty_tags(self):
        """매치에 tag가 없으면 빈 리스트이다."""
        matches = [_make_yara_match("NoTags")]
        engine, _ = self._engine_with_scanner(scan_data_return=matches)
        alert = engine.analyze(make_tcp(payload=b"data"))
        assert alert.metadata["tags"] == []
