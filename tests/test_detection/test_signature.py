"""Tests for YAML signature detection engine."""

import os
import time

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from netwatcher.detection.engines.signature import (
    RuleParser,
    SignatureEngine,
    SignatureRule,
)
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


# ---------------------------------------------------------------------------
# RuleParser tests
# ---------------------------------------------------------------------------
class TestRuleParser:

    def test_parse_basic_rule(self):
        raw = {
            "id": "TEST-001",
            "name": "Test Rule",
            "severity": "WARNING",
            "protocol": "tcp",
            "dst_port": 22,
        }
        rule = RuleParser.parse(raw)
        assert rule.id == "TEST-001"
        assert rule.name == "Test Rule"
        assert rule.severity == Severity.WARNING
        assert rule.protocol == "tcp"
        assert rule.dst_port == 22
        assert rule.enabled is True

    def test_parse_rule_with_content(self):
        raw = {
            "id": "TEST-002",
            "name": "Content Rule",
            "severity": "CRITICAL",
            "content": ["UNION SELECT", "OR 1=1"],
            "content_nocase": True,
        }
        rule = RuleParser.parse(raw)
        assert len(rule.content) == 2
        assert rule.content[0] == b"UNION SELECT"
        assert rule.content_nocase is True
        assert len(rule._content_lower) == 2
        assert rule._content_lower[0] == b"union select"

    def test_parse_rule_with_regex(self):
        raw = {
            "id": "TEST-003",
            "name": "Regex Rule",
            "severity": "INFO",
            "regex": "/evil.*payload/i",
        }
        rule = RuleParser.parse(raw)
        assert rule.regex is not None
        assert rule.regex.search(b"EVIL_test_PAYLOAD") is not None

    def test_parse_rule_with_regex_no_pcre(self):
        raw = {
            "id": "TEST-004",
            "name": "Simple Regex",
            "severity": "WARNING",
            "regex": "malware\\d+",
        }
        rule = RuleParser.parse(raw)
        assert rule.regex is not None
        assert rule.regex.search(b"malware123") is not None
        assert rule.regex.search(b"benign") is None

    def test_parse_rule_with_threshold(self):
        raw = {
            "id": "TEST-005",
            "name": "Threshold Rule",
            "severity": "CRITICAL",
            "threshold": {"count": 10, "seconds": 60, "by": "src_ip"},
        }
        rule = RuleParser.parse(raw)
        assert rule.threshold is not None
        assert rule.threshold["count"] == 10
        assert rule.threshold["seconds"] == 60
        assert rule.threshold["by"] == "src_ip"

    def test_parse_threshold_default_by(self):
        raw = {
            "id": "TEST-006",
            "name": "Default By",
            "severity": "WARNING",
            "threshold": {"count": 5, "seconds": 30},
        }
        rule = RuleParser.parse(raw)
        assert rule.threshold["by"] == "src_ip"

    def test_parse_port_list(self):
        raw = {
            "id": "TEST-007",
            "name": "Multi-port",
            "severity": "WARNING",
            "dst_port": [80, 8080, 443],
        }
        rule = RuleParser.parse(raw)
        assert rule.dst_port == [80, 8080, 443]

    def test_parse_missing_id_raises(self):
        raw = {"name": "No ID", "severity": "WARNING"}
        with pytest.raises(ValueError, match="must have an 'id'"):
            RuleParser.parse(raw)

    def test_parse_invalid_severity_raises(self):
        raw = {"id": "BAD", "severity": "EXTREME"}
        with pytest.raises(ValueError, match="Unknown severity"):
            RuleParser.parse(raw)

    def test_parse_invalid_threshold_raises(self):
        raw = {
            "id": "BAD-TH",
            "name": "Bad Threshold",
            "severity": "WARNING",
            "threshold": {"count": 10},  # missing 'seconds'
        }
        with pytest.raises(ValueError, match="must have 'count' and 'seconds'"):
            RuleParser.parse(raw)

    def test_parse_content_hex_escape(self):
        raw = {
            "id": "HEX-001",
            "name": "Hex Content",
            "severity": "WARNING",
            "content": ["\\x00\\xff"],
        }
        rule = RuleParser.parse(raw)
        assert rule.content[0] == b"\x00\xff"

    def test_parse_disabled_rule(self):
        raw = {
            "id": "DIS-001",
            "name": "Disabled",
            "severity": "INFO",
            "enabled": False,
        }
        rule = RuleParser.parse(raw)
        assert rule.enabled is False

    def test_parse_flags(self):
        raw = {
            "id": "FLAG-001",
            "name": "SYN rule",
            "severity": "WARNING",
            "flags": "SYN",
        }
        rule = RuleParser.parse(raw)
        assert rule.flags == "SYN"
        assert rule._flags_mask == 0x02

    def test_load_file(self, tmp_path):
        yaml_content = """
rules:
  - id: "F-001"
    name: "File Rule 1"
    severity: "WARNING"
    protocol: "tcp"
  - id: "F-002"
    name: "File Rule 2"
    severity: "CRITICAL"
"""
        rule_file = tmp_path / "test.yaml"
        rule_file.write_text(yaml_content)
        rules = RuleParser.load_file(str(rule_file))
        assert len(rules) == 2
        assert rules[0].id == "F-001"
        assert rules[1].severity == Severity.CRITICAL

    def test_load_file_missing(self, tmp_path):
        rules = RuleParser.load_file(str(tmp_path / "nonexistent.yaml"))
        assert rules == []

    def test_load_file_no_rules_key(self, tmp_path):
        rule_file = tmp_path / "bad.yaml"
        rule_file.write_text("something: else\n")
        rules = RuleParser.load_file(str(rule_file))
        assert rules == []

    def test_load_file_invalid_rule_skipped(self, tmp_path):
        yaml_content = """
rules:
  - id: "GOOD-001"
    name: "Good Rule"
    severity: "WARNING"
  - name: "No ID Rule"
    severity: "CRITICAL"
"""
        rule_file = tmp_path / "partial.yaml"
        rule_file.write_text(yaml_content)
        rules = RuleParser.load_file(str(rule_file))
        # Only the valid rule should be loaded
        assert len(rules) == 1
        assert rules[0].id == "GOOD-001"

    def test_load_directory(self, tmp_path):
        f1 = tmp_path / "a.yaml"
        f1.write_text("""
rules:
  - id: "D-001"
    name: "Dir Rule 1"
    severity: "WARNING"
""")
        f2 = tmp_path / "b.yml"
        f2.write_text("""
rules:
  - id: "D-002"
    name: "Dir Rule 2"
    severity: "CRITICAL"
""")
        # Non-yaml file should be ignored
        f3 = tmp_path / "c.txt"
        f3.write_text("not a rule file")

        rules = RuleParser.load_directory(str(tmp_path))
        assert len(rules) == 2
        ids = {r.id for r in rules}
        assert "D-001" in ids
        assert "D-002" in ids

    def test_load_directory_nonexistent(self, tmp_path):
        rules = RuleParser.load_directory(str(tmp_path / "does_not_exist"))
        assert rules == []

    def test_load_directory_empty(self, tmp_path):
        rules = RuleParser.load_directory(str(tmp_path))
        assert rules == []


# ---------------------------------------------------------------------------
# SignatureEngine tests
# ---------------------------------------------------------------------------
class TestSignatureEngine:

    def _engine(self, tmp_path, rules_yaml: str | None = None) -> SignatureEngine:
        """Helper to create engine with optional rules."""
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir, exist_ok=True)
        if rules_yaml:
            rule_file = tmp_path / "rules" / "test.yaml"
            rule_file.write_text(rules_yaml)
        return SignatureEngine({
            "enabled": True,
            "rules_dir": rules_dir,
            "hot_reload": True,
        })

    def test_empty_rules_no_alert(self, tmp_path):
        engine = self._engine(tmp_path)
        pkt = make_tcp()
        assert engine.analyze(pkt) is None

    def test_protocol_match_tcp(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "P-TCP"
    name: "TCP Match"
    severity: "WARNING"
    protocol: "tcp"
""")
        assert engine.analyze(make_tcp()) is not None
        assert engine.analyze(make_udp()) is None
        assert engine.analyze(make_icmp()) is None

    def test_protocol_match_udp(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "P-UDP"
    name: "UDP Match"
    severity: "WARNING"
    protocol: "udp"
""")
        assert engine.analyze(make_udp()) is not None
        assert engine.analyze(make_tcp()) is None

    def test_protocol_match_icmp(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "P-ICMP"
    name: "ICMP Match"
    severity: "WARNING"
    protocol: "icmp"
""")
        assert engine.analyze(make_icmp()) is not None
        assert engine.analyze(make_tcp()) is None

    def test_protocol_any(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "P-ANY"
    name: "Any Match"
    severity: "INFO"
    protocol: "any"
""")
        assert engine.analyze(make_tcp()) is not None
        assert engine.analyze(make_udp()) is not None
        assert engine.analyze(make_icmp()) is not None

    def test_port_match_single(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "PORT-1"
    name: "Port 22"
    severity: "WARNING"
    protocol: "tcp"
    dst_port: 22
""")
        assert engine.analyze(make_tcp(dport=22)) is not None
        assert engine.analyze(make_tcp(dport=80)) is None

    def test_port_match_list(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "PORT-L"
    name: "Multi Port"
    severity: "WARNING"
    protocol: "tcp"
    dst_port: [80, 443, 8080]
""")
        assert engine.analyze(make_tcp(dport=80)) is not None
        assert engine.analyze(make_tcp(dport=443)) is not None
        assert engine.analyze(make_tcp(dport=8080)) is not None
        assert engine.analyze(make_tcp(dport=22)) is None

    def test_src_port_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "SPORT-1"
    name: "Src Port"
    severity: "WARNING"
    protocol: "tcp"
    src_port: 12345
""")
        assert engine.analyze(make_tcp(sport=12345)) is not None
        assert engine.analyze(make_tcp(sport=54321)) is None

    def test_flags_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "FLAG-1"
    name: "SYN Flag"
    severity: "WARNING"
    protocol: "tcp"
    flags: "SYN"
""")
        assert engine.analyze(make_tcp(flags="S")) is not None
        assert engine.analyze(make_tcp(flags="SA")) is not None  # SYN+ACK has SYN bit
        assert engine.analyze(make_tcp(flags="A")) is None  # ACK only

    def test_content_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "CONT-1"
    name: "Content Match"
    severity: "CRITICAL"
    protocol: "tcp"
    content:
      - "SELECT"
      - "FROM"
""")
        assert engine.analyze(make_tcp(payload=b"SELECT * FROM users")) is not None
        assert engine.analyze(make_tcp(payload=b"SELECT * WHERE 1")) is None  # missing FROM
        assert engine.analyze(make_tcp(payload=b"")) is None

    def test_content_nocase(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "NOCASE-1"
    name: "NoCase Match"
    severity: "CRITICAL"
    protocol: "tcp"
    content:
      - "UNION SELECT"
    content_nocase: true
""")
        assert engine.analyze(make_tcp(payload=b"union select * from users")) is not None
        assert engine.analyze(make_tcp(payload=b"Union Select * from users")) is not None
        assert engine.analyze(make_tcp(payload=b"nothing here")) is None

    def test_regex_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "RX-1"
    name: "Regex Match"
    severity: "WARNING"
    protocol: "tcp"
    regex: '/cmd[.]exe|powershell/i'
""")
        assert engine.analyze(make_tcp(payload=b"GET /cmd.exe HTTP/1.1")) is not None
        assert engine.analyze(make_tcp(payload=b"run PowerShell -enc")) is not None
        assert engine.analyze(make_tcp(payload=b"normal traffic")) is None

    def test_ip_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "IP-1"
    name: "IP Match"
    severity: "WARNING"
    src_ip: "192.168.1.100"
""")
        assert engine.analyze(make_tcp(src_ip="192.168.1.100")) is not None
        assert engine.analyze(make_tcp(src_ip="10.0.0.1")) is None

    def test_dst_ip_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "DIP-1"
    name: "Dst IP Match"
    severity: "WARNING"
    dst_ip: "10.0.0.99"
""")
        assert engine.analyze(make_tcp(dst_ip="10.0.0.99")) is not None
        assert engine.analyze(make_tcp(dst_ip="10.0.0.1")) is None

    def test_threshold_detection(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "TH-1"
    name: "Threshold Rule"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: 22
    flags: "SYN"
    threshold:
      count: 5
      seconds: 60
      by: "src_ip"
""")
        # First 4 packets: no alert (threshold not met)
        for i in range(4):
            assert engine.analyze(make_tcp(dport=22, flags="S")) is None

        # 5th packet: threshold met, alert generated
        alert = engine.analyze(make_tcp(dport=22, flags="S"))
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "TH-1" in alert.title

        # After threshold triggers, counter resets, so next 4 should not alert
        for i in range(4):
            assert engine.analyze(make_tcp(dport=22, flags="S")) is None

    def test_threshold_different_sources(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "TH-SRC"
    name: "Per Source Threshold"
    severity: "WARNING"
    protocol: "tcp"
    dst_port: 22
    threshold:
      count: 3
      seconds: 60
      by: "src_ip"
""")
        # Source A sends 2 packets
        for i in range(2):
            assert engine.analyze(make_tcp(src_ip="10.0.0.1", dport=22)) is None

        # Source B sends 2 packets
        for i in range(2):
            assert engine.analyze(make_tcp(src_ip="10.0.0.2", dport=22)) is None

        # Source A sends 1 more -> threshold met for A
        alert = engine.analyze(make_tcp(src_ip="10.0.0.1", dport=22))
        assert alert is not None
        assert alert.source_ip == "10.0.0.1"

    def test_disabled_rule_skipped(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "DIS-1"
    name: "Disabled"
    severity: "WARNING"
    protocol: "tcp"
    enabled: false
""")
        assert engine.analyze(make_tcp()) is None

    def test_first_matching_rule_wins(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "FIRST"
    name: "First Rule"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: 80
  - id: "SECOND"
    name: "Second Rule"
    severity: "INFO"
    protocol: "tcp"
""")
        alert = engine.analyze(make_tcp(dport=80))
        assert alert is not None
        assert "FIRST" in alert.title

    def test_alert_metadata(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "META-1"
    name: "Meta Test"
    severity: "WARNING"
    protocol: "tcp"
""")
        alert = engine.analyze(make_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2"))
        assert alert is not None
        assert alert.metadata["rule_id"] == "META-1"
        assert alert.metadata["rule_name"] == "Meta Test"
        assert alert.engine == "signature"
        assert alert.source_ip == "10.0.0.1"
        assert alert.dest_ip == "10.0.0.2"

    def test_hot_reload(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        engine = SignatureEngine({
            "enabled": True,
            "rules_dir": str(rules_dir),
            "hot_reload": True,
        })
        assert len(engine.rules) == 0

        # Add a rule file
        time.sleep(0.05)  # Ensure mtime difference
        rule_file = rules_dir / "new.yaml"
        rule_file.write_text("""
rules:
  - id: "HOT-1"
    name: "Hot Rule"
    severity: "WARNING"
    protocol: "tcp"
""")

        # Trigger on_tick which checks for hot-reload
        engine.on_tick(time.time())
        assert len(engine.rules) == 1
        assert engine.rules[0].id == "HOT-1"

    def test_reload_rules_method(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        engine = SignatureEngine({
            "enabled": True,
            "rules_dir": str(rules_dir),
            "hot_reload": False,
        })
        assert len(engine.rules) == 0

        rule_file = rules_dir / "manual.yaml"
        rule_file.write_text("""
rules:
  - id: "MAN-1"
    name: "Manual Rule"
    severity: "INFO"
""")
        engine.reload_rules()
        assert len(engine.rules) == 1

    def test_on_tick_prunes_threshold_counters(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "PRUNE-1"
    name: "Prune Test"
    severity: "WARNING"
    protocol: "tcp"
    threshold:
      count: 100
      seconds: 1
      by: "src_ip"
""")
        # Generate some threshold entries
        engine.analyze(make_tcp())
        assert len(engine._threshold_counters) > 0

        # Wait for expiry and tick
        time.sleep(1.1)
        engine.on_tick(time.time())
        # Expired counters should be pruned
        assert len(engine._threshold_counters) == 0

    def test_shutdown_clears_state(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "SD-1"
    name: "Shutdown Test"
    severity: "WARNING"
    protocol: "tcp"
""")
        assert len(engine.rules) == 1
        engine.shutdown()
        assert len(engine.rules) == 0
        assert len(engine._threshold_counters) == 0

    def test_combined_conditions(self, tmp_path):
        """Protocol + port + flags + content: all must match."""
        engine = self._engine(tmp_path, """
rules:
  - id: "COMBO-1"
    name: "Combined Rule"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: 80
    content:
      - "DROP TABLE"
    content_nocase: true
""")
        # All conditions met
        assert engine.analyze(make_tcp(dport=80, payload=b"drop table users")) is not None
        # Wrong port
        assert engine.analyze(make_tcp(dport=22, payload=b"drop table users")) is None
        # Wrong protocol
        assert engine.analyze(make_udp(dport=80, payload=b"drop table users")) is None
        # Missing content
        assert engine.analyze(make_tcp(dport=80, payload=b"normal request")) is None

    def test_no_payload_with_content_rule(self, tmp_path):
        """Content rule should not match packet without payload."""
        engine = self._engine(tmp_path, """
rules:
  - id: "NP-1"
    name: "No Payload"
    severity: "WARNING"
    protocol: "tcp"
    content:
      - "test"
""")
        assert engine.analyze(make_tcp(payload=b"")) is None

    def test_udp_port_match(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "UDP-P"
    name: "UDP Port"
    severity: "WARNING"
    protocol: "udp"
    dst_port: 53
""")
        assert engine.analyze(make_udp(dport=53)) is not None
        assert engine.analyze(make_udp(dport=80)) is None

    def test_rules_by_id_property(self, tmp_path):
        engine = self._engine(tmp_path, """
rules:
  - id: "A-001"
    name: "Rule A"
    severity: "WARNING"
  - id: "B-002"
    name: "Rule B"
    severity: "CRITICAL"
""")
        by_id = engine.rules_by_id
        assert "A-001" in by_id
        assert "B-002" in by_id
        assert by_id["A-001"].name == "Rule A"
