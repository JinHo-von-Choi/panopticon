"""ProtocolInspectEngine 시험."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from scapy.all import IP, TCP, Raw, Ether

from netwatcher.detection.engines.protocol_inspect import ProtocolInspectEngine
from netwatcher.detection.models import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(
    src: str = "192.168.1.10",
    dst: str = "10.0.0.1",
    sport: int = 12345,
    dport: int = 80,
    payload: bytes = b"",
) -> Ether:
    """Build a minimal Ether/IP/TCP/Raw packet for testing."""
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload)


# Legacy alias used by HTTP tests
_make_http_packet = _make_packet


def _build_http_request(
    method: str = "GET",
    path: str = "/",
    host: str = "example.com",
    user_agent: str = "Mozilla/5.0",
    extra_headers: str = "",
) -> bytes:
    """Build a raw HTTP/1.1 request payload."""
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
    ]
    if extra_headers:
        lines.append(extra_headers)
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8")


def _build_http_response(
    status_code: int = 200,
    reason: str = "OK",
    server: str = "nginx/1.24.0",
    content_type: str = "text/html",
) -> bytes:
    """Build a raw HTTP/1.1 response payload."""
    lines = [
        f"HTTP/1.1 {status_code} {reason}",
        f"Server: {server}",
        f"Content-Type: {content_type}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def _default_engine_config() -> dict:
    """Return default config for ProtocolInspectEngine tests."""
    return {
        "enabled": True,
        "detect_plain_auth": True,
    }




class TestProtocolInspectEngine:
    """Tests for ProtocolInspectEngine HTTP detections.

    The engine currently detects two things:
    1. Plaintext authentication on ports 21/25/110/143 (USER/PASS/LOGIN/AUTHENTICATE)
    2. Suspicious file extension requests via HTTP GET (.sh/.php/.exe/.py/.pl/.jsp/.asp/.bat)
    """

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_suspicious_file_extension_sh(self):
        """GET request for .sh file should trigger INFO alert."""
        payload = _build_http_request(method="GET", path="/install.sh")
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.engine == "protocol_inspect"
        assert "Suspicious File Request" in alert.title
        assert alert.metadata["extension"] == "sh"

    def test_suspicious_file_extension_php(self):
        """GET request for .php file should trigger INFO alert."""
        payload = _build_http_request(method="GET", path="/admin/shell.php")
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.metadata["extension"] == "php"

    def test_suspicious_file_extension_exe(self):
        """GET request for .exe file should trigger INFO alert."""
        payload = _build_http_request(method="GET", path="/download/payload.exe")
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.metadata["extension"] == "exe"

    def test_normal_http_no_alert(self):
        """Legitimate HTTP traffic should produce no alert."""
        payload = _build_http_request(
            path="/index.html", user_agent="Mozilla/5.0 (X11; Linux x86_64)",
        )
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_non_http_no_alert(self):
        """Non-HTTP TCP traffic (binary data) should produce no alert."""
        pkt = _make_http_packet(payload=b"\x00\x01\x02\x03\xff")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_whitelisted_ip_no_alert(self):
        """Whitelisted source IP should be skipped (engine has no whitelist check
        in analyze, but this verifies general packet flow)."""
        payload = _build_http_request(path="/index.html")
        pkt = _make_http_packet(payload=payload)
        # Normal request with no suspicious extension -> no alert regardless
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_config_schema(self):
        """Validate config_schema keys exist."""
        schema = ProtocolInspectEngine.config_schema
        assert "detect_plain_auth" in schema
        assert schema["detect_plain_auth"]["type"] is bool
        assert schema["detect_plain_auth"]["default"] is True

    def test_suspicious_file_dedup(self):
        """Same extension from same IP should only alert once."""
        payload = _build_http_request(method="GET", path="/a.php")
        pkt = _make_http_packet(payload=payload)
        first  = self.engine.analyze(pkt)
        second = self.engine.analyze(pkt)
        assert first is not None
        assert second is None

    def test_different_extensions_both_alert(self):
        """Different extensions from same IP should both alert."""
        pkt1 = _make_http_packet(payload=_build_http_request(method="GET", path="/a.php"))
        pkt2 = _make_http_packet(payload=_build_http_request(method="GET", path="/b.exe"))
        alert1 = self.engine.analyze(pkt1)
        alert2 = self.engine.analyze(pkt2)
        assert alert1 is not None
        assert alert2 is not None
        assert alert1.metadata["extension"] == "php"
        assert alert2.metadata["extension"] == "exe"

    def test_post_method_not_detected(self):
        """POST requests are not matched by the suspicious file regex (only GET)."""
        payload = b"POST /upload.php HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        # The engine checks "GET\s+/..." regex, POST won't match
        assert alert is None

    def test_no_tcp_layer_ignored(self):
        """Packet without TCP layer should be ignored."""
        from scapy.all import UDP
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / UDP() / Raw(load=b"data")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_no_raw_layer_ignored(self):
        """Packet without Raw layer (empty TCP payload) should be ignored."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=80)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_on_tick_returns_empty(self):
        """on_tick with no accumulated data should return empty list."""
        result = self.engine.on_tick(0.0)
        assert result == []

    def test_shutdown_clears_state(self):
        """shutdown should clear internal state (_alerted_ips)."""
        payload = _build_http_request(method="GET", path="/test.php")
        pkt = _make_http_packet(payload=payload)
        self.engine.analyze(pkt)
        assert len(self.engine._alerted_ips) > 0

        self.engine.shutdown()
        assert len(self.engine._alerted_ips) == 0

    def test_get_on_non_80_port_with_get_prefix(self):
        """GET request on non-80 port should still be inspected if payload starts with GET."""
        payload = _build_http_request(method="GET", path="/backdoor.jsp")
        pkt = _make_http_packet(dport=8080, payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.metadata["extension"] == "jsp"

    def test_safe_file_extension_no_alert(self):
        """GET request for safe file types (.html, .css, .js) should not alert."""
        for ext in ("html", "css", "js", "png", "jpg"):
            payload = _build_http_request(method="GET", path=f"/static/file.{ext}")
            pkt = _make_http_packet(payload=payload)
            alert = self.engine.analyze(pkt)
            assert alert is None, f"Unexpected alert for .{ext}"


# ===========================================================================
# ProtocolInspectEngine Tests - SMTP plaintext auth
# ===========================================================================


class TestProtocolInspectSMTP:
    """Tests for ProtocolInspectEngine SMTP plaintext auth detection."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_smtp_auth_login_alert(self):
        """AUTH LOGIN on port 25 should trigger Plaintext Authentication alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"AUTH LOGIN\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Plaintext Authentication" in alert.title
        assert alert.source_ip == "192.168.1.10"
        assert alert.metadata["port"] == 25

    def test_smtp_authenticate_alert(self):
        """AUTHENTICATE command on SMTP port should trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"AUTHENTICATE PLAIN\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Plaintext Authentication" in alert.title

    def test_smtp_normal_ehlo_no_alert(self):
        """Normal EHLO command should not trigger alert (not a USER/PASS/LOGIN/AUTHENTICATE pattern)."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"EHLO myserver.local\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_smtp_user_command_alert(self):
        """USER command on SMTP port should trigger plaintext auth alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"USER admin\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Plaintext Authentication" in alert.title

    def test_smtp_pass_command_alert(self):
        """PASS command on port 25 should trigger plaintext auth alert."""
        pkt = _make_packet(
            src="10.0.0.50", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"PASS secret123\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING

    def test_smtp_dedup_per_source_ip(self):
        """Same source IP should only trigger one plaintext auth alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"USER admin\r\n",
        )
        first  = self.engine.analyze(pkt)
        second = self.engine.analyze(pkt)
        assert first is not None
        assert second is None

    def test_smtp_port_110_pop3(self):
        """Plaintext auth on port 110 (POP3) should also be detected."""
        pkt = _make_packet(
            src="192.168.1.20", dst="10.0.0.5",
            sport=54321, dport=110,
            payload=b"USER mailuser\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.metadata["port"] == 110

    def test_smtp_port_143_imap(self):
        """Plaintext auth on port 143 (IMAP) should also be detected."""
        pkt = _make_packet(
            src="192.168.1.30", dst="10.0.0.5",
            sport=54321, dport=143,
            payload=b"LOGIN user pass\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.metadata["port"] == 143

    def test_detect_plain_auth_disabled(self):
        """When detect_plain_auth is False, plaintext auth should not alert."""
        engine = ProtocolInspectEngine({"enabled": True, "detect_plain_auth": False})
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"USER admin\r\n",
        )
        alert = engine.analyze(pkt)
        assert alert is None


# ===========================================================================
# ProtocolInspectEngine Tests - FTP plaintext auth
# ===========================================================================


class TestProtocolInspectFTP:
    """Tests for ProtocolInspectEngine FTP plaintext auth detection."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_ftp_user_command_alert(self):
        """USER command on FTP port 21 should trigger plaintext auth alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"USER anonymous\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Plaintext Authentication" in alert.title
        assert alert.source_ip == "192.168.1.10"
        assert alert.metadata["port"] == 21

    def test_ftp_pass_command_alert(self):
        """PASS command on FTP port should trigger plaintext auth alert."""
        pkt = _make_packet(
            src="10.0.0.50", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"PASS secret123\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING

    def test_ftp_normal_retr_no_alert(self):
        """RETR for non-sensitive file should not trigger alert (no USER/PASS pattern)."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"RETR report.pdf\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ftp_dedup_per_source_ip(self):
        """Same source IP should only trigger one FTP plaintext auth alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"USER admin\r\n",
        )
        first  = self.engine.analyze(pkt)
        # Same src_ip:plain_auth key -> deduped
        pkt2 = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"PASS secret\r\n",
        )
        second = self.engine.analyze(pkt2)
        assert first is not None
        assert second is None

    def test_ftp_different_sources_both_alert(self):
        """Different source IPs should both get alerted."""
        pkt1 = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"USER admin\r\n",
        )
        pkt2 = _make_packet(
            src="192.168.1.20", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"PASS secret\r\n",
        )
        alert1 = self.engine.analyze(pkt1)
        alert2 = self.engine.analyze(pkt2)
        assert alert1 is not None
        assert alert2 is not None

    def test_ftp_list_no_alert(self):
        """LIST command (no USER/PASS/LOGIN/AUTHENTICATE) should not trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"LIST\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None


# ===========================================================================
# ProtocolInspectEngine Tests - SSH (no detection in current engine)
# ===========================================================================


class TestProtocolInspectSSH:
    """Tests for ProtocolInspectEngine SSH behavior.

    The current engine does not inspect SSH traffic (port 22).
    These tests verify that SSH packets do not cause false positives.
    """

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_ssh_banner_no_alert(self):
        """SSH-2.0 banner on port 22 should not trigger alert (not inspected)."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ssh_old_protocol_no_alert(self):
        """SSH-1.5 banner on port 22 should not trigger alert (SSH not inspected)."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-1.5-OldServer_1.0\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ssh_client_banner_no_alert(self):
        """SSH banner from client side (dport=22) should not trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=22,
            payload=b"SSH-1.5-PuTTY_0.60\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ssh_199_protocol_no_alert(self):
        """SSH-1.99 banner should not trigger alert (SSH not inspected)."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-1.99-OpenSSH_3.9\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None


# ===========================================================================
# ProtocolInspectEngine Tests - Cross-protocol / Edge cases
# ===========================================================================


class TestProtocolInspectEdgeCases:
    """Edge cases and cross-protocol tests."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_non_smtp_port_ignored(self):
        """Plaintext auth payload on non-monitored port should be ignored."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=443,
            payload=b"USER admin\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_non_ftp_port_ignored(self):
        """FTP-like payload on non-monitored port should be ignored."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=443,
            payload=b"PASS secret\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_non_ssh_port_ignored(self):
        """SSH payload on non-SSH port should be ignored."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=443,
            payload=b"SSH-1.5-OldServer\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_smtp_response_from_server_port(self):
        """SMTP response from server port (sport=25) should not trigger alert
        (no USER/PASS/LOGIN/AUTHENTICATE pattern in response)."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=25, dport=54321,
            payload=b"220 mail.example.com ESMTP\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ftp_response_from_server_port(self):
        """FTP welcome banner from server should not trigger alert."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=21, dport=54321,
            payload=b"220 Welcome to FTP\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_binary_payload_on_smtp_port_no_crash(self):
        """Binary data on SMTP port should not crash the engine."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"\x00\x01\x02\xff\xfe\xfd",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_binary_payload_on_ftp_port_no_crash(self):
        """Binary data on FTP port should not crash the engine."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"\x00\x01\x02\xff\xfe\xfd",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_binary_payload_on_ssh_port_no_crash(self):
        """Binary data on SSH port should not crash the engine."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=22,
            payload=b"\x00\x01\x02\xff\xfe\xfd",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_shutdown_clears_all_state(self):
        """shutdown should clear _alerted_ips."""
        # Add an entry via analyze
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"USER admin\r\n",
        )
        self.engine.analyze(pkt)
        assert len(self.engine._alerted_ips) > 0

        self.engine.shutdown()
        assert len(self.engine._alerted_ips) == 0
