"""Tests for protocol parsers (HTTP, SMTP, FTP, SSH) and ProtocolInspectEngine."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from scapy.all import IP, TCP, Raw, Ether

from netwatcher.detection.engines.protocol_inspect import ProtocolInspectEngine
from netwatcher.detection.models import Severity
from netwatcher.protocols.http import parse_http_request, parse_http_response
from netwatcher.protocols.smtp import parse_smtp_command, parse_smtp_response
from netwatcher.protocols.ftp import parse_ftp_command, parse_ftp_response
from netwatcher.protocols.ssh import parse_ssh_banner


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


# ===========================================================================
# HTTP Parser Tests
# ===========================================================================


class TestParseHttpRequest:
    """Tests for parse_http_request."""

    def test_parse_get_request(self):
        payload = _build_http_request(
            method="GET", path="/index.html",
            host="www.example.com", user_agent="Mozilla/5.0",
        )
        result = parse_http_request(payload)
        assert result is not None
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["version"] == "HTTP/1.1"
        assert result["host"] == "www.example.com"
        assert result["user_agent"] == "Mozilla/5.0"

    def test_parse_post_request(self):
        payload = (
            b"POST /api/login HTTP/1.1\r\n"
            b"Host: api.example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 42\r\n"
            b"\r\n"
            b'{"username": "admin", "password": "test"}'
        )
        result = parse_http_request(payload)
        assert result is not None
        assert result["method"] == "POST"
        assert result["path"] == "/api/login"
        assert result["content_type"] == "application/json"
        assert result["content_length"] == "42"

    def test_parse_response(self):
        payload = _build_http_response(
            status_code=200, reason="OK", server="Apache/2.4.41",
        )
        result = parse_http_response(payload)
        assert result is not None
        assert result["status_code"] == 200
        assert result["reason"] == "OK"
        assert result["server"] == "Apache/2.4.41"
        assert result["version"] == "HTTP/1.1"

    def test_non_http_returns_none(self):
        payload = b"\x00\x01\x02\x03\xff\xfe\xfd binary garbage"
        assert parse_http_request(payload) is None
        assert parse_http_response(payload) is None

    def test_truncated_request(self):
        """Incomplete HTTP request line (no CRLF)."""
        payload = b"GET /foo HTTP/1.1"
        assert parse_http_request(payload) is None

    def test_empty_payload(self):
        assert parse_http_request(b"") is None
        assert parse_http_response(b"") is None

    def test_various_methods(self):
        for method in ("PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
            payload = _build_http_request(method=method, path="/resource")
            result = parse_http_request(payload)
            assert result is not None, f"Failed for method {method}"
            assert result["method"] == method

    def test_unknown_method_returns_none(self):
        payload = b"FOOBAR /path HTTP/1.1\r\nHost: x.com\r\n\r\n"
        assert parse_http_request(payload) is None

    def test_response_no_reason(self):
        """Some servers omit the reason phrase."""
        payload = b"HTTP/1.1 204\r\nServer: test\r\n\r\n"
        # split with maxsplit=2 yields only 2 parts; reason defaults to ""
        result = parse_http_response(payload)
        assert result is not None
        assert result["status_code"] == 204
        assert result["reason"] == ""

    def test_response_invalid_status(self):
        payload = b"HTTP/1.1 abc Bad\r\nServer: test\r\n\r\n"
        assert parse_http_response(payload) is None


# ===========================================================================
# SMTP Parser Tests
# ===========================================================================


class TestParseSmtpCommand:
    """Tests for parse_smtp_command."""

    def test_parse_smtp_ehlo(self):
        result = parse_smtp_command(b"EHLO evil.com\r\n")
        assert result is not None
        assert result["command"] == "EHLO"
        assert result["argument"] == "evil.com"

    def test_parse_smtp_mail_from(self):
        result = parse_smtp_command(b"MAIL FROM:<user@evil.com>\r\n")
        assert result is not None
        assert result["command"] == "MAIL FROM"
        assert result["argument"] == "<user@evil.com>"

    def test_parse_smtp_auth(self):
        result = parse_smtp_command(b"AUTH LOGIN\r\n")
        assert result is not None
        assert result["command"] == "AUTH"
        assert result["argument"] == "LOGIN"

    def test_parse_smtp_rcpt_to(self):
        result = parse_smtp_command(b"RCPT TO:<target@external.com>\r\n")
        assert result is not None
        assert result["command"] == "RCPT TO"
        assert result["argument"] == "<target@external.com>"

    def test_parse_smtp_vrfy(self):
        result = parse_smtp_command(b"VRFY admin\r\n")
        assert result is not None
        assert result["command"] == "VRFY"
        assert result["argument"] == "admin"

    def test_parse_smtp_expn(self):
        result = parse_smtp_command(b"EXPN mailing-list\r\n")
        assert result is not None
        assert result["command"] == "EXPN"
        assert result["argument"] == "mailing-list"

    def test_parse_smtp_quit(self):
        result = parse_smtp_command(b"QUIT\r\n")
        assert result is not None
        assert result["command"] == "QUIT"
        assert result["argument"] == ""

    def test_parse_smtp_non_smtp_returns_none(self):
        assert parse_smtp_command(b"\x00\x01\x02binary") is None
        assert parse_smtp_command(b"GET / HTTP/1.1\r\n") is None
        assert parse_smtp_command(b"") is None
        assert parse_smtp_command(b"FOOBAR something\r\n") is None


class TestParseSmtpResponse:
    """Tests for parse_smtp_response."""

    def test_parse_smtp_response_banner(self):
        result = parse_smtp_response(b"220 mail.example.com ESMTP Postfix\r\n")
        assert result is not None
        assert result["code"] == 220
        assert result["message"] == "mail.example.com ESMTP Postfix"

    def test_parse_smtp_response_250(self):
        result = parse_smtp_response(b"250 OK\r\n")
        assert result is not None
        assert result["code"] == 250
        assert result["message"] == "OK"

    def test_parse_smtp_response_multiline(self):
        """Multiline response (hyphen continuation): parse first line."""
        result = parse_smtp_response(b"250-SIZE 10485760\r\n250 OK\r\n")
        assert result is not None
        assert result["code"] == 250
        assert result["message"] == "SIZE 10485760"

    def test_parse_smtp_response_non_smtp_returns_none(self):
        assert parse_smtp_response(b"") is None
        assert parse_smtp_response(b"abc invalid\r\n") is None
        assert parse_smtp_response(b"\x00\x01") is None


# ===========================================================================
# FTP Parser Tests
# ===========================================================================


class TestParseFtpCommand:
    """Tests for parse_ftp_command."""

    def test_parse_ftp_user(self):
        result = parse_ftp_command(b"USER anonymous\r\n")
        assert result is not None
        assert result["command"] == "USER"
        assert result["argument"] == "anonymous"

    def test_parse_ftp_retr(self):
        result = parse_ftp_command(b"RETR secret.txt\r\n")
        assert result is not None
        assert result["command"] == "RETR"
        assert result["argument"] == "secret.txt"

    def test_parse_ftp_stor(self):
        result = parse_ftp_command(b"STOR backup.tar.gz\r\n")
        assert result is not None
        assert result["command"] == "STOR"
        assert result["argument"] == "backup.tar.gz"

    def test_parse_ftp_pass(self):
        result = parse_ftp_command(b"PASS secret123\r\n")
        assert result is not None
        assert result["command"] == "PASS"
        assert result["argument"] == "secret123"

    def test_parse_ftp_quit(self):
        result = parse_ftp_command(b"QUIT\r\n")
        assert result is not None
        assert result["command"] == "QUIT"
        assert result["argument"] == ""

    def test_parse_ftp_non_ftp_returns_none(self):
        assert parse_ftp_command(b"") is None
        assert parse_ftp_command(b"\x00\x01binary") is None
        assert parse_ftp_command(b"GET / HTTP/1.1\r\n") is None
        assert parse_ftp_command(b"FOOBAR something\r\n") is None


class TestParseFtpResponse:
    """Tests for parse_ftp_response."""

    def test_parse_ftp_response(self):
        result = parse_ftp_response(b"220 Welcome to FTP\r\n")
        assert result is not None
        assert result["code"] == 220
        assert result["message"] == "Welcome to FTP"

    def test_parse_ftp_response_530(self):
        result = parse_ftp_response(b"530 Login incorrect.\r\n")
        assert result is not None
        assert result["code"] == 530
        assert result["message"] == "Login incorrect."

    def test_parse_ftp_response_non_ftp_returns_none(self):
        assert parse_ftp_response(b"") is None
        assert parse_ftp_response(b"abc not ftp\r\n") is None
        assert parse_ftp_response(b"\x00\x01") is None


# ===========================================================================
# SSH Parser Tests
# ===========================================================================


class TestParseSshBanner:
    """Tests for parse_ssh_banner."""

    def test_parse_ssh_banner_openssh(self):
        result = parse_ssh_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
        assert result is not None
        assert result["protocol"] == "2.0"
        assert result["software"] == "OpenSSH_8.9p1"
        assert result["comments"] == "Ubuntu-3ubuntu0.4"

    def test_parse_ssh_banner_old_protocol(self):
        result = parse_ssh_banner(b"SSH-1.99-OpenSSH_3.9\r\n")
        assert result is not None
        assert result["protocol"] == "1.99"
        assert result["software"] == "OpenSSH_3.9"
        assert result["comments"] is None

    def test_parse_ssh_banner_v1(self):
        result = parse_ssh_banner(b"SSH-1.5-OldServer_1.0\r\n")
        assert result is not None
        assert result["protocol"] == "1.5"
        assert result["software"] == "OldServer_1.0"
        assert result["comments"] is None

    def test_parse_ssh_banner_with_multiple_comments(self):
        result = parse_ssh_banner(b"SSH-2.0-dropbear_2022.83 extra info here\r\n")
        assert result is not None
        assert result["protocol"] == "2.0"
        assert result["software"] == "dropbear_2022.83"
        assert result["comments"] == "extra info here"

    def test_parse_ssh_non_ssh_returns_none(self):
        assert parse_ssh_banner(b"") is None
        assert parse_ssh_banner(b"GET / HTTP/1.1\r\n") is None
        assert parse_ssh_banner(b"\x00\x01\x02binary") is None
        assert parse_ssh_banner(b"NOT-SSH-2.0-foo\r\n") is None


# ===========================================================================
# ProtocolInspectEngine Tests - HTTP
# ===========================================================================


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
