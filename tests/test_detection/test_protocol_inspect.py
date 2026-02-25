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
        "suspicious_user_agents": [
            "Nmap", "sqlmap", "Nikto", "DirBuster",
            "Hydra", "Masscan", "ZmEu", "w3af",
        ],
        "sensitive_paths": [
            "/admin", "/wp-login.php", "/.env", "/actuator",
            "/phpmyadmin", "/wp-config.php", "/.git", "/server-status",
        ],
        "check_response": True,
        "max_tracked_responses": 5000,
        "smtp_ports": [25, 587, 465],
        "ftp_ports": [20, 21],
        "ssh_port": 22,
        "sensitive_files": [".env", ".htpasswd", "passwd", "shadow", "id_rsa", ".ssh"],
        "smtp_auth_threshold": 5,
        "smtp_auth_window": 300,
        "ftp_fail_threshold": 5,
        "ftp_fail_window": 300,
        "max_tracked_sources": 10000,
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
# ProtocolInspectEngine Tests - HTTP (existing)
# ===========================================================================


class TestProtocolInspectEngine:
    """Tests for ProtocolInspectEngine HTTP detections."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_suspicious_user_agent_alert(self):
        """Nmap UA should trigger a WARNING alert."""
        payload = _build_http_request(
            path="/scan", user_agent="Mozilla/5.0 (Nmap Scripting Engine)",
        )
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert alert.engine == "protocol_inspect"
        assert "User-Agent" in alert.title
        assert alert.metadata["matched_ua"] == "nmap"

    def test_sensitive_path_alert(self):
        """/admin access should trigger a WARNING alert."""
        payload = _build_http_request(path="/admin/dashboard")
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Sensitive Path" in alert.title
        assert alert.metadata["matched_path"] == "/admin"

    def test_combined_suspicious_ua_and_path(self):
        """Both suspicious UA and sensitive path should trigger CRITICAL."""
        payload = _build_http_request(
            path="/.env", user_agent="sqlmap/1.6",
        )
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.metadata["matched_ua"] == "sqlmap"
        assert alert.metadata["matched_path"] == "/.env"

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
        """Whitelisted source IP should be skipped."""
        payload = _build_http_request(
            path="/admin", user_agent="Nmap",
        )
        pkt = _make_http_packet(payload=payload)

        with patch.object(self.engine, "is_whitelisted", return_value=True):
            alert = self.engine.analyze(pkt)
        assert alert is None

    def test_server_banner_outdated(self):
        """Apache/2.2 in response should trigger INFO alert."""
        resp_payload = _build_http_response(
            status_code=200, server="Apache/2.2.34",
        )
        pkt = _make_http_packet(
            src="10.0.0.1", dst="192.168.1.10",
            sport=80, dport=54321, payload=resp_payload,
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "Outdated" in alert.title
        assert alert.metadata["server_banner"] == "Apache/2.2.34"

    def test_server_banner_modern_no_alert(self):
        """Modern server banner should not trigger alert."""
        resp_payload = _build_http_response(
            status_code=200, server="nginx/1.24.0",
        )
        pkt = _make_http_packet(
            src="10.0.0.1", dst="192.168.1.10",
            sport=80, dport=54321, payload=resp_payload,
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_config_schema(self):
        """Validate config_schema keys exist."""
        schema = ProtocolInspectEngine.config_schema
        assert "suspicious_user_agents" in schema
        assert "sensitive_paths" in schema
        assert "check_response" in schema
        assert "max_tracked_responses" in schema
        assert "smtp_ports" in schema
        assert "ftp_ports" in schema
        assert "ssh_port" in schema
        assert "sensitive_files" in schema

    def test_multiple_sensitive_paths(self):
        """Various sensitive paths should all be detected."""
        paths = [
            "/wp-login.php", "/.env", "/actuator/health",
            "/phpmyadmin/index.php", "/wp-config.php",
            "/.git/config", "/server-status",
        ]
        for path in paths:
            payload = _build_http_request(path=path)
            pkt = _make_http_packet(payload=payload)
            alert = self.engine.analyze(pkt)
            assert alert is not None, f"No alert for sensitive path: {path}"
            assert alert.severity == Severity.WARNING

    def test_method_abuse_trace(self):
        """TRACE method should trigger HTTP Method Abuse alert."""
        payload = b"TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Method Abuse" in alert.title
        assert alert.metadata["method"] == "TRACE"

    def test_method_abuse_connect(self):
        """CONNECT method should trigger HTTP Method Abuse alert."""
        payload = b"CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
        pkt = _make_http_packet(payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Method Abuse" in alert.title
        assert alert.metadata["method"] == "CONNECT"

    def test_port_8080(self):
        """HTTP traffic on port 8080 should be inspected."""
        payload = _build_http_request(path="/admin", user_agent="Nikto/2.1.5")
        pkt = _make_http_packet(dport=8080, payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL

    def test_port_8443(self):
        """HTTP traffic on port 8443 should be inspected."""
        payload = _build_http_request(path="/.git/HEAD")
        pkt = _make_http_packet(dport=8443, payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING

    def test_non_http_port_ignored(self):
        """HTTP traffic on non-HTTP ports should be ignored."""
        payload = _build_http_request(path="/admin")
        pkt = _make_http_packet(dport=443, payload=payload)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_response_check_disabled(self):
        """When check_response is False, response inspection is skipped."""
        engine = ProtocolInspectEngine({
            "enabled": True,
            "check_response": False,
        })
        resp_payload = _build_http_response(server="Apache/2.2.34")
        pkt = _make_http_packet(
            src="10.0.0.1", dst="192.168.1.10",
            sport=80, dport=54321, payload=resp_payload,
        )
        alert = engine.analyze(pkt)
        assert alert is None

    def test_outdated_banner_dedup(self):
        """Same outdated banner from same IP should only alert once."""
        resp_payload = _build_http_response(server="IIS/6.0")
        engine = ProtocolInspectEngine({
            "enabled": True,
            "check_response": True,
        })
        pkt = _make_http_packet(
            src="10.0.0.1", dst="192.168.1.10",
            sport=80, dport=54321, payload=resp_payload,
        )
        first  = engine.analyze(pkt)
        second = engine.analyze(pkt)
        assert first is not None
        assert second is None

    def test_dual_http_port_classified_as_request(self):
        """Packet where both sport and dport are HTTP ports: classify by dport (request)."""
        payload = _build_http_request(path="/admin")
        pkt = _make_http_packet(
            src="10.0.0.1", dst="10.0.0.2",
            sport=8080, dport=80, payload=payload,
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "Sensitive Path" in alert.title

    def test_no_tcp_layer_ignored(self):
        """Packet without TCP layer should be ignored."""
        from scapy.all import UDP
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / UDP() / Raw(load=b"data")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_no_raw_layer_ignored(self):
        """Packet without Raw layer should be ignored."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=80)
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_on_tick_returns_empty(self):
        """on_tick with no accumulated data should return empty list."""
        result = self.engine.on_tick(0.0)
        assert result == []

    def test_shutdown_clears_state(self):
        """shutdown should clear internal state."""
        # Add an entry to alerted banners
        resp_payload = _build_http_response(server="Apache/2.2.1")
        pkt = _make_http_packet(
            src="10.0.0.1", dst="192.168.1.10",
            sport=80, dport=54321, payload=resp_payload,
        )
        self.engine.analyze(pkt)
        assert len(self.engine._alerted_banners) > 0

        self.engine.shutdown()
        assert len(self.engine._alerted_banners) == 0
        assert len(self.engine._smtp_auth_attempts) == 0
        assert len(self.engine._ftp_fail_attempts) == 0
        assert len(self.engine._alerted_ssh_banners) == 0


# ===========================================================================
# ProtocolInspectEngine Tests - SMTP
# ===========================================================================


class TestProtocolInspectSMTP:
    """Tests for ProtocolInspectEngine SMTP detections."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_smtp_vrfy_alert(self):
        """VRFY command should trigger WARNING alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"VRFY admin\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "User Enumeration" in alert.title
        assert alert.metadata["protocol"] == "smtp"
        assert alert.metadata["command"] == "VRFY"

    def test_smtp_expn_alert(self):
        """EXPN command should trigger WARNING alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=587,
            payload=b"EXPN postmaster\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "User Enumeration" in alert.title
        assert alert.metadata["command"] == "EXPN"

    def test_smtp_normal_ehlo_no_alert(self):
        """Normal EHLO command should not trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"EHLO myserver.local\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_smtp_auth_tracking(self):
        """AUTH command should be tracked (no immediate alert)."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=25,
            payload=b"AUTH LOGIN\r\n",
        )
        alert = self.engine.analyze(pkt)
        # Single AUTH should not trigger alert
        assert alert is None
        # But should be tracked
        assert "192.168.1.10" in self.engine._smtp_auth_attempts

    def test_smtp_auth_brute_force_on_tick(self):
        """Multiple AUTH commands should trigger brute force alert on tick."""
        config = _default_engine_config()
        config["smtp_auth_threshold"] = 3
        config["smtp_auth_window"] = 300
        engine = ProtocolInspectEngine(config)

        # Simulate 3 AUTH attempts
        for _ in range(3):
            pkt = _make_packet(
                src="10.0.0.50", dst="10.0.0.5",
                sport=54321, dport=25,
                payload=b"AUTH LOGIN\r\n",
            )
            engine.analyze(pkt)

        alerts = engine.on_tick(time.time())
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.WARNING
        assert "AUTH Brute Force" in alerts[0].title
        assert alerts[0].metadata["protocol"] == "smtp"

    def test_smtp_port_465(self):
        """SMTP on port 465 (SMTPS) should be inspected."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=465,
            payload=b"VRFY root\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "User Enumeration" in alert.title


# ===========================================================================
# ProtocolInspectEngine Tests - FTP
# ===========================================================================


class TestProtocolInspectFTP:
    """Tests for ProtocolInspectEngine FTP detections."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_ftp_anonymous_alert(self):
        """USER anonymous should trigger INFO alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"USER anonymous\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "Anonymous" in alert.title
        assert alert.metadata["protocol"] == "ftp"

    def test_ftp_normal_user_no_alert(self):
        """Normal USER command should not trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"USER admin\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ftp_sensitive_file_alert(self):
        """RETR .env should trigger WARNING alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"RETR .env\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Sensitive File" in alert.title
        assert alert.metadata["protocol"] == "ftp"
        assert alert.metadata["matched_pattern"] == ".env"

    def test_ftp_sensitive_file_passwd(self):
        """RETR /etc/passwd should trigger WARNING alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"RETR /etc/passwd\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Sensitive File" in alert.title

    def test_ftp_sensitive_file_stor(self):
        """STOR with sensitive file should also trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"STOR id_rsa\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING

    def test_ftp_normal_retr_no_alert(self):
        """RETR for non-sensitive file should not trigger alert."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=21,
            payload=b"RETR report.pdf\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ftp_530_tracking(self):
        """FTP 530 response should be tracked for brute force detection."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=21, dport=54321,
            payload=b"530 Login incorrect.\r\n",
        )
        alert = self.engine.analyze(pkt)
        # Single 530 does not trigger immediate alert
        assert alert is None
        # But should be tracked (tracked by dst_ip = the client that received the failure)
        assert "192.168.1.10" in self.engine._ftp_fail_attempts

    def test_ftp_brute_force_on_tick(self):
        """Multiple FTP 530 responses should trigger brute force alert."""
        config = _default_engine_config()
        config["ftp_fail_threshold"] = 3
        config["ftp_fail_window"] = 300
        engine = ProtocolInspectEngine(config)

        for _ in range(3):
            pkt = _make_packet(
                src="10.0.0.5", dst="192.168.1.100",
                sport=21, dport=54321,
                payload=b"530 Login incorrect.\r\n",
            )
            engine.analyze(pkt)

        alerts = engine.on_tick(time.time())
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.WARNING
        assert "FTP Login Brute Force" in alerts[0].title


# ===========================================================================
# ProtocolInspectEngine Tests - SSH
# ===========================================================================


class TestProtocolInspectSSH:
    """Tests for ProtocolInspectEngine SSH detections."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_ssh_outdated_protocol_alert(self):
        """SSH-1.5 should trigger WARNING alert for outdated protocol."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-1.5-OldServer_1.0\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Outdated SSH Protocol" in alert.title
        assert alert.metadata["protocol"] == "ssh"
        assert alert.metadata["ssh_version"] == "1.5"

    def test_ssh_modern_no_alert(self):
        """SSH-2.0 with modern software should produce no alert."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_ssh_vulnerable_software_alert(self):
        """SSH with known vulnerable software should trigger INFO alert."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-2.0-OpenSSH_5.3\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "Outdated SSH Software" in alert.title

    def test_ssh_client_banner(self):
        """SSH banner from client side (dport=22) should also be inspected."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=22,
            payload=b"SSH-1.5-PuTTY_0.60\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Outdated SSH Protocol" in alert.title

    def test_ssh_199_protocol_modern(self):
        """SSH-1.99 is backward-compatible, treated as >= 2.0 (major = 1)."""
        # Protocol 1.99 has major version 1, which is < 2.0
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=22, dport=54321,
            payload=b"SSH-1.99-OpenSSH_3.9\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is not None
        # SSH-1.99 major = 1 < 2, triggers outdated protocol alert
        assert alert.severity == Severity.WARNING


# ===========================================================================
# ProtocolInspectEngine Tests - Cross-protocol / Edge cases
# ===========================================================================


class TestProtocolInspectEdgeCases:
    """Edge cases and cross-protocol tests."""

    def setup_method(self):
        self.engine = ProtocolInspectEngine(_default_engine_config())

    def test_non_smtp_port_ignored(self):
        """SMTP payload on non-SMTP port should be ignored."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=443,
            payload=b"VRFY admin\r\n",
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_non_ftp_port_ignored(self):
        """FTP payload on non-FTP port should be ignored."""
        pkt = _make_packet(
            src="192.168.1.10", dst="10.0.0.5",
            sport=54321, dport=443,
            payload=b"USER anonymous\r\n",
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
        """SMTP response from server port (sport=25) should be inspected."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=25, dport=54321,
            payload=b"220 mail.example.com ESMTP\r\n",
        )
        alert = self.engine.analyze(pkt)
        # SMTP responses currently don't generate per-packet alerts
        assert alert is None

    def test_ftp_response_from_server_port(self):
        """FTP welcome banner from server should be inspected."""
        pkt = _make_packet(
            src="10.0.0.5", dst="192.168.1.10",
            sport=21, dport=54321,
            payload=b"220 Welcome to FTP\r\n",
        )
        alert = self.engine.analyze(pkt)
        # 220 response doesn't trigger alert (only 530 is tracked)
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
        """shutdown should clear all tracking data structures."""
        # Add entries to various tracking structures
        self.engine._smtp_auth_attempts["1.2.3.4"] = [time.time()]
        self.engine._ftp_fail_attempts["5.6.7.8"] = [time.time()]
        self.engine._alerted_ssh_banners[("1.2.3.4", "SSH-2.0-old")] = True
        self.engine._alerted_banners[("1.2.3.4", "Apache/2.2.1")] = True

        self.engine.shutdown()
        assert len(self.engine._smtp_auth_attempts) == 0
        assert len(self.engine._ftp_fail_attempts) == 0
        assert len(self.engine._alerted_ssh_banners) == 0
        assert len(self.engine._alerted_banners) == 0
