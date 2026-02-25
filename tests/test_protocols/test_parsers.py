"""Tests for protocol parsers: SMTP, FTP, SSH."""

from netwatcher.protocols.smtp import parse_smtp_command, parse_smtp_response
from netwatcher.protocols.ftp import parse_ftp_command, parse_ftp_response
from netwatcher.protocols.ssh import parse_ssh_banner


class TestSMTPCommandParser:
    def test_ehlo(self):
        result = parse_smtp_command(b"EHLO mail.example.com\r\n")
        assert result is not None
        assert result["command"] == "EHLO"
        assert result["argument"] == "mail.example.com"

    def test_helo(self):
        result = parse_smtp_command(b"HELO localhost\r\n")
        assert result is not None
        assert result["command"] == "HELO"
        assert result["argument"] == "localhost"

    def test_mail_from(self):
        result = parse_smtp_command(b"MAIL FROM:<user@example.com>\r\n")
        assert result is not None
        assert result["command"] == "MAIL FROM"
        assert "<user@example.com>" in result["argument"]

    def test_rcpt_to(self):
        result = parse_smtp_command(b"RCPT TO:<admin@target.com>\r\n")
        assert result is not None
        assert result["command"] == "RCPT TO"
        assert "<admin@target.com>" in result["argument"]

    def test_auth(self):
        result = parse_smtp_command(b"AUTH LOGIN\r\n")
        assert result is not None
        assert result["command"] == "AUTH"
        assert result["argument"] == "LOGIN"

    def test_quit(self):
        result = parse_smtp_command(b"QUIT\r\n")
        assert result is not None
        assert result["command"] == "QUIT"
        assert result["argument"] == ""

    def test_data(self):
        result = parse_smtp_command(b"DATA\r\n")
        assert result is not None
        assert result["command"] == "DATA"

    def test_non_smtp_returns_none(self):
        result = parse_smtp_command(b"GET / HTTP/1.1\r\n")
        assert result is None

    def test_empty_returns_none(self):
        assert parse_smtp_command(b"") is None
        assert parse_smtp_command(b"\r\n") is None

    def test_binary_returns_none(self):
        assert parse_smtp_command(b"\x00\x01\x02\x03") is None

    def test_lf_only_line_ending(self):
        result = parse_smtp_command(b"EHLO test.com\n")
        assert result is not None
        assert result["command"] == "EHLO"

    def test_no_line_ending(self):
        result = parse_smtp_command(b"EHLO partial")
        assert result is not None
        assert result["command"] == "EHLO"


class TestSMTPResponseParser:
    def test_greeting(self):
        result = parse_smtp_response(b"220 mail.example.com ESMTP ready\r\n")
        assert result is not None
        assert result["code"] == 220
        assert "ESMTP" in result["message"]

    def test_ok(self):
        result = parse_smtp_response(b"250 OK\r\n")
        assert result is not None
        assert result["code"] == 250
        assert result["message"] == "OK"

    def test_auth_required(self):
        result = parse_smtp_response(b"530 Authentication required\r\n")
        assert result is not None
        assert result["code"] == 530

    def test_multiline_continuation(self):
        result = parse_smtp_response(b"250-mail.example.com\r\n250 SIZE 10240000\r\n")
        assert result is not None
        assert result["code"] == 250

    def test_non_smtp_returns_none(self):
        assert parse_smtp_response(b"HTTP/1.1 200 OK\r\n") is None

    def test_empty_returns_none(self):
        assert parse_smtp_response(b"") is None

    def test_code_only(self):
        result = parse_smtp_response(b"250\r\n")
        assert result is not None
        assert result["code"] == 250
        assert result["message"] == ""


class TestFTPCommandParser:
    def test_user(self):
        result = parse_ftp_command(b"USER anonymous\r\n")
        assert result is not None
        assert result["command"] == "USER"
        assert result["argument"] == "anonymous"

    def test_pass(self):
        result = parse_ftp_command(b"PASS secret123\r\n")
        assert result is not None
        assert result["command"] == "PASS"
        assert result["argument"] == "secret123"

    def test_retr(self):
        result = parse_ftp_command(b"RETR /etc/passwd\r\n")
        assert result is not None
        assert result["command"] == "RETR"
        assert result["argument"] == "/etc/passwd"

    def test_stor(self):
        result = parse_ftp_command(b"STOR malware.exe\r\n")
        assert result is not None
        assert result["command"] == "STOR"
        assert result["argument"] == "malware.exe"

    def test_list(self):
        result = parse_ftp_command(b"LIST\r\n")
        assert result is not None
        assert result["command"] == "LIST"

    def test_cwd(self):
        result = parse_ftp_command(b"CWD /var/www\r\n")
        assert result is not None
        assert result["command"] == "CWD"

    def test_pasv(self):
        result = parse_ftp_command(b"PASV\r\n")
        assert result is not None
        assert result["command"] == "PASV"

    def test_port(self):
        result = parse_ftp_command(b"PORT 192,168,1,1,10,20\r\n")
        assert result is not None
        assert result["command"] == "PORT"

    def test_quit(self):
        result = parse_ftp_command(b"QUIT\r\n")
        assert result is not None
        assert result["command"] == "QUIT"

    def test_non_ftp_returns_none(self):
        assert parse_ftp_command(b"GET / HTTP/1.1\r\n") is None

    def test_empty_returns_none(self):
        assert parse_ftp_command(b"") is None

    def test_unknown_command_returns_none(self):
        assert parse_ftp_command(b"INVALID command\r\n") is None


class TestFTPResponseParser:
    def test_welcome(self):
        result = parse_ftp_response(b"220 Welcome to FTP server\r\n")
        assert result is not None
        assert result["code"] == 220
        assert "Welcome" in result["message"]

    def test_login_ok(self):
        result = parse_ftp_response(b"230 Login successful\r\n")
        assert result is not None
        assert result["code"] == 230

    def test_transfer_complete(self):
        result = parse_ftp_response(b"226 Transfer complete\r\n")
        assert result is not None
        assert result["code"] == 226

    def test_login_failed(self):
        result = parse_ftp_response(b"530 Login incorrect\r\n")
        assert result is not None
        assert result["code"] == 530

    def test_pasv_response(self):
        result = parse_ftp_response(b"227 Entering Passive Mode (192,168,1,1,10,20)\r\n")
        assert result is not None
        assert result["code"] == 227

    def test_non_ftp_returns_none(self):
        assert parse_ftp_response(b"SSH-2.0-OpenSSH_8.9") is None

    def test_empty_returns_none(self):
        assert parse_ftp_response(b"") is None


class TestSSHBannerParser:
    def test_openssh(self):
        result = parse_ssh_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
        assert result is not None
        assert result["protocol"] == "2.0"
        assert result["software"] == "OpenSSH_8.9p1"
        assert result["comments"] == "Ubuntu-3"

    def test_dropbear(self):
        result = parse_ssh_banner(b"SSH-2.0-dropbear_2022.83\r\n")
        assert result is not None
        assert result["protocol"] == "2.0"
        assert result["software"] == "dropbear_2022.83"
        assert result["comments"] is None

    def test_old_ssh1(self):
        result = parse_ssh_banner(b"SSH-1.99-OpenSSH_3.9\r\n")
        assert result is not None
        assert result["protocol"] == "1.99"

    def test_no_comments(self):
        result = parse_ssh_banner(b"SSH-2.0-libssh-0.9.6\r\n")
        assert result is not None
        assert result["software"] == "libssh-0.9.6"
        assert result["comments"] is None

    def test_non_ssh_returns_none(self):
        assert parse_ssh_banner(b"HTTP/1.1 200 OK\r\n") is None
        assert parse_ssh_banner(b"220 SMTP ready\r\n") is None

    def test_empty_returns_none(self):
        assert parse_ssh_banner(b"") is None

    def test_partial_banner_no_terminator(self):
        result = parse_ssh_banner(b"SSH-2.0-OpenSSH_9.0")
        assert result is not None
        assert result["protocol"] == "2.0"

    def test_lf_only(self):
        result = parse_ssh_banner(b"SSH-2.0-OpenSSH_9.0\n")
        assert result is not None

    def test_malformed_no_software(self):
        assert parse_ssh_banner(b"SSH-2.0-\r\n") is None

    def test_malformed_no_version(self):
        assert parse_ssh_banner(b"SSH--OpenSSH\r\n") is None
