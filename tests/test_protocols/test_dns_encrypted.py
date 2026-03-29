"""Tests for encrypted DNS (DoT/DoH) detection parsers."""

from netwatcher.protocols.dns_encrypted import (
    detect_dot,
    detect_doh,
    detect_encrypted_dns,
)


class TestDetectDoT:
    """DNS-over-TLS 탐지 테스트."""

    def test_tls12_clienthello_on_853(self):
        # TLS 1.2 ClientHello: ContentType=0x16, Version=0x0303
        payload = bytes([0x16, 0x03, 0x03]) + b"\x00\x80" + b"\x00" * 128
        result = detect_dot(payload, 853)
        assert result is not None
        assert result["type"] == "dot"
        assert result["tls_detected"] is True

    def test_tls10_clienthello_on_853(self):
        payload = bytes([0x16, 0x03, 0x01]) + b"\x00\x40" + b"\x00" * 64
        result = detect_dot(payload, 853)
        assert result is not None
        assert result["type"] == "dot"
        assert result["tls_detected"] is True

    def test_non_tls_on_853(self):
        payload = b"\x00\x01\x02\x03\x04\x05"
        result = detect_dot(payload, 853)
        assert result is not None
        assert result["type"] == "dot"
        assert result["tls_detected"] is False

    def test_wrong_port_returns_none(self):
        payload = bytes([0x16, 0x03, 0x03]) + b"\x00\x80"
        assert detect_dot(payload, 443) is None
        assert detect_dot(payload, 53) is None

    def test_empty_payload_returns_none(self):
        assert detect_dot(b"", 853) is None

    def test_truncated_payload(self):
        # 3바이트 미만은 TLS 판별 불가 -- 포트 853이므로 dot 결과 반환
        payload = bytes([0x16, 0x03])
        assert detect_dot(payload, 853) is None

        # 정확히 3바이트: TLS 핸드셰이크지만 버전 불완전
        payload3 = bytes([0x16, 0x03, 0x00])
        result = detect_dot(payload3, 853)
        assert result is not None
        assert result["tls_detected"] is False

    def test_invalid_tls_version(self):
        payload = bytes([0x16, 0x04, 0x00]) + b"\x00" * 10
        result = detect_dot(payload, 853)
        assert result is not None
        assert result["tls_detected"] is False


class TestDetectDoH:
    """DNS-over-HTTPS 탐지 테스트."""

    def test_get_dns_query(self):
        payload = b"GET /dns-query?dns=AAAB HTTP/1.1\r\nHost: dns.google\r\n\r\n"
        result = detect_doh(payload, 443)
        assert result is not None
        assert result["type"] == "doh"
        assert result["method"] == "GET"
        assert "/dns-query" in result["path"]
        assert result["provider"] == "dns.google"

    def test_post_dns_query(self):
        payload = (
            b"POST /dns-query HTTP/1.1\r\n"
            b"Host: cloudflare-dns.com\r\n"
            b"Content-Type: application/dns-message\r\n\r\n"
        )
        result = detect_doh(payload, 443)
        assert result is not None
        assert result["type"] == "doh"
        assert result["method"] == "POST"
        assert result["provider"] == "cloudflare-dns.com"

    def test_dns_message_content_type_only(self):
        payload = (
            b"POST /resolve HTTP/1.1\r\n"
            b"Content-Type: application/dns-message\r\n\r\n"
        )
        result = detect_doh(payload, 443)
        assert result is not None
        assert result["type"] == "doh"

    def test_no_doh_pattern_returns_none(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert detect_doh(payload, 443) is None

    def test_non_http_returns_none(self):
        payload = b"\x16\x03\x03\x00\x80" + b"\x00" * 128
        assert detect_doh(payload, 443) is None

    def test_empty_payload_returns_none(self):
        assert detect_doh(b"", 443) is None

    def test_known_provider_quad9(self):
        payload = b"GET /dns-query?dns=test HTTP/1.1\r\nHost: dns.quad9.net\r\n\r\n"
        result = detect_doh(payload, 443)
        assert result is not None
        assert result["provider"] == "dns.quad9.net"

    def test_unknown_provider(self):
        payload = b"GET /dns-query HTTP/1.1\r\nHost: custom-dns.example.com\r\n\r\n"
        result = detect_doh(payload, 443)
        assert result is not None
        assert result["provider"] is None


class TestDetectEncryptedDNS:
    """통합 암호화 DNS 탐지 테스트."""

    def test_dot_takes_priority(self):
        payload = bytes([0x16, 0x03, 0x03]) + b"\x00\x80" + b"\x00" * 128
        result = detect_encrypted_dns(payload, 853)
        assert result is not None
        assert result["type"] == "dot"

    def test_falls_through_to_doh(self):
        payload = b"GET /dns-query HTTP/1.1\r\nHost: dns.google\r\n\r\n"
        result = detect_encrypted_dns(payload, 443)
        assert result is not None
        assert result["type"] == "doh"

    def test_neither_returns_none(self):
        payload = b"\x00\x01\x02\x03"
        assert detect_encrypted_dns(payload, 80) is None
