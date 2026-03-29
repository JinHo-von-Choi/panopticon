"""Tests for QUIC/HTTP3 Initial packet parsers."""

import struct

from netwatcher.protocols.quic import (
    parse_quic_initial,
    extract_quic_sni,
    is_quic,
)


def _build_quic_initial(
    version: int = 0x00000001,
    dcid: bytes = b"\xaa\xbb\xcc\xdd",
    scid: bytes = b"\x11\x22",
    packet_type: int = 0x00,
) -> bytes:
    """테스트용 QUIC Initial 패킷을 조립한다."""
    first_byte = 0x80 | 0x40 | (packet_type << 4)
    buf = bytes([first_byte])
    buf += struct.pack("!I", version)
    buf += bytes([len(dcid)]) + dcid
    buf += bytes([len(scid)]) + scid
    buf += b"\x00" * 20  # 나머지 페이로드
    return buf


class TestParseQuicInitial:
    """QUIC Initial 헤더 파싱 테스트."""

    def test_valid_initial_v1(self):
        payload = _build_quic_initial(version=0x00000001)
        result = parse_quic_initial(payload)
        assert result is not None
        assert result["version"] == 0x00000001
        assert result["dcid"] == b"\xaa\xbb\xcc\xdd"
        assert result["dcid_len"] == 4
        assert result["scid"] == b"\x11\x22"
        assert result["scid_len"] == 2
        assert result["is_long_header"] is True
        assert result["packet_type"] == "Initial"

    def test_valid_initial_v2(self):
        payload = _build_quic_initial(version=0x6B3343CF)
        result = parse_quic_initial(payload)
        assert result is not None
        assert result["version"] == 0x6B3343CF

    def test_handshake_type(self):
        payload = _build_quic_initial(packet_type=0x02)
        result = parse_quic_initial(payload)
        assert result is not None
        assert result["packet_type"] == "Handshake"

    def test_0rtt_type(self):
        payload = _build_quic_initial(packet_type=0x01)
        result = parse_quic_initial(payload)
        assert result is not None
        assert result["packet_type"] == "0-RTT"

    def test_retry_type(self):
        payload = _build_quic_initial(packet_type=0x03)
        result = parse_quic_initial(payload)
        assert result is not None
        assert result["packet_type"] == "Retry"

    def test_empty_cids(self):
        payload = _build_quic_initial(dcid=b"", scid=b"")
        result = parse_quic_initial(payload)
        assert result is not None
        assert result["dcid_len"] == 0
        assert result["scid_len"] == 0
        assert result["dcid"] == b""
        assert result["scid"] == b""

    def test_short_header_returns_none(self):
        # Short Header: form bit = 0
        payload = bytes([0x40]) + b"\x00" * 20
        assert parse_quic_initial(payload) is None

    def test_missing_fixed_bit_returns_none(self):
        # Form bit set but fixed bit not set
        payload = bytes([0x80]) + struct.pack("!I", 1) + b"\x00" * 20
        assert parse_quic_initial(payload) is None

    def test_truncated_payload_returns_none(self):
        assert parse_quic_initial(b"") is None
        assert parse_quic_initial(b"\xc0\x00\x00") is None

    def test_truncated_dcid_returns_none(self):
        # DCID 길이가 20이지만 실제 데이터가 부족
        first_byte = 0xC0
        buf = bytes([first_byte]) + struct.pack("!I", 1) + bytes([20])
        buf += b"\x00" * 5  # 20바이트 미만
        assert parse_quic_initial(buf) is None

    def test_truncated_scid_returns_none(self):
        first_byte = 0xC0
        dcid = b"\xaa\xbb"
        buf = bytes([first_byte]) + struct.pack("!I", 1)
        buf += bytes([len(dcid)]) + dcid
        buf += bytes([10])  # SCID 길이 10이지만 데이터 없음
        assert parse_quic_initial(buf) is None


class TestExtractQuicSni:
    """QUIC SNI 추출 테스트."""

    def _build_sni_extension(self, hostname: str) -> bytes:
        """SNI 확장 바이트를 조립한다."""
        name_bytes = hostname.encode("ascii")
        name_len   = len(name_bytes)
        # SNI 확장: type(2) + ext_len(2) + list_len(2) + name_type(1) + name_len(2) + name
        list_len = 1 + 2 + name_len
        ext_len  = 2 + list_len
        buf = struct.pack("!H", 0x0000)          # Extension Type: SNI
        buf += struct.pack("!H", ext_len)         # Extension Length
        buf += struct.pack("!H", list_len)        # Server Name List Length
        buf += bytes([0x00])                      # Name Type: host_name
        buf += struct.pack("!H", name_len)        # Name Length
        buf += name_bytes                         # Name
        return buf

    def test_extract_sni_from_payload(self):
        prefix = b"\x00" * 50
        sni_ext = self._build_sni_extension("example.com")
        payload = prefix + sni_ext + b"\x00" * 50
        result = extract_quic_sni(payload)
        assert result == "example.com"

    def test_extract_sni_google(self):
        prefix = b"\x00" * 30
        sni_ext = self._build_sni_extension("www.google.com")
        payload = prefix + sni_ext
        result = extract_quic_sni(payload)
        assert result == "www.google.com"

    def test_no_sni_returns_none(self):
        payload = b"\x00" * 100
        assert extract_quic_sni(payload) is None

    def test_empty_returns_none(self):
        assert extract_quic_sni(b"") is None

    def test_short_payload_returns_none(self):
        assert extract_quic_sni(b"\x00" * 5) is None


class TestIsQuic:
    """QUIC 빠른 확인 테스트."""

    def test_valid_quic_v1(self):
        payload = _build_quic_initial(version=0x00000001)
        assert is_quic(payload, 443) is True

    def test_valid_quic_v2(self):
        payload = _build_quic_initial(version=0x6B3343CF)
        assert is_quic(payload, 443) is True

    def test_unknown_version(self):
        payload = _build_quic_initial(version=0xDEADBEEF)
        assert is_quic(payload, 443) is False

    def test_short_header(self):
        payload = bytes([0x40]) + b"\x00" * 20
        assert is_quic(payload, 443) is False

    def test_empty(self):
        assert is_quic(b"", 443) is False

    def test_too_short(self):
        assert is_quic(b"\xc0\x00", 443) is False
