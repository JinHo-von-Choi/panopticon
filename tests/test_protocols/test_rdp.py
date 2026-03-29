"""Tests for RDP protocol parsers."""

import struct

from netwatcher.protocols.rdp import (
    parse_rdp_connection_request,
    parse_rdp_negotiation_response,
    is_rdp,
)


def _build_tpkt(payload_after_tpkt: bytes) -> bytes:
    """TPKT 헤더를 붙인다."""
    total_len = 4 + len(payload_after_tpkt)
    return bytes([3, 0]) + struct.pack("!H", total_len) + payload_after_tpkt


def _build_x224_cr(
    cookie: str | None = None,
    requested_protocols: int | None = None,
) -> bytes:
    """X.224 Connection Request PDU를 조립한다."""
    # X.224 고정 필드: length(1) + code(1=0xE0) + dst_ref(2) + src_ref(2) + class(1)
    variable = b""

    if cookie is not None:
        variable += f"Cookie: mstshash={cookie}\r\n".encode("ascii")

    if requested_protocols is not None:
        # RDP Negotiation Request: type(1) + flags(1) + length(2) + protocols(4)
        variable += bytes([0x01, 0x00])
        variable += struct.pack("<H", 8)
        variable += struct.pack("<I", requested_protocols)

    x224_length = 6 + len(variable)  # code(1) + dst_ref(2) + src_ref(2) + class(1) + variable
    x224 = bytes([x224_length, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00])
    return _build_tpkt(x224 + variable)


def _build_x224_cc(selected_protocol: int | None = None) -> bytes:
    """X.224 Connection Confirm PDU를 조립한다."""
    variable = b""
    if selected_protocol is not None:
        variable += bytes([0x02, 0x00])  # type + flags
        variable += struct.pack("<H", 8)
        variable += struct.pack("<I", selected_protocol)

    x224_length = 6 + len(variable)
    x224 = bytes([x224_length, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00])
    return _build_tpkt(x224 + variable)


class TestParseRDPConnectionRequest:
    """RDP Connection Request 파싱 테스트."""

    def test_basic_cr_with_cookie_and_nla(self):
        payload = _build_x224_cr(
            cookie="admin",
            requested_protocols=0x00000003,  # TLS + CredSSP
        )
        result = parse_rdp_connection_request(payload)
        assert result is not None
        assert result["cookie"] == "admin"
        assert result["has_tls"] is True
        assert result["has_nla"] is True
        assert result["requested_protocols"] == 3

    def test_cr_tls_only(self):
        payload = _build_x224_cr(
            cookie="user1",
            requested_protocols=0x00000001,
        )
        result = parse_rdp_connection_request(payload)
        assert result is not None
        assert result["has_tls"] is True
        assert result["has_nla"] is False

    def test_cr_standard_rdp(self):
        payload = _build_x224_cr(
            cookie="test",
            requested_protocols=0x00000000,
        )
        result = parse_rdp_connection_request(payload)
        assert result is not None
        assert result["has_tls"] is False
        assert result["has_nla"] is False

    def test_cr_without_cookie(self):
        payload = _build_x224_cr(
            cookie=None,
            requested_protocols=0x00000002,
        )
        result = parse_rdp_connection_request(payload)
        assert result is not None
        assert result["cookie"] is None
        assert result["has_nla"] is True

    def test_cr_without_negotiation(self):
        payload = _build_x224_cr(cookie="admin", requested_protocols=None)
        result = parse_rdp_connection_request(payload)
        assert result is not None
        assert result["cookie"] == "admin"
        assert result["requested_protocols"] == 0

    def test_wrong_tpkt_version_returns_none(self):
        payload = bytes([2, 0, 0, 20]) + b"\x00" * 16
        assert parse_rdp_connection_request(payload) is None

    def test_wrong_x224_code_returns_none(self):
        # X.224 Data 코드 (0xF0)
        x224 = bytes([6, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00])
        payload = _build_tpkt(x224)
        assert parse_rdp_connection_request(payload) is None

    def test_empty_returns_none(self):
        assert parse_rdp_connection_request(b"") is None

    def test_truncated_returns_none(self):
        assert parse_rdp_connection_request(b"\x03\x00") is None
        assert parse_rdp_connection_request(b"\x03\x00\x00\x05") is None


class TestParseRDPNegotiationResponse:
    """RDP Negotiation Response 파싱 테스트."""

    def test_tls_selected(self):
        payload = _build_x224_cc(selected_protocol=0x00000001)
        result = parse_rdp_negotiation_response(payload)
        assert result is not None
        assert result["selected_protocol"] == 1
        assert result["protocol_name"] == "TLS"

    def test_credssp_selected(self):
        payload = _build_x224_cc(selected_protocol=0x00000002)
        result = parse_rdp_negotiation_response(payload)
        assert result is not None
        assert result["selected_protocol"] == 2
        assert result["protocol_name"] == "CredSSP (NLA)"

    def test_standard_rdp_selected(self):
        payload = _build_x224_cc(selected_protocol=0x00000000)
        result = parse_rdp_negotiation_response(payload)
        assert result is not None
        assert result["selected_protocol"] == 0
        assert result["protocol_name"] == "Standard RDP"

    def test_no_negotiation_returns_none(self):
        payload = _build_x224_cc(selected_protocol=None)
        assert parse_rdp_negotiation_response(payload) is None

    def test_wrong_tpkt_returns_none(self):
        payload = bytes([2, 0, 0, 20]) + b"\x00" * 16
        assert parse_rdp_negotiation_response(payload) is None

    def test_cr_code_returns_none(self):
        # Connection Request 코드 -- CC가 아님
        payload = _build_x224_cr(cookie="test", requested_protocols=1)
        assert parse_rdp_negotiation_response(payload) is None

    def test_empty_returns_none(self):
        assert parse_rdp_negotiation_response(b"") is None


class TestIsRDP:
    """RDP 빠른 확인 테스트."""

    def test_valid_rdp_on_3389(self):
        payload = _build_x224_cr(cookie="test", requested_protocols=1)
        assert is_rdp(payload, 3389) is True

    def test_wrong_port(self):
        payload = _build_x224_cr(cookie="test", requested_protocols=1)
        assert is_rdp(payload, 443) is False
        assert is_rdp(payload, 80) is False

    def test_wrong_tpkt_version(self):
        payload = bytes([2, 0, 0, 20]) + b"\x00" * 16
        assert is_rdp(payload, 3389) is False

    def test_empty(self):
        assert is_rdp(b"", 3389) is False

    def test_too_short(self):
        assert is_rdp(b"\x03", 3389) is False
