"""단일 패킷 검사용 경량 RDP(Remote Desktop Protocol) 파서.

처음 2048 바이트만 파싱한다. RDP가 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

import struct

_MAX_PAYLOAD_BYTES = 2048

# TPKT 헤더
_TPKT_VERSION = 3
_TPKT_HEADER_SIZE = 4

# X.224 Connection Request 코드
_X224_CR_CODE = 0xE0
# X.224 Connection Confirm 코드
_X224_CC_CODE = 0xD0

# RDP 협상 요청/응답 타입
_RDP_NEG_REQ_TYPE  = 0x01
_RDP_NEG_RSP_TYPE  = 0x02
_RDP_NEG_FAILURE   = 0x03

# 요청 프로토콜 플래그
_PROTOCOL_RDP    = 0x00000000  # 표준 RDP
_PROTOCOL_TLS    = 0x00000001  # TLS 1.0+
_PROTOCOL_CREDSSP = 0x00000002  # CredSSP (NLA)
_PROTOCOL_RDSTLS = 0x00000008  # RDSTLS

_PROTOCOL_NAMES = {
    _PROTOCOL_RDP:     "Standard RDP",
    _PROTOCOL_TLS:     "TLS",
    _PROTOCOL_CREDSSP: "CredSSP (NLA)",
    _PROTOCOL_RDSTLS:  "RDSTLS",
}

# RDP 쿠키 접두사
_RDP_COOKIE_PREFIX = b"Cookie: mstshash="


def parse_rdp_connection_request(payload: bytes) -> dict | None:
    """RDP에서 사용하는 X.224 Connection Request를 파싱한다.

    {"cookie": str | None, "requested_protocols": int,
     "has_nla": bool, "has_tls": bool} 또는 None을 반환한다.
    """
    if not payload or len(payload) < _TPKT_HEADER_SIZE + 3:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # TPKT 헤더: version(1) + reserved(1) + length(2, big-endian)
    if data[0] != _TPKT_VERSION:
        return None

    tpkt_length = struct.unpack("!H", data[2:4])[0]
    if tpkt_length < _TPKT_HEADER_SIZE + 3:
        return None

    # X.224 CR PDU: length(1) + code(1) + dst_ref(2) + src_ref(2) + class(1)
    x224_offset = _TPKT_HEADER_SIZE
    if len(data) < x224_offset + 2:
        return None

    x224_length = data[x224_offset]
    x224_code   = data[x224_offset + 1]

    # Connection Request 확인 (상위 4비트 = 0xE)
    if (x224_code & 0xF0) != _X224_CR_CODE:
        return None

    # X.224 고정 필드 건너뛰기: length(1) + code(1) + dst_ref(2) + src_ref(2) + class(1) = 7
    variable_offset = x224_offset + 7

    # 쿠키 추출 ("Cookie: mstshash=username\r\n")
    cookie: str | None = None
    remaining = data[variable_offset:]

    cookie_idx = remaining.find(_RDP_COOKIE_PREFIX)
    if cookie_idx >= 0:
        cookie_start = cookie_idx + len(_RDP_COOKIE_PREFIX)
        cookie_end   = remaining.find(b"\r\n", cookie_start)
        if cookie_end < 0:
            cookie_end = len(remaining)
        try:
            cookie = remaining[cookie_start:cookie_end].decode(
                "ascii", errors="replace"
            )
        except (UnicodeDecodeError, ValueError):
            cookie = None

    # RDP Negotiation Request 찾기
    # 구조: type(1=0x01) + flags(1) + length(2=0x0008) + requestedProtocols(4)
    requested_protocols = _PROTOCOL_RDP
    has_tls = False
    has_nla = False

    # 쿠키 이후 또는 변수 영역에서 협상 요청을 찾는다
    neg_search_start = variable_offset
    if cookie_idx >= 0:
        cr_end = remaining.find(b"\r\n", cookie_idx)
        if cr_end >= 0:
            neg_search_start = variable_offset + cr_end + 2

    neg_data = data[neg_search_start:]
    if len(neg_data) >= 8:
        neg_type = neg_data[0]
        if neg_type == _RDP_NEG_REQ_TYPE:
            neg_length = struct.unpack("<H", neg_data[2:4])[0]
            if neg_length == 8 and len(neg_data) >= 8:
                requested_protocols = struct.unpack("<I", neg_data[4:8])[0]
                has_tls = bool(requested_protocols & _PROTOCOL_TLS)
                has_nla = bool(requested_protocols & _PROTOCOL_CREDSSP)

    return {
        "cookie":              cookie,
        "requested_protocols": requested_protocols,
        "has_nla":             has_nla,
        "has_tls":             has_tls,
    }


def parse_rdp_negotiation_response(payload: bytes) -> dict | None:
    """RDP 협상이 포함된 X.224 Connection Confirm을 파싱한다.

    {"selected_protocol": int, "protocol_name": str} 또는 None을 반환한다.
    """
    if not payload or len(payload) < _TPKT_HEADER_SIZE + 3:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # TPKT 헤더 확인
    if data[0] != _TPKT_VERSION:
        return None

    # X.224 CC PDU
    x224_offset = _TPKT_HEADER_SIZE
    if len(data) < x224_offset + 2:
        return None

    x224_code = data[x224_offset + 1]

    # Connection Confirm 확인 (상위 4비트 = 0xD)
    if (x224_code & 0xF0) != _X224_CC_CODE:
        return None

    # X.224 고정 필드 건너뛰기 (7바이트)
    neg_offset = x224_offset + 7

    # RDP Negotiation Response: type(1=0x02) + flags(1) + length(2) + selectedProtocol(4)
    if len(data) < neg_offset + 8:
        return None

    neg_type = data[neg_offset]
    if neg_type == _RDP_NEG_RSP_TYPE:
        neg_length = struct.unpack("<H", data[neg_offset + 2:neg_offset + 4])[0]
        if neg_length != 8:
            return None
        selected = struct.unpack("<I", data[neg_offset + 4:neg_offset + 8])[0]
        protocol_name = _PROTOCOL_NAMES.get(selected, f"Unknown(0x{selected:08X})")
        return {
            "selected_protocol": selected,
            "protocol_name":     protocol_name,
        }

    if neg_type == _RDP_NEG_FAILURE:
        return None

    return None


def is_rdp(payload: bytes, dst_port: int) -> bool:
    """페이로드가 RDP(TPKT + X.224) 트래픽인지 빠르게 확인한다.

    포트 3389와 TPKT 버전 3을 검사한다.
    """
    if dst_port != 3389:
        return False

    if not payload or len(payload) < _TPKT_HEADER_SIZE:
        return False

    return payload[0] == _TPKT_VERSION
