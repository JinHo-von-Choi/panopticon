"""단일 패킷 검사용 경량 QUIC Initial 패킷 파서(RFC 9000).

처음 2048 바이트만 파싱한다. QUIC이 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

import struct

_MAX_PAYLOAD_BYTES = 2048

# QUIC Long Header 비트 마스크
_HEADER_FORM_BIT = 0x80  # 1 = Long Header
_FIXED_BIT       = 0x40  # 항상 1이어야 함
_PACKET_TYPE_MASK = 0x30  # Long Header 패킷 타입 (2비트)

# Long Header 패킷 타입
_PACKET_TYPE_INITIAL   = 0x00
_PACKET_TYPE_0RTT      = 0x01
_PACKET_TYPE_HANDSHAKE = 0x02
_PACKET_TYPE_RETRY     = 0x03

_PACKET_TYPE_NAMES = {
    _PACKET_TYPE_INITIAL:   "Initial",
    _PACKET_TYPE_0RTT:      "0-RTT",
    _PACKET_TYPE_HANDSHAKE: "Handshake",
    _PACKET_TYPE_RETRY:     "Retry",
}

# 알려진 QUIC 버전
_QUIC_VERSION_1 = 0x00000001
_QUIC_VERSION_2 = 0x6B3343CF

_KNOWN_VERSIONS = frozenset({
    _QUIC_VERSION_1,
    _QUIC_VERSION_2,
})

# TLS SNI 확장 타입
_TLS_EXT_SNI = 0x0000


def parse_quic_initial(payload: bytes) -> dict | None:
    """QUIC Initial 패킷 헤더를 파싱한다(RFC 9000).

    {"version": int, "dcid": bytes, "dcid_len": int,
     "scid": bytes, "scid_len": int,
     "is_long_header": bool, "packet_type": str} 또는 None을 반환한다.
    """
    if not payload or len(payload) < 7:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    first_byte = data[0]

    # Long Header 확인: 최상위 비트가 1
    if not (first_byte & _HEADER_FORM_BIT):
        return None

    # Fixed 비트 확인
    if not (first_byte & _FIXED_BIT):
        return None

    is_long_header = True
    packet_type_bits = (first_byte & _PACKET_TYPE_MASK) >> 4
    packet_type_name = _PACKET_TYPE_NAMES.get(packet_type_bits, f"Unknown({packet_type_bits})")

    # Version (4 bytes, big-endian) - offset 1
    if len(data) < 5:
        return None
    version = struct.unpack("!I", data[1:5])[0]

    # DCID Length (1 byte) - offset 5
    if len(data) < 6:
        return None
    dcid_len = data[5]

    # DCID - offset 6
    dcid_end = 6 + dcid_len
    if len(data) < dcid_end:
        return None
    dcid = bytes(data[6:dcid_end])

    # SCID Length (1 byte)
    if len(data) < dcid_end + 1:
        return None
    scid_len = data[dcid_end]

    # SCID
    scid_end = dcid_end + 1 + scid_len
    if len(data) < scid_end:
        return None
    scid = bytes(data[dcid_end + 1:scid_end])

    return {
        "version":        version,
        "dcid":           dcid,
        "dcid_len":       dcid_len,
        "scid":           scid,
        "scid_len":       scid_len,
        "is_long_header": is_long_header,
        "packet_type":    packet_type_name,
    }


def extract_quic_sni(payload: bytes) -> str | None:
    """QUIC Initial 패킷에서 SNI를 추출한다(최선 노력 휴리스틱).

    TLS ClientHello의 SNI 확장(타입 0x0000)을 페이로드에서
    직접 검색한다. QUIC Initial은 암호화되어 있으므로
    항상 성공하지는 않는다. SNI 호스트명 또는 None을 반환한다.
    """
    if not payload or len(payload) < 20:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # TLS ClientHello 시그니처 검색: HandshakeType=0x01
    # SNI 확장: 타입 0x0000, 이름 타입 0x00(host_name)
    #
    # SNI 확장 구조:
    # ExtensionType(2) + Length(2) + ServerNameListLength(2)
    # + NameType(1) + NameLength(2) + Name(N)
    offset = 0
    while offset < len(data) - 9:
        # SNI 확장 타입 0x00 0x00을 찾되 오탐 최소화
        if data[offset] == 0x00 and data[offset + 1] == 0x00:
            # 확장 길이
            if offset + 4 > len(data):
                break
            ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            if ext_len < 5 or ext_len > 512:
                offset += 1
                continue

            # ServerNameList 길이
            sni_offset = offset + 4
            if sni_offset + 2 > len(data):
                break
            list_len = struct.unpack("!H", data[sni_offset:sni_offset + 2])[0]
            if list_len < 3 or list_len > ext_len:
                offset += 1
                continue

            # NameType (0x00 = host_name)
            name_type_offset = sni_offset + 2
            if name_type_offset >= len(data):
                break
            if data[name_type_offset] != 0x00:
                offset += 1
                continue

            # NameLength
            name_len_offset = name_type_offset + 1
            if name_len_offset + 2 > len(data):
                break
            name_len = struct.unpack("!H", data[name_len_offset:name_len_offset + 2])[0]
            if name_len < 1 or name_len > 255:
                offset += 1
                continue

            # Name
            name_offset = name_len_offset + 2
            if name_offset + name_len > len(data):
                break

            name_bytes = data[name_offset:name_offset + name_len]
            try:
                hostname = name_bytes.decode("ascii")
                # 유효한 호스트명인지 기본 확인
                if "." in hostname and all(
                    c.isalnum() or c in ".-" for c in hostname
                ):
                    return hostname
            except (UnicodeDecodeError, ValueError):
                pass

        offset += 1

    return None


def is_quic(payload: bytes, dst_port: int) -> bool:
    """페이로드가 QUIC 패킷인지 빠르게 확인한다.

    UDP 페이로드의 Long Header 형식 비트와 알려진 버전을 검사한다.
    """
    if not payload or len(payload) < 5:
        return False

    first_byte = payload[0]

    # Long Header: Form 비트 + Fixed 비트
    if not (first_byte & _HEADER_FORM_BIT):
        return False
    if not (first_byte & _FIXED_BIT):
        return False

    # Version 확인
    version = struct.unpack("!I", payload[1:5])[0]
    return version in _KNOWN_VERSIONS
