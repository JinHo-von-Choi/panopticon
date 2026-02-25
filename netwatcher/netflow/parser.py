"""NetFlow v5 / v9 / IPFIX UDP 페이로드 파서.

v5: 표준 고정 길이 포맷, 순수 Python struct 파싱.
v9/IPFIX: 추후 구현 예정 (TODO 마커 포함).
"""

from __future__ import annotations

import socket
import struct
import logging

from netwatcher.netflow.models import FlowRecord, Protocol

logger = logging.getLogger("netwatcher.netflow.parser")

# NetFlow v5 구조체 포맷
_V5_HEADER_FMT  = "!HHIIIIBBH"   # 24 bytes
_V5_HEADER_SIZE = struct.calcsize(_V5_HEADER_FMT)   # 24

_V5_RECORD_FMT  = "!4s4s4sHHIIIIHHBBBBHHBBH"  # 48 bytes
_V5_RECORD_SIZE = struct.calcsize(_V5_RECORD_FMT)   # 48


class ParseError(ValueError):
    """NetFlow 패킷 파싱 실패."""


def parse_netflow_v5(data: bytes) -> list[FlowRecord]:
    """NetFlow v5 UDP 페이로드를 파싱하여 FlowRecord 리스트로 반환한다.

    Args:
        data: 수신된 UDP 페이로드 (raw bytes).

    Returns:
        파싱된 FlowRecord 리스트. 빈 패킷이면 빈 리스트.

    Raises:
        ParseError: 버전 불일치 또는 데이터가 너무 짧은 경우.
    """
    if len(data) < _V5_HEADER_SIZE:
        raise ParseError(
            f"Packet too short: {len(data)} bytes (minimum {_V5_HEADER_SIZE})"
        )

    (
        version, count, sys_uptime, unix_secs,
        unix_nsecs, flow_seq, engine_type, engine_id, sampling,
    ) = struct.unpack_from(_V5_HEADER_FMT, data, 0)

    if version != 5:
        raise ParseError(f"Expected NetFlow v5, got version={version}")

    if count == 0:
        return []

    expected_size = _V5_HEADER_SIZE + count * _V5_RECORD_SIZE
    if len(data) < expected_size:
        raise ParseError(
            f"Packet truncated: expected {expected_size} bytes for {count} records, "
            f"got {len(data)}"
        )

    flows: list[FlowRecord] = []
    offset = _V5_HEADER_SIZE

    for _ in range(count):
        (
            srcaddr, dstaddr, nexthop,
            input_iface, output_iface,
            dpkts, doctets,
            first_ms, last_ms,
            srcport, dstport,
            pad1, tcp_flags, prot, tos,
            src_as, dst_as,
            src_mask, dst_mask, pad2,
        ) = struct.unpack_from(_V5_RECORD_FMT, data, offset)
        offset += _V5_RECORD_SIZE

        flows.append(FlowRecord(
            src_ip          = socket.inet_ntoa(srcaddr),
            dst_ip          = socket.inet_ntoa(dstaddr),
            src_port        = srcport,
            dst_port        = dstport,
            protocol        = Protocol.from_int(prot),
            bytes_count     = doctets,
            packets_count   = dpkts,
            start_uptime_ms = first_ms,
            end_uptime_ms   = last_ms,
            tcp_flags       = tcp_flags,
            tos             = tos,
            src_as          = src_as,
            dst_as          = dst_as,
            input_iface     = input_iface,
            output_iface    = output_iface,
        ))

    return flows


def parse_netflow(data: bytes) -> list[FlowRecord]:
    """NetFlow 버전을 자동 감지하여 파싱한다.

    현재 v5만 지원. v9/IPFIX는 TODO.

    Args:
        data: 수신된 UDP 페이로드.

    Returns:
        FlowRecord 리스트. 지원하지 않는 버전이면 빈 리스트.
    """
    if len(data) < 2:
        return []

    version = struct.unpack_from("!H", data, 0)[0]

    if version == 5:
        try:
            return parse_netflow_v5(data)
        except ParseError as exc:
            logger.debug("Failed to parse NetFlow v5: %s", exc)
            return []

    # v9/IPFIX: 추후 구현
    # TODO(phase-1.5): v9/IPFIX 지원 추가
    logger.debug("Unsupported NetFlow version: %d (only v5 supported)", version)
    return []
