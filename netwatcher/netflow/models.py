"""NetFlow 정규화 모델 — FlowRecord."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Protocol(enum.IntEnum):
    """IANA 프로토콜 번호 (주요 항목)."""
    ICMP  = 1
    TCP   = 6
    UDP   = 17
    OTHER = 0  # 위에 해당하지 않는 모든 경우

    @classmethod
    def from_int(cls, value: int) -> "Protocol":
        """정수에서 Protocol로 변환한다. 알 수 없는 값은 OTHER로 처리한다."""
        try:
            return cls(value)
        except ValueError:
            return cls.OTHER


@dataclass(frozen=True)
class FlowRecord:
    """NetFlow/IPFIX 단일 플로우의 정규화된 표현.

    v5, v9, IPFIX 파서가 모두 이 형식으로 변환하여 FlowProcessor에 전달한다.
    frozen=True로 불변 객체로 만들어 dict 키로도 사용 가능하다.
    """
    src_ip:          str
    dst_ip:          str
    src_port:        int
    dst_port:        int
    protocol:        Protocol
    bytes_count:     int
    packets_count:   int
    start_uptime_ms: int   # 라우터 부팅 후 경과 ms
    end_uptime_ms:   int
    tcp_flags:       int   # TCP 플래그 비트맵 (비-TCP면 0)
    tos:             int
    src_as:          int   # BGP AS 번호 (없으면 0)
    dst_as:          int
    input_iface:     int   # SNMP 인터페이스 인덱스
    output_iface:    int

    @property
    def duration_ms(self) -> int:
        """플로우 지속 시간 (ms)."""
        return max(0, self.end_uptime_ms - self.start_uptime_ms)

    @property
    def is_tcp(self) -> bool:
        return self.protocol == Protocol.TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == Protocol.UDP

    @property
    def is_icmp(self) -> bool:
        return self.protocol == Protocol.ICMP
