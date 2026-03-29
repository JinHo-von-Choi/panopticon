"""호스트별 트래픽 통계에서 특징 벡터를 추출하는 모듈.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class _HostAccumulator:
    """단일 호스트의 윈도우 내 트래픽 통계."""

    flow_count:    int            = 0
    byte_count:    int            = 0
    ports:         set[int]       = field(default_factory=set)
    protocol_tcp:  int            = 0
    protocol_udp:  int            = 0
    protocol_other: int           = 0
    packet_sizes:  list[int]      = field(default_factory=list)
    timestamps:    list[float]    = field(default_factory=list)
    first_seen:    float          = 0.0
    last_seen:     float          = 0.0


def _shannon_entropy(values: list[int]) -> float:
    """정수 목록의 섀넌 엔트로피를 계산한다."""
    if not values:
        return 0.0
    total = len(values)
    freq: dict[int, int] = {}
    for v in values:
        freq[v] = freq.get(v, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class FeatureExtractor:
    """호스트별 트래픽 통계에서 특징 벡터를 추출한다.

    각 호스트에 대해 window_seconds 기간 내 수집된 패킷 정보를
    10차원 특징 벡터로 변환한다.
    """

    FEATURE_NAMES = [
        "flow_rate",
        "byte_rate",
        "unique_ports",
        "port_entropy",
        "protocol_ratio_tcp",
        "protocol_ratio_udp",
        "avg_packet_size",
        "iat_mean",
        "iat_std",
        "hour_of_day",
    ]

    def __init__(self, window_seconds: int = 60) -> None:
        """특징 추출기를 초기화한다.

        Args:
            window_seconds: 특징 계산에 사용할 시간 윈도우(초).
        """
        self._window_seconds = window_seconds
        self._hosts: dict[str, _HostAccumulator] = defaultdict(_HostAccumulator)
        self._port_log: dict[str, list[int]] = defaultdict(list)

    def feed_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        port: int,
    ) -> None:
        """패킷 정보를 호스트 통계에 반영한다.

        Args:
            src_ip:   소스 IP 주소.
            dst_ip:   목적지 IP 주소.
            protocol: 프로토콜 문자열 ("tcp", "udp", 등).
            size:     패킷 바이트 크기.
            port:     목적지 포트 번호.
        """
        now = time.time()
        acc = self._hosts[src_ip]

        if acc.first_seen == 0.0:
            acc.first_seen = now
        acc.last_seen = now

        acc.flow_count += 1
        acc.byte_count += size
        acc.ports.add(port)
        acc.packet_sizes.append(size)
        acc.timestamps.append(now)

        proto_lower = protocol.lower()
        if proto_lower == "tcp":
            acc.protocol_tcp += 1
        elif proto_lower == "udp":
            acc.protocol_udp += 1
        else:
            acc.protocol_other += 1

        self._port_log[src_ip].append(port)

    def extract(self, src_ip: str) -> list[float] | None:
        """특정 호스트의 특징 벡터를 추출한다.

        데이터가 충분하지 않으면(2개 미만 패킷) None을 반환한다.

        Args:
            src_ip: 대상 호스트 IP.

        Returns:
            10차원 float 리스트 또는 None.
        """
        acc = self._hosts.get(src_ip)
        if acc is None or acc.flow_count < 2:
            return None

        elapsed = max(acc.last_seen - acc.first_seen, 1.0)

        # flow_rate, byte_rate
        flow_rate = acc.flow_count / elapsed
        byte_rate = acc.byte_count / elapsed

        # unique_ports
        unique_ports = float(len(acc.ports))

        # port_entropy
        port_entropy = _shannon_entropy(self._port_log.get(src_ip, []))

        # protocol_ratio
        total_proto = acc.protocol_tcp + acc.protocol_udp + acc.protocol_other
        ratio_tcp = acc.protocol_tcp / total_proto if total_proto > 0 else 0.0
        ratio_udp = acc.protocol_udp / total_proto if total_proto > 0 else 0.0

        # avg_packet_size
        avg_pkt_size = (
            sum(acc.packet_sizes) / len(acc.packet_sizes)
            if acc.packet_sizes
            else 0.0
        )

        # inter-arrival time (IAT)
        iats: list[float] = []
        sorted_ts = sorted(acc.timestamps)
        for i in range(1, len(sorted_ts)):
            iats.append(sorted_ts[i] - sorted_ts[i - 1])

        iat_mean = sum(iats) / len(iats) if iats else 0.0
        if len(iats) > 1:
            variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
            iat_std = math.sqrt(variance)
        else:
            iat_std = 0.0

        # hour_of_day (UTC)
        hour_of_day = float(datetime.now(timezone.utc).hour)

        return [
            flow_rate,
            byte_rate,
            unique_ports,
            port_entropy,
            ratio_tcp,
            ratio_udp,
            avg_pkt_size,
            iat_mean,
            iat_std,
            hour_of_day,
        ]

    def extract_all(self) -> dict[str, list[float]]:
        """모든 추적 호스트의 특징 벡터를 추출한다.

        Returns:
            호스트 IP -> 특징 벡터 매핑 딕셔너리. 데이터 부족 호스트는 제외.
        """
        result: dict[str, list[float]] = {}
        for ip in list(self._hosts.keys()):
            features = self.extract(ip)
            if features is not None:
                result[ip] = features
        return result

    def reset(self) -> None:
        """모든 누적 데이터를 초기화한다."""
        self._hosts.clear()
        self._port_log.clear()
