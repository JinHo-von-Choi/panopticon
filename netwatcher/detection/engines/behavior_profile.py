"""다차원 호스트 행위 프로파일링 엔진.

Welford의 온라인 알고리즘으로 호스트별 행위 통계(이동 평균/분산)를 추적하고,
다차원 Z-score 분석으로 갑작스러운 행위 변화를 탐지한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.behavior_profile")


@dataclass
class _WelfordStats:
    """이동 평균 및 분산 계산을 위한 Welford 온라인 알고리즘."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        """새 값을 반영하여 이동 평균 및 분산을 갱신한다."""
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """표본 분산을 반환한다."""
        if self.n < 2:
            return 0.0
        return self.m2 / (self.n - 1)

    @property
    def std_dev(self) -> float:
        """표본 표준편차를 반환한다."""
        return self.variance ** 0.5

    def z_score(self, value: float) -> float:
        """이동 통계에 대한 *value*의 절대 Z-score를 계산한다."""
        if self.n < 2:
            return 0.0
        if self.std_dev < 1e-10:
            # 분산 0인 기준선: 유의미한 편차는 모두 이상으로 표시
            return float("inf") if abs(value - self.mean) > 1e-10 else 0.0
        return abs(value - self.mean) / self.std_dev


@dataclass
class _HostProfile:
    """호스트별 다차원 통계."""

    # 각 행위 차원별 Welford 통계
    bytes_per_tick: _WelfordStats = field(default_factory=_WelfordStats)
    packets_per_tick: _WelfordStats = field(default_factory=_WelfordStats)
    unique_dst_ips: _WelfordStats = field(default_factory=_WelfordStats)
    unique_dst_ports: _WelfordStats = field(default_factory=_WelfordStats)
    avg_pkt_size: _WelfordStats = field(default_factory=_WelfordStats)
    dns_queries_per_tick: _WelfordStats = field(default_factory=_WelfordStats)

    # 현재 틱 누적기 (매 틱 리셋)
    tick_bytes: int = 0
    tick_packets: int = 0
    tick_dst_ips: set[str] = field(default_factory=set)
    tick_dst_ports: set[int] = field(default_factory=set)
    tick_pkt_size_sum: int = 0
    tick_pkt_size_count: int = 0
    tick_dns_count: int = 0

    ticks_seen: int = 0
    last_seen: float = 0.0

    def reset_accumulators(self) -> None:
        """다음 인터벌을 위해 틱별 누적기를 리셋한다."""
        self.tick_bytes = 0
        self.tick_packets = 0
        self.tick_dst_ips = set()
        self.tick_dst_ports = set()
        self.tick_pkt_size_sum = 0
        self.tick_pkt_size_count = 0
        self.tick_dns_count = 0


# 차원 이름 -> (_HostProfile Welford 속성, 누적기 값 추출기) 매핑
_DIMENSIONS: list[tuple[str, str]] = [
    ("bytes_per_tick", "bytes_per_tick"),
    ("packets_per_tick", "packets_per_tick"),
    ("unique_dst_ips", "unique_dst_ips"),
    ("unique_dst_ports", "unique_dst_ports"),
    ("avg_pkt_size", "avg_pkt_size"),
    ("dns_queries_per_tick", "dns_queries_per_tick"),
]


class BehaviorProfileEngine(DetectionEngine):
    """호스트별 행위의 갑작스런 다차원 변화를 탐지한다.

    각 호스트에 대해 틱당 바이트, 패킷, 고유 목적지 IP/포트, 평균 패킷
    크기, DNS 질의 수를 추적한다. 워밍업 기간 이후 모든 차원에 걸친
    Z-score 분석으로 이상을 탐지한다.
    """

    name = "behavior_profile"
    description = "호스트별 행위 프로파일을 구축하여 이상 행동을 탐지합니다. 정상 패턴 대비 비정상적 접속 시간, 프로토콜 변화 등을 식별합니다."
    config_schema = {
        "warmup_ticks": {
            "type": int, "default": 300, "min": 30, "max": 3600,
            "label": "워밍업 틱 수",
            "description": "행위 프로파일링이 활성화되기까지 필요한 틱(초) 수. "
                           "호스트별 정상 행위 기준선 학습에 필요한 시간. "
                           "짧으면 부정확한 프로파일로 오탐 발생.",
        },
        "z_threshold": {
            "type": float, "default": 3.5, "min": 1.0, "max": 10.0,
            "label": "Z-Score 임계값",
            "description": "호스트 행위의 Z-Score가 이 값을 초과하면 이상 행위 알림. "
                           "3.5 = 표준편차 3.5배 이상 편차. 낮추면 민감도 증가.",
        },
        "max_tracked_hosts": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 호스트 수",
            "description": "메모리에 유지하는 행위 프로파일 테이블 크기.",
        },
        "eviction_seconds": {
            "type": int, "default": 86400, "min": 3600, "max": 604800,
            "label": "호스트 제거 시간(초)",
            "description": "이 시간 동안 관측되지 않은 호스트의 프로파일을 제거. 기본값 24시간.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """행위 프로파일링 엔진을 초기화한다. 워밍업 틱, Z-score 임계값 등을 설정한다."""
        super().__init__(config)
        self._warmup_ticks = config.get("warmup_ticks", 300)
        self._z_threshold = config.get("z_threshold", 3.5)
        self._max_tracked_hosts = config.get("max_tracked_hosts", 10000)
        self._eviction_seconds = config.get("eviction_seconds", 86400)

        # max_tracked_hosts 초과 시 LRU 제거를 위한 OrderedDict
        self._profiles: OrderedDict[str, _HostProfile] = OrderedDict()

    # ------------------------------------------------------------------
    # 패킷별 누적 (< 1ms)
    # ------------------------------------------------------------------

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷 정보를 호스트 프로파일의 틱별 누적기에 기록한다."""
        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip:
            return None

        profile = self._get_or_create_profile(src_ip)
        now = time.time()

        pkt_len = len(packet)
        profile.tick_bytes += pkt_len
        profile.tick_packets += 1
        profile.tick_pkt_size_sum += pkt_len
        profile.tick_pkt_size_count += 1
        profile.last_seen = now

        if dst_ip:
            profile.tick_dst_ips.add(dst_ip)

        # TCP/UDP 레이어에서 목적지 포트 추적
        if packet.haslayer(TCP):
            profile.tick_dst_ports.add(packet[TCP].dport)
        elif packet.haslayer(UDP):
            profile.tick_dst_ports.add(packet[UDP].dport)

        # DNS 질의 탐지
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNS]
            if dns.qr == 0:  # 질의, 응답 아님
                profile.tick_dns_count += 1

        # 항상 None 반환; 알림은 on_tick에서 발행
        return None

    # ------------------------------------------------------------------
    # 주기적 분석 (매 틱)
    # ------------------------------------------------------------------

    def on_tick(self, timestamp: float) -> list[Alert]:
        """호스트별 다차원 Z-score를 계산하여 행위 이상 알림을 생성한다."""
        alerts: list[Alert] = []
        now = time.time()
        hosts_to_evict: list[str] = []

        for host_ip, profile in self._profiles.items():
            # 제거 대상 검사
            if profile.last_seen > 0 and (now - profile.last_seen) > self._eviction_seconds:
                hosts_to_evict.append(host_ip)
                continue

            # 이 틱에 활동이 없는 호스트 건너뛰기 (평가할 데이터 없음)
            if profile.tick_packets == 0:
                continue

            # 현재 틱 차원 값 계산
            current_values = self._extract_tick_values(profile)

            # 워밍업 이후: Z-score 계산 및 이상 여부 검사
            if profile.ticks_seen >= self._warmup_ticks:
                anomalous_dims: list[dict[str, Any]] = []
                max_z = 0.0

                for dim_name, welford_attr in _DIMENSIONS:
                    welford: _WelfordStats = getattr(profile, welford_attr)
                    val = current_values[dim_name]
                    z = welford.z_score(val)
                    if z > self._z_threshold:
                        anomalous_dims.append({
                            "dimension": dim_name,
                            "z_score": round(z, 2),
                            "value": round(val, 2),
                            "mean": round(welford.mean, 2),
                            "std_dev": round(welford.std_dev, 2),
                        })
                    if z > max_z:
                        max_z = z

                if anomalous_dims:
                    num_dims = len(anomalous_dims)
                    severity = Severity.CRITICAL if num_dims >= 3 else Severity.WARNING
                    confidence = min(1.0, 0.5 + (max_z - self._z_threshold) * 0.1)
                    dim_names = [d["dimension"] for d in anomalous_dims]

                    alerts.append(Alert(
                        engine=self.name,
                        severity=severity,
                        title="Host Behavior Anomaly",
                        description=(
                            f"Host {host_ip} deviated in {num_dims} dimension(s): "
                            f"{', '.join(dim_names)} "
                            f"(max Z-score: {max_z:.1f})"
                        ),
                        source_ip=host_ip,
                        confidence=confidence,
                        metadata={
                            "anomalous_dimensions": anomalous_dims,
                            "max_z_score": round(max_z, 2),
                            "ticks_observed": profile.ticks_seen,
                            "confidence": round(confidence, 2),
                        },
                    ))

            # 현재 값을 Welford 통계에 반영 (기준선 지속 업데이트를 위해 항상 수행)
            for dim_name, welford_attr in _DIMENSIONS:
                welford: _WelfordStats = getattr(profile, welford_attr)
                welford.update(current_values[dim_name])

            # 누적기 리셋 및 틱 카운트 증가
            profile.reset_accumulators()
            profile.ticks_seen += 1

        # 오래된 호스트 제거
        for host_ip in hosts_to_evict:
            self._profiles.pop(host_ip, None)

        return alerts

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _get_or_create_profile(self, src_ip: str) -> _HostProfile:
        """기존 프로파일을 가져오거나 새로 생성하며 LRU 제거를 적용한다."""
        if src_ip in self._profiles:
            # 끝으로 이동 (가장 최근 사용)
            self._profiles.move_to_end(src_ip)
            return self._profiles[src_ip]

        # 용량 초과 시 가장 오래된 항목 제거
        if len(self._profiles) >= self._max_tracked_hosts:
            self._profiles.popitem(last=False)

        profile = _HostProfile()
        self._profiles[src_ip] = profile
        return profile

    @staticmethod
    def _extract_tick_values(profile: _HostProfile) -> dict[str, float]:
        """누적기에서 현재 틱의 측정 값을 추출한다."""
        avg_size = 0.0
        if profile.tick_pkt_size_count > 0:
            avg_size = profile.tick_pkt_size_sum / profile.tick_pkt_size_count

        return {
            "bytes_per_tick": float(profile.tick_bytes),
            "packets_per_tick": float(profile.tick_packets),
            "unique_dst_ips": float(len(profile.tick_dst_ips)),
            "unique_dst_ports": float(len(profile.tick_dst_ports)),
            "avg_pkt_size": avg_size,
            "dns_queries_per_tick": float(profile.tick_dns_count),
        }

    def shutdown(self) -> None:
        """모든 추적 프로파일을 정리한다."""
        self._profiles.clear()
