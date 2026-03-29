"""TLS 터널 탐지기.

TLS 플로우의 패킷 크기 균일성을 분석하여
VPN/터널 트래픽을 탐지한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import math
import time
from collections import deque
from typing import TYPE_CHECKING

from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.detection.engines.tls.engine import TLSFingerprintEngine


class TunnelDetector:
    """패킷 크기 변동계수(CV) 기반 TLS 터널 탐지."""

    def __init__(
        self,
        engine: TLSFingerprintEngine,
        tunnel_min_packets: int,
        tunnel_cv_threshold: float,
        max_tracked_flows: int,
    ) -> None:
        self._engine              = engine
        self._tunnel_min_packets  = tunnel_min_packets
        self._tunnel_cv_threshold = tunnel_cv_threshold
        self._max_tracked_flows   = max_tracked_flows

        # 터널 탐지용 플로우 추적:
        # (src_ip, dst_ip, dst_port) -> (timestamp, pkt_size) deque
        self._flow_stats: dict[
            tuple[str | None, str | None, int], deque[tuple[float, int]]
        ] = {}

    def track_flow(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int,
        pkt_size: int,
    ) -> None:
        """플로우의 패킷 크기를 기록하며 max_tracked_flows 제한을 적용한다.

        플로우 딕셔너리가 ``_max_tracked_flows``를 초과하면 가장 오래된
        마지막 관측 타임스탬프의 플로우를 제거한다.
        """
        key = (src_ip, dst_ip, dst_port)
        now = time.time()

        if key not in self._flow_stats:
            # 용량 초과 시 가장 오래된 플로우 제거
            if len(self._flow_stats) >= self._max_tracked_flows:
                oldest_key = min(
                    self._flow_stats,
                    key=lambda k: self._flow_stats[k][-1][0]
                    if self._flow_stats[k]
                    else float("inf"),
                )
                del self._flow_stats[oldest_key]
            self._flow_stats[key] = deque()

        self._flow_stats[key].append((now, pkt_size))

    def detect_tunnels(self, timestamp: float) -> list[Alert]:
        """패킷 크기 균일성 기반의 터널 유사 플로우 주기적 검사.

        ``tunnel_min_packets`` 이상의 샘플이 있는 플로우에 대해 패킷 크기의
        변동계수(CV = 표준편차 / 평균)를 계산한다. CV가 ``tunnel_cv_threshold``
        미만이면 거의 동일한 패킷 크기를 나타내며, VPN/터널 캡슐화의
        특징이다.
        """
        alerts: list[Alert] = []

        keys_to_delete: list[tuple[str | None, str | None, int]] = []
        for flow_key, samples in self._flow_stats.items():
            if len(samples) < self._tunnel_min_packets:
                continue

            sizes = [s for _, s in samples]
            mean = sum(sizes) / len(sizes)
            if mean <= 0:
                continue

            variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
            stddev = math.sqrt(variance)
            cv = stddev / mean

            if cv < self._tunnel_cv_threshold:
                src_ip, dst_ip, dst_port = flow_key
                if self._engine.is_whitelisted(source_ip=src_ip):
                    continue
                alerts.append(Alert(
                    engine=self._engine.name,
                    severity=Severity.WARNING,
                    title="Suspected Encrypted Tunnel (Uniform Packet Sizes)",
                    description=(
                        f"Flow {src_ip} -> {dst_ip}:{dst_port} shows highly "
                        f"uniform packet sizes (CV={cv:.4f}, "
                        f"packets={len(samples)}), suggesting VPN/tunnel traffic"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.5,
                    metadata={
                        "cv": round(cv, 6),
                        "mean_pkt_size": round(mean, 1),
                        "packet_count": len(samples),
                        "dst_port": dst_port,
                    },
                ))
                # 반복 알림 방지를 위해 알림 후 플로우 초기화
                keys_to_delete.append(flow_key)

        for key in keys_to_delete:
            del self._flow_stats[key]

        return alerts

    def clear(self) -> None:
        """플로우 추적 데이터를 초기화한다."""
        self._flow_stats.clear()
