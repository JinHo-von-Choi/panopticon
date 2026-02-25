"""트래픽 이상 탐지: 볼륨 급증, 새 장치, Welford 기반 통계."""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from typing import Any

from scapy.all import ARP, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_src_ip

logger = logging.getLogger("netwatcher.detection.engines.traffic_anomaly")

# 이상 탐지 활성화 전 최소 틱 수 (워밍업 기간)
_DEFAULT_WARMUP_TICKS = 30


class _WelfordStats:
    """실행 중 평균과 분산을 계산하는 Welford 온라인 알고리즘."""

    __slots__ = ("count", "mean", "m2")

    def __init__(self) -> None:
        """Welford 통계를 초기화한다."""
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, value: float) -> None:
        """새 값을 반영하여 이동 평균 및 분산을 갱신한다."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """표본 분산을 반환한다."""
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        """표본 표준편차를 반환한다."""
        return math.sqrt(self.variance)


class TrafficAnomalyEngine(DetectionEngine):
    """트래픽 볼륨 이상 및 네트워크의 새 장치를 탐지한다.

    - 호스트가 기준선보다 크게 많은 트래픽을 송/수신할 때 알림
    - 이전에 관측되지 않은 MAC 주소가 나타날 때 알림
    - 워밍업 후 Welford 알고리즘으로 온라인 평균+분산 추적
    - 워밍업 기간 중 EMA-배율 방식으로 폴백
    """

    name = "traffic_anomaly"
    description = "트래픽 볼륨의 통계적 이상을 탐지합니다. 기준선 대비 급격한 트래픽 증감으로 DDoS, 데이터 유출 등을 식별합니다."
    config_schema = {
        "volume_threshold_multiplier": {
            "type": float, "default": 3.0, "min": 1.5, "max": 20.0,
            "label": "볼륨 임계 배율",
            "description": "호스트 트래픽이 기준선(평균) 대비 이 배율을 초과하면 알림 발생. "
                           "3.0 = 평균의 3배. 낮추면 민감도 증가, 높이면 극단적 이상만 탐지.",
        },
        "min_baseline_bytes": {
            "type": int, "default": 1000, "min": 100, "max": 1000000,
            "label": "최소 기준선(bytes)",
            "description": "기준선이 이 값 이상인 호스트만 볼륨 이상 탐지 대상. "
                           "너무 낮으면 트래픽이 거의 없는 호스트에서 오탐 발생.",
        },
        "warmup_ticks": {
            "type": int, "default": 30, "min": 5, "max": 600,
            "label": "워밍업 틱 수",
            "description": "이상 탐지가 활성화되기까지 필요한 틱(초) 수. "
                           "기준선 학습에 충분한 시간 확보. 짧으면 부정확한 기준선으로 오탐 발생.",
        },
        "z_score_threshold": {
            "type": float, "default": 3.0, "min": 1.0, "max": 10.0,
            "label": "Z-Score 임계값",
            "description": "Welford 알고리즘 기반 Z-Score가 이 값을 초과하면 이상 탐지. "
                           "3.0 = 표준편차 3배 이상 편차. 통계적 이상치 탐지 기준.",
        },
        "host_eviction_seconds": {
            "type": int, "default": 86400, "min": 3600, "max": 604800,
            "label": "호스트 제거 시간(초)",
            "description": "이 시간 동안 관측되지 않은 호스트를 추적 테이블에서 제거. "
                           "기본값 24시간. 메모리 관리용.",
        },
        "max_tracked_hosts": {
            "type": int, "default": 50000, "min": 100, "max": 1000000,
            "label": "최대 추적 호스트 수",
            "description": "메모리에 유지하는 호스트 통계 테이블 크기.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """트래픽 이상 탐지 엔진을 초기화한다. 볼륨 배율, 워밍업 틱 등을 설정한다."""
        super().__init__(config)
        self._volume_multiplier = config.get("volume_threshold_multiplier", 3.0)
        self._min_baseline_bytes = config.get("min_baseline_bytes", 1000)
        self._warmup_ticks = config.get("warmup_ticks", _DEFAULT_WARMUP_TICKS)
        self._z_score_threshold = config.get("z_score_threshold", 3.0)
        self._host_eviction_seconds = config.get("host_eviction_seconds", 86400)

        # 알려진 MAC 주소 (시간이 지남에 따라 학습)
        self._known_macs: set[str] = set()
        self._new_mac_alerted: set[str] = set()

        # 볼륨 이상 탐지용 호스트별 바이트 수
        self._host_bytes: dict[str, int] = defaultdict(int)
        # 호스트별 Welford 통계 (워밍업 후 단순 EMA를 대체)
        self._host_stats: dict[str, _WelfordStats] = {}
        # 워밍업 기간용 EMA 기준선
        self._host_avg_bytes: dict[str, float] = {}
        # 호스트별 틱 수 (이 호스트를 관측한 틱 횟수)
        self._host_tick_count: dict[str, int] = defaultdict(int)
        # 제거용 마지막 관측 타임스탬프
        self._host_last_seen: dict[str, float] = {}
        self._mac_last_seen: dict[str, float] = {}
        self._tick_count = 0

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷별 바이트를 추적하고 새 MAC 주소 탐지 시 알림을 생성한다."""
        src_mac = getattr(packet, "src", None)
        if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff":
            return None

        pkt_len = len(packet)
        now = time.time()

        # 출발지별 바이트 추적
        src_ip = get_src_ip(packet)
        if not src_ip and packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

        if src_ip:
            self._host_bytes[src_ip] += pkt_len
            self._host_last_seen[src_ip] = now

        self._mac_last_seen[src_mac] = now

        # 새 장치 탐지
        if src_mac not in self._known_macs:
            self._known_macs.add(src_mac)
            if src_mac not in self._new_mac_alerted:
                self._new_mac_alerted.add(src_mac)
                return Alert(
                    engine=self.name,
                    severity=Severity.INFO,
                    title="New Device Detected",
                    description=(
                        f"New MAC address {src_mac} appeared on the network"
                        + (f" (IP: {src_ip})" if src_ip else "")
                    ),
                    source_ip=src_ip,
                    source_mac=src_mac,
                    metadata={
                        "mac": src_mac,
                        "ip": src_ip,
                        "confidence": 1.0,
                    },
                )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """호스트별 트래픽 볼륨을 기준선과 비교하여 이상 알림을 생성한다."""
        alerts = []
        self._tick_count += 1
        now = time.time()

        for host, byte_count in self._host_bytes.items():
            self._host_tick_count[host] += 1
            host_ticks = self._host_tick_count[host]

            # 필요시 Welford 통계 초기화
            if host not in self._host_stats:
                self._host_stats[host] = _WelfordStats()

            stats = self._host_stats[host]

            if host_ticks > self._warmup_ticks and stats.count >= self._warmup_ticks:
                # 워밍업 후: Z-score 기반 탐지 사용
                if stats.mean >= self._min_baseline_bytes and stats.stddev > 0:
                    z_score = (byte_count - stats.mean) / stats.stddev
                    if z_score > self._z_score_threshold:
                        confidence = min(1.0, 0.5 + (z_score - self._z_score_threshold) * 0.1)
                        alerts.append(Alert(
                            engine=self.name,
                            severity=Severity.WARNING,
                            title="Traffic Volume Anomaly",
                            description=(
                                f"Host {host} sent {byte_count:,} bytes "
                                f"(mean: {stats.mean:,.0f}, stddev: {stats.stddev:,.0f}, "
                                f"z-score: {z_score:.1f})"
                            ),
                            source_ip=host,
                            metadata={
                                "bytes": byte_count,
                                "mean": round(stats.mean, 0),
                                "stddev": round(stats.stddev, 0),
                                "z_score": round(z_score, 2),
                                "ticks_observed": host_ticks,
                                "confidence": round(confidence, 2),
                            },
                        ))
            elif host in self._host_avg_bytes:
                avg = self._host_avg_bytes[host]
                # 워밍업 기간: 배율 기반 탐지 사용
                if (
                    host_ticks > self._warmup_ticks
                    and avg >= self._min_baseline_bytes
                    and byte_count > avg * self._volume_multiplier
                ):
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Traffic Volume Anomaly",
                        description=(
                            f"Host {host} sent {byte_count:,} bytes "
                            f"(baseline avg: {avg:,.0f} bytes, "
                            f"{byte_count / avg:.1f}x normal)"
                        ),
                        source_ip=host,
                        metadata={
                            "bytes": byte_count,
                            "avg_bytes": round(avg, 0),
                            "multiplier": round(byte_count / avg, 2),
                            "ticks_observed": host_ticks,
                            "confidence": 0.5,
                        },
                    ))

            # Welford 통계 업데이트
            stats.update(float(byte_count))

            # EMA 업데이트 (워밍업 중 사용)
            if host in self._host_avg_bytes:
                alpha = 0.3 if host_ticks <= self._warmup_ticks else 0.05
                self._host_avg_bytes[host] = (
                    alpha * byte_count + (1 - alpha) * self._host_avg_bytes[host]
                )
            else:
                self._host_avg_bytes[host] = float(byte_count)

        self._host_bytes.clear()

        # 오래된 호스트 주기적 제거 (60틱마다 ~ 1분)
        if self._tick_count % 60 == 0:
            self._evict_stale(now)

        return alerts

    def _evict_stale(self, now: float) -> None:
        """host_eviction_seconds 동안 관측되지 않은 호스트를 제거한다."""
        cutoff = now - self._host_eviction_seconds
        stale_hosts = [
            h for h, ts in self._host_last_seen.items() if ts < cutoff
        ]
        for host in stale_hosts:
            self._host_last_seen.pop(host, None)
            self._host_stats.pop(host, None)
            self._host_avg_bytes.pop(host, None)
            self._host_tick_count.pop(host, None)

        stale_macs = [
            m for m, ts in self._mac_last_seen.items() if ts < cutoff
        ]
        for mac in stale_macs:
            self._mac_last_seen.pop(mac, None)
            self._known_macs.discard(mac)
            self._new_mac_alerted.discard(mac)

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._host_stats.clear()
        self._host_bytes.clear()
        self._host_avg_bytes.clear()
        self._host_tick_count.clear()
        self._host_last_seen.clear()
        self._mac_last_seen.clear()
        self._known_macs.clear()
        self._new_mac_alerted.clear()
