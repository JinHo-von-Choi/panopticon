"""트래픽 양 이상 탐지: Adaptive EWMA + Seasonal + MAD 기반 통계적 탐지, 신규 장치 탐지.

작성자: 최진호
작성일: 2026-03-13
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from scapy.all import IP, Ether, TCP, UDP, Packet

from netwatcher.detection.context_policy import MAX_FLOWS
from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.eviction import BoundedDefaultDict, LRUSet
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.stats import AdaptiveEWMA, MADDetector, SeasonalBuffer

logger = logging.getLogger("netwatcher.detection.engines.traffic_anomaly")


@dataclass
class _HostTickState:
    """호스트별 현재 틱 내 패킷/바이트 카운터."""
    packets: int = 0
    bytes:   int = 0
    flows: dict = field(default_factory=dict)
    flows_incomplete: bool = False


@dataclass
class _HostStats:
    """호스트별 EWMA + MAD 추적 상태."""
    ewma: AdaptiveEWMA = field(default=None)
    mad:  MADDetector   = field(default=None)
    rejected_ticks: int = 0
    consecutive_rejections: int = 0
    restored: bool = False

    def __post_init__(self) -> None:
        if self.ewma is None:
            self.ewma = AdaptiveEWMA(span=60)
        if self.mad is None:
            self.mad = MADDetector(window_size=100)


class TrafficAnomalyEngine(DetectionEngine):
    """네트워크 트래픽의 통계적 이상 징후를 탐지한다.

    - Per-host Adaptive EWMA: 호스트별 지수 가중 이동 평균으로 트래픽 추세 추적
    - Seasonal Decomposition: 168-슬롯(주간) 계절성 보정
    - MAD Anomaly Detection: Median Absolute Deviation 기반 로버스트 이상 탐지
    - New Device: 네트워크에서 처음 관측된 MAC 주소 (인가되지 않은 장치)

    EWMA z-score 또는 MAD z-score 중 하나라도 임계값을 초과하면 알림을 발생시킨다.
    """

    name = "traffic_anomaly"
    description = "Adaptive EWMA + MAD 기반 호스트별 트래픽 이상 및 신규 장치 탐지."
    description_key = "engines.traffic_anomaly.description"
    engine_type = "cpu"
    mitre_attack_ids = ["T1018", "T1041"]
    config_schema = {
        "warmup_ticks": {
            "type": int, "default": 3, "min": 3, "max": 1000,
            "label": "최소 정상 학습 틱", "description": "볼륨 평가를 시작할 최소 표본 수. 독립 탐지를 면제하지 않는다.",
        },
        "ewma_span": {
            "type": int, "default": 60, "min": 5, "max": 1440,
            "label": "EWMA 스팬(틱 수)",
            "label_key": "engines.traffic_anomaly.ewma_span.label",
            "description": "EWMA 평활화 계수 산출을 위한 스팬. alpha = 2/(span+1).",
            "description_key": "engines.traffic_anomaly.ewma_span.description",
        },
        "z_threshold": {
            "type": float, "default": 3.0, "min": 1.5, "max": 10.0,
            "label": "EWMA Z-score 임계값",
            "label_key": "engines.traffic_anomaly.z_threshold.label",
            "description": "EWMA z-score가 이 값을 초과하면 이상으로 판단.",
            "description_key": "engines.traffic_anomaly.z_threshold.description",
        },
        "mad_threshold": {
            "type": float, "default": 3.5, "min": 1.5, "max": 10.0,
            "label": "MAD Z-score 임계값",
            "label_key": "engines.traffic_anomaly.mad_threshold.label",
            "description": "MAD modified z-score가 이 값을 초과하면 이상으로 판단.",
            "description_key": "engines.traffic_anomaly.mad_threshold.description",
        },
        "max_tracked_hosts": {
            "type": int, "default": 5000, "min": 100, "max": 100_000,
            "label": "최대 추적 호스트 수",
            "label_key": "engines.traffic_anomaly.max_tracked_hosts.label",
            "description": "메모리 제한을 위한 동시 추적 호스트 상한.",
            "description_key": "engines.traffic_anomaly.max_tracked_hosts.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._ewma_span       = config.get("ewma_span", 60)
        self._z_threshold     = config.get("z_threshold", 3.0)
        self._mad_threshold   = config.get("mad_threshold", 3.5)
        self._warmup_ticks    = max(3, min(1000, int(config.get("warmup_ticks", 3))))
        max_hosts             = config.get("max_tracked_hosts", 5000)

        # 호스트별 현재 틱 카운터
        self._tick_counters: BoundedDefaultDict = BoundedDefaultDict(
            _HostTickState, max_keys=max_hosts,
        )

        # 호스트별 통계 추적기
        self._host_stats: BoundedDefaultDict = BoundedDefaultDict(
            lambda: _HostStats(
                ewma=AdaptiveEWMA(span=self._ewma_span),
                mad=MADDetector(window_size=100),
            ),
            max_keys=max_hosts,
        )

        # 전역 계절성 버퍼
        self._seasonal = SeasonalBuffer()

        # 전역 카운터 (하위 호환)
        self._current_packets = 0
        self._current_bytes   = 0

        # 신규 장치 탐지
        self._new_devices_alerted = LRUSet(maxlen=max_hosts)

    def baseline_status(self, src_ip: str) -> dict:
        stats = self._host_stats.get(src_ip)
        count = stats.ewma.count if stats else 0
        state = 'cold_start' if count == 0 else 'learning' if count < self._warmup_ticks else (
            'drift_suspected' if stats.consecutive_rejections >= 5 else
            'restored' if stats.restored else 'sufficient_samples')
        return {'state': state, 'accepted_samples': count, 'required_samples': self._warmup_ticks,
                'rejected_ticks': stats.rejected_ticks if stats else 0,
                'scope': 'host_volume', 'human_verified_normal': False}

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷을 호스트별로 카운팅하고 신규 장치를 탐지한다."""
        self._current_packets += 1
        pkt_len = len(packet)
        self._current_bytes += pkt_len

        # 호스트별 틱 카운터 갱신
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            state  = self._tick_counters[src_ip]
            state.packets += 1
            state.bytes   += pkt_len
            transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None
            if (not packet.haslayer(Ether) or transport is None
                    or getattr(packet, 'capture_time_verified', False) is not True):
                state.flows_incomplete = True
            else:
                ethernet = packet[Ether]
                key = (str(ethernet.src).lower(), str(ethernet.dst).lower(), packet[IP].dst,
                       'tcp' if packet.haslayer(TCP) else 'udp', int(transport.dport))
                sampled_at = float(packet.time)
                if key in state.flows:
                    flow = state.flows[key]
                    flow['bytes'] += pkt_len
                    flow['first_at'] = min(flow['first_at'], sampled_at)
                    flow['last_at'] = max(flow['last_at'], sampled_at)
                elif len(state.flows) >= MAX_FLOWS:
                    state.flows_incomplete = True
                else:
                    state.flows[key] = dict(zip(('source_mac', 'peer_mac', 'peer_ip', 'protocol', 'service_port'), key),
                                            bytes=pkt_len, first_at=sampled_at, last_at=sampled_at)


        # 신규 장치 탐지 (등록된 장치가 아닌 경우)
        src_mac = getattr(packet, "src", None)
        if src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
            if self.whitelist and src_mac not in self._new_devices_alerted:
                if not self.whitelist.is_whitelisted(source_mac=src_mac):
                    self._new_devices_alerted.add(src_mac)
                    src_ip_val = packet[IP].src if packet.haslayer(IP) else None
                    return Alert(
                        engine=self.name,
                        severity=Severity.INFO,
                        title="New Network Device Detected",
                        title_key="engines.traffic_anomaly.alerts.new_device.title",
                        description=(
                            f"A new device with MAC {src_mac} "
                            f"(IP: {src_ip_val or 'unknown'}) "
                            "was observed for the first time on the network."
                        ),
                        description_key="engines.traffic_anomaly.alerts.new_device.description",
                        source_ip=src_ip_val,
                        source_mac=src_mac,
                        confidence=0.5,
                        metadata={"mac": src_mac, "ip": src_ip_val},
                    )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 호스트별 트래픽을 평가하여 통계적 이상을 탐지한다.

        1. 각 활성 호스트의 틱 내 패킷 수 확보
        2. EWMA 및 MAD 갱신
        3. 계절 보정 적용 (준비 시)
        4. z-score 임계값 초과 시 알림 생성
        5. 틱 카운터 리셋
        6. 빈 키 정리
        """
        alerts = []
        now = datetime.now(timezone.utc)
        hour_of_week = now.weekday() * 24 + now.hour

        # 활성 호스트 목록 스냅샷 (반복 중 dict 변경 방지)
        active_hosts = list(self._tick_counters.keys())

        for src_ip in active_hosts:
            tick = self._tick_counters.get(src_ip)
            if tick is None:
                continue

            packets = tick.packets
            if packets == 0:
                continue

            value = float(packets)

            # 계절 보정: 계절 계수로 나누어 비계절화
            seasonal_factor = self._seasonal.get_factor(hour_of_week, min_slot_samples=3,
                                                        min_covered_slots=168)
            adjusted_value = value / seasonal_factor if seasonal_factor > 0.0 else value

            # 이전 기준으로 판정한다. 탐지한 급증을 정상 표본에 넣지 않는다.
            stats = self._host_stats[src_ip]
            ready = stats.ewma.count >= self._warmup_ticks
            # 1 packet/tick 하한은 일정한 표본의 0 분산을 유한하게 평가한다.
            ewma_z = stats.ewma.score(adjusted_value, min_scale=1.0) if ready else 0.0
            mad_z = stats.mad.score(adjusted_value, min_scale=1.0) if ready else 0.0

            # 임계값 판정
            triggered_ewma = abs(ewma_z) > self._z_threshold
            triggered_mad  = abs(mad_z) > self._mad_threshold

            if triggered_ewma or triggered_mad:
                stats.rejected_ticks += 1
                stats.consecutive_rejections += 1
            else:
                stats.ewma.update(adjusted_value)
                stats.mad.update(adjusted_value)
                self._seasonal.update(hour_of_week, value)
                stats.consecutive_rejections = 0

            if triggered_ewma or triggered_mad:
                # 가장 높은 z-score 기준으로 보고
                primary_z = max(abs(ewma_z), abs(mad_z))
                method    = "EWMA" if abs(ewma_z) >= abs(mad_z) else "MAD"
                severity  = (
                    Severity.CRITICAL if primary_z > self._z_threshold * 2
                    else Severity.WARNING
                )
                confidence = min(0.95, 0.5 + primary_z * 0.05)

                alerts.append(Alert(
                    engine=self.name,
                    severity=severity,
                    title="Traffic Volume Anomaly Detected",
                    title_key="engines.traffic_anomaly.alerts.volume.title",
                    description=(
                        f"Traffic anomaly for {src_ip}: {packets} packets "
                        f"({method} z={primary_z:.2f}, "
                        f"EWMA z={ewma_z:.2f}, MAD z={mad_z:.2f})."
                    ),
                    description_key="engines.traffic_anomaly.alerts.volume.description",
                    source_ip=src_ip,
                    confidence=confidence,
                    metadata={
                        "packets": packets,
                        "bytes": tick.bytes,
                        "flows": list(tick.flows.values()),
                        "flows_incomplete": tick.flows_incomplete,
                        "ewma_z_score": round(ewma_z, 2),
                        "mad_z_score": round(mad_z, 2),
                        "method": method,
                        "seasonal_factor": round(seasonal_factor, 3),
                        "ewma_mean": round(stats.ewma.mean, 1),
                        "baseline": self.baseline_status(src_ip),
                        "baseline_updated": False,
                        "seasonal_status": 'sufficient_samples' if (
                            all(self._seasonal._counts) and self._seasonal._counts[hour_of_week] >= 3
                        ) else 'unknown',
                    },
                ))

        # 글로벌 카운터 리셋
        self._current_packets = 0
        self._current_bytes   = 0

        # 틱 카운터 전체 리셋
        self._tick_counters.clear()

        return alerts

    def export_state(self) -> dict | None:
        """호스트별 EWMA/MAD 통계 및 계절성 상태를 직렬화한다."""
        host_stats = {}
        for src_ip, stats in self._host_stats.items():
            host_stats[src_ip] = {
                "ewma": {
                    "alpha": stats.ewma._alpha,
                    "mu": stats.ewma._mu,
                    "sigma": stats.ewma._sigma,
                    "count": stats.ewma._count,
                },
                "mad_window": list(stats.mad._window),
                "rejected_ticks": stats.rejected_ticks,
                "consecutive_rejections": stats.consecutive_rejections,
            }

        return {
            "host_stats": host_stats,
            "seasonal": {
                "sums": list(self._seasonal._sums),
                "counts": list(self._seasonal._counts),
                "total_updates": self._seasonal._total_updates,
            },
            "new_devices_alerted": list(self._new_devices_alerted),
        }

    def import_state(self, state: dict) -> None:
        """이전에 내보낸 트래픽 이상 탐지 상태를 복원한다."""
        for src_ip, data in state.get("host_stats", {}).items():
            stats = self._host_stats[src_ip]
            stats.restored = True
            stats.rejected_ticks = max(0, int(data.get('rejected_ticks', 0)))
            stats.consecutive_rejections = max(0, int(data.get('consecutive_rejections', 0)))
            ewma_data = data.get("ewma", {})
            stats.ewma._alpha = float(ewma_data.get("alpha", stats.ewma._alpha))
            stats.ewma._mu = float(ewma_data.get("mu", 0.0))
            stats.ewma._sigma = float(ewma_data.get("sigma", 0.0))
            stats.ewma._count = int(ewma_data.get("count", 0))
            mad_window = data.get("mad_window", [])
            stats.mad._window.clear()
            for v in mad_window:
                stats.mad._window.append(float(v))

        seasonal = state.get("seasonal", {})
        if seasonal:
            sums = seasonal.get("sums", [])
            counts = seasonal.get("counts", [])
            if len(sums) == 168:
                self._seasonal._sums = [float(s) for s in sums]
            if len(counts) == 168:
                self._seasonal._counts = [int(c) for c in counts]
            self._seasonal._total_updates = int(seasonal.get("total_updates", 0))

        for mac in state.get("new_devices_alerted", []):
            self._new_devices_alerted.add(mac)

    def shutdown(self) -> None:
        """엔진 상태를 정리한다."""
        self._tick_counters.clear()
        self._host_stats.clear()
        self._seasonal = SeasonalBuffer()
        self._new_devices_alerted.clear()
        self._current_packets = 0
        self._current_bytes   = 0
