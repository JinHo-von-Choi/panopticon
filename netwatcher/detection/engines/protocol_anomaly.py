"""프로토콜 이상 탐지: TTL 이상, TCP 플래그 이상, IP 스푸핑."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.protocol_anomaly")

# 비정상 TCP 플래그 조합
_ABNORMAL_FLAGS = {
    0x03: "SYN+FIN",           # SYN + FIN 동시 설정
    0x29: "FIN+PSH+URG",      # 크리스마스 트리 (URG+PSH+FIN)
    0x00: "NULL",              # 플래그 없음
    0x23: "SYN+FIN+URG",      # SYN + FIN + URG 동시 설정
    0x27: "SYN+FIN+PSH+URG",  # 모든 공격 플래그
}


class ProtocolAnomalyEngine(DetectionEngine):
    """프로토콜 수준의 이상을 탐지한다.

    - TTL 이상: 알려진 출발지의 갑작스런 TTL 변화 (MITM 가능성)
    - TCP 플래그 이상: 불가능하거나 의심스러운 플래그 조합
    - IP 스푸핑 지표: 예상치 못한 출발지 IP 범위
    """

    name = "protocol_anomaly"
    description = "프로토콜 규격 위반 및 비정상 패킷 구조를 탐지합니다. 잘못된 헤더, 비표준 플래그 조합 등 프로토콜 수준 이상을 식별합니다."
    config_schema = {
        "ttl_change_threshold": {
            "type": int, "default": 10, "min": 1, "max": 128,
            "label": "TTL 변화 임계값",
            "description": "동일 출발지 IP의 TTL 값 변화가 이 값을 초과하면 알림. "
                           "TTL 급변은 경로 변경 또는 중간자 공격(MITM)을 의미할 수 있음.",
        },
        "min_ttl_samples": {
            "type": int, "default": 5, "min": 2, "max": 100,
            "label": "최소 TTL 샘플 수",
            "description": "TTL 이상 탐지 전 수집해야 하는 최소 패킷 수. "
                           "샘플이 적으면 정상적인 TTL 변동도 이상으로 오탐할 수 있음.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """프로토콜 이상 탐지 엔진을 초기화한다. TTL/플래그 관련 임계값을 설정한다."""
        super().__init__(config)
        self._ttl_change_threshold = config.get("ttl_change_threshold", 10)
        self._min_ttl_samples = config.get("min_ttl_samples", 5)

        # src_ip -> 관측된 TTL 목록 (최근 N개 유지)
        self._ttl_history: dict[str, list[int]] = defaultdict(list)
        self._ttl_alerted: dict[str, float] = {}
        self._flag_alerted: set[tuple[str, str, int]] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """TCP 플래그 이상, TTL 이상, IP 스푸핑 지표를 검사한다."""
        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip or not dst_ip:
            return None

        # TTL 분석은 IPv4 전용
        ttl = packet[IP].ttl if packet.haslayer(IP) else None

        # TCP 플래그 이상 탐지
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags_int = int(tcp.flags)

            # 알려진 비정상 플래그 조합 검사
            if flags_int in _ABNORMAL_FLAGS:
                flag_name = _ABNORMAL_FLAGS[flags_int]
                key = (src_ip, dst_ip, flags_int)
                if key not in self._flag_alerted:
                    self._flag_alerted.add(key)
                    return Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title=f"TCP Flag Anomaly: {flag_name}",
                        description=(
                            f"Abnormal TCP flags ({flag_name}, 0x{flags_int:02x}) "
                            f"from {src_ip} to {dst_ip}:{tcp.dport}. "
                            "This may indicate OS fingerprinting or evasion attempt."
                        ),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.75,
                        metadata={
                            "tcp_flags": flags_int,
                            "flag_name": flag_name,
                            "dst_port": tcp.dport,
                        },
                    )

        # TTL 이상 탐지 (IPv4 전용)
        if ttl is None:
            return self._check_spoofed_source(src_ip, dst_ip)

        history = self._ttl_history[src_ip]
        history.append(ttl)
        # 최근 20개 샘플만 유지
        if len(history) > 20:
            history[:] = history[-20:]

        if len(history) >= self._min_ttl_samples:
            # 예상 TTL 계산 (최근 값의 최빈값)
            ttl_counts: dict[int, int] = {}
            for t in history[:-1]:  # exclude current
                ttl_counts[t] = ttl_counts.get(t, 0) + 1
            if ttl_counts:
                expected_ttl = max(ttl_counts, key=ttl_counts.get)
                ttl_diff = abs(ttl - expected_ttl)

                if ttl_diff >= self._ttl_change_threshold:
                    now = time.time()
                    last_alert = self._ttl_alerted.get(src_ip, 0)
                    if now - last_alert > 300:
                        self._ttl_alerted[src_ip] = now
                        confidence = min(1.0, 0.5 + ttl_diff * 0.03)
                        return Alert(
                            engine=self.name,
                            severity=Severity.WARNING,
                            title="TTL Anomaly Detected",
                            description=(
                                f"Source {src_ip} TTL changed from expected "
                                f"{expected_ttl} to {ttl} (diff: {ttl_diff}). "
                                "Sudden TTL changes may indicate MITM or "
                                "route manipulation."
                            ),
                            source_ip=src_ip,
                            confidence=confidence,
                            metadata={
                                "expected_ttl": expected_ttl,
                                "observed_ttl": ttl,
                                "ttl_diff": ttl_diff,
                            },
                        )

        return self._check_spoofed_source(src_ip, dst_ip)

    def _check_spoofed_source(self, src_ip: str, dst_ip: str) -> Alert | None:
        """IP 스푸핑 지표: 예상치 못한 범위의 출발지 IP."""
        try:
            src_addr = ipaddress.ip_address(src_ip)
            # LAN에 존재해서는 안 되는 Bogon/예약 출발지 IP
            if src_addr.is_multicast or src_addr.is_reserved:
                key = (src_ip, dst_ip, 0)
                if key not in self._flag_alerted:
                    self._flag_alerted.add(key)
                    return Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Suspicious Source IP",
                        description=(
                            f"Packet from suspicious source IP {src_ip} "
                            f"(multicast/reserved) to {dst_ip}. "
                            "May indicate IP spoofing."
                        ),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.6,
                        metadata={"reason": "bogon_source"},
                    )
        except ValueError:
            pass
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """오래된 TTL 이력과 플래그 알림 데이터를 주기적으로 정리한다."""
        # 오래된 데이터 주기적 정리
        now = time.time()
        if len(self._ttl_history) > 10000:
            # 최근 항목만 유지
            oldest = sorted(self._ttl_alerted.items(), key=lambda x: x[1])
            for ip, _ in oldest[:len(oldest) // 2]:
                self._ttl_history.pop(ip, None)
                self._ttl_alerted.pop(ip, None)

        if len(self._flag_alerted) > 5000:
            self._flag_alerted.clear()

        return []

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._ttl_history.clear()
        self._ttl_alerted.clear()
        self._flag_alerted.clear()
