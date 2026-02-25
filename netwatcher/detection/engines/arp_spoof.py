"""ARP 스푸핑 탐지 엔진."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import ARP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.arp_spoof")


class ARPSpoofEngine(DetectionEngine):
    """MAC-IP 바인딩 추적을 통해 ARP 스푸핑을 탐지한다.

    트리거 조건:
    - 알려진 IP가 갑자기 다른 MAC으로 나타남 (ARP 캐시 포이즈닝)
    - Gratuitous ARP 응답 폭주 탐지 (슬라이딩 윈도우)
    """

    name = "arp_spoof"
    description = "ARP 스푸핑 및 Gratuitous ARP 폭주를 탐지합니다. MAC-IP 매핑 변경을 감시하여 중간자 공격(MITM)을 식별합니다."
    config_schema = {
        "gratuitous_window_seconds": {
            "type": int, "default": 30, "min": 5, "max": 300,
            "label": "Gratuitous ARP 윈도우(초)",
            "description": "Gratuitous ARP 패킷을 집계하는 슬라이딩 윈도우 길이. "
                           "짧게 설정하면 짧은 버스트만 탐지, 길게 설정하면 느린 스푸핑도 탐지.",
        },
        "gratuitous_threshold": {
            "type": int, "default": 10, "min": 2, "max": 100,
            "label": "Gratuitous ARP 임계값",
            "description": "윈도우 내 Gratuitous ARP 수가 이 값을 초과하면 알림 발생. "
                           "낮추면 민감도 증가(오탐 가능), 높이면 민감도 감소.",
        },
        "cooldown_seconds": {
            "type": int, "default": 300, "min": 10, "max": 3600,
            "label": "재알림 쿨다운(초)",
            "description": "동일 호스트에 대해 알림 재발송까지 대기하는 시간. "
                           "너무 짧으면 알림 폭주, 너무 길면 지속적 공격 누락 가능.",
        },
        "max_tracked_hosts": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 호스트 수",
            "description": "메모리에 유지하는 ARP 테이블 최대 크기. "
                           "네트워크 규모에 맞게 조정. 초과 시 오래된 엔트리부터 제거.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """ARP 스푸핑 엔진을 초기화한다. Gratuitous ARP 윈도우/임계값 등을 설정한다."""
        super().__init__(config)
        self._gratuitous_window = config.get("gratuitous_window_seconds", 30)
        self._gratuitous_threshold = config.get("gratuitous_threshold", 10)
        self._cooldown_seconds = config.get("cooldown_seconds", 300)
        self._max_tracked_hosts = config.get("max_tracked_hosts", 10000)

        # ARP 트래픽에서 학습한 MAC -> IP 바인딩 테이블
        self._arp_table: dict[str, str] = {}
        # 역방향 조회용 IP -> MAC
        self._ip_to_mac: dict[str, str] = {}
        # 출발지 MAC별 Gratuitous ARP 타임스탬프 추적: deque of timestamps
        self._gratuitous_timestamps: dict[str, deque[float]] = defaultdict(deque)
        # 쿨다운: MAC -> 마지막 알림 타임스탬프 (재알림 방지)
        self._gratuitous_cooldown: dict[str, float] = {}
        # 제거용 IP -> 마지막 관측 타임스탬프
        self._ip_last_seen: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """ARP 패킷에서 IP-MAC 바인딩 변경 및 Gratuitous ARP 폭주를 탐지한다."""
        if not packet.haslayer(ARP):
            return None

        arp = packet[ARP]

        # ARP 응답(op=2)과 요청(op=1)만 처리
        if arp.op not in (1, 2):
            return None

        src_mac = arp.hwsrc
        src_ip = arp.psrc

        if not src_mac or not src_ip or src_ip == "0.0.0.0":
            return None

        # IP 충돌 검사: 동일 IP, 다른 MAC
        if src_ip in self._ip_to_mac:
            known_mac = self._ip_to_mac[src_ip]
            if known_mac != src_mac:
                alert = Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="ARP Spoofing Detected",
                    description=(
                        f"IP {src_ip} was associated with MAC {known_mac}, "
                        f"but now claims to be MAC {src_mac}. "
                        "Possible ARP cache poisoning attack."
                    ),
                    source_ip=src_ip,
                    source_mac=src_mac,
                    metadata={
                        "original_mac": known_mac,
                        "new_mac": src_mac,
                        "arp_op": arp.op,
                        "confidence": 0.9,
                    },
                )
                # 테이블 업데이트 (공격자가 새로운 정상 장치일 수 있음)
                self._ip_to_mac[src_ip] = src_mac
                self._arp_table[src_mac] = src_ip
                return alert

        # 최대 추적 호스트 수 제한 (가득 차면 가장 오래된 항목 제거)
        if len(self._ip_to_mac) >= self._max_tracked_hosts and src_ip not in self._ip_to_mac:
            oldest_ip = min(self._ip_last_seen, key=self._ip_last_seen.get)  # type: ignore[arg-type]
            old_mac = self._ip_to_mac.pop(oldest_ip, None)
            if old_mac:
                self._arp_table.pop(old_mac, None)
            self._ip_last_seen.pop(oldest_ip, None)

        # 바인딩 학습
        self._ip_to_mac[src_ip] = src_mac
        self._arp_table[src_mac] = src_ip
        self._ip_last_seen[src_ip] = time.time()

        # Gratuitous ARP 폭주 탐지 (ARP 응답에서 src_ip == dst_ip)
        if arp.op == 2 and arp.psrc == arp.pdst:
            now = time.time()
            timestamps = self._gratuitous_timestamps[src_mac]
            timestamps.append(now)

            # 슬라이딩 윈도우 밖의 항목 제거
            cutoff = now - self._gratuitous_window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            # 재알림 방지를 위한 쿨다운과 함께 임계값 검사
            if len(timestamps) >= self._gratuitous_threshold:
                last_alert_time = self._gratuitous_cooldown.get(src_mac, 0)
                if now - last_alert_time > self._cooldown_seconds:
                    self._gratuitous_cooldown[src_mac] = now
                    return Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Gratuitous ARP Flood",
                        description=(
                            f"MAC {src_mac} (IP {src_ip}) sent "
                            f"{len(timestamps)}+ gratuitous ARP replies "
                            f"in {self._gratuitous_window}s. "
                            "This may indicate ARP spoofing preparation."
                        ),
                        source_ip=src_ip,
                        source_mac=src_mac,
                        metadata={
                            "count": len(timestamps),
                            "window_seconds": self._gratuitous_window,
                            "confidence": 0.6,
                        },
                    )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """오래된 Gratuitous ARP 추적 항목과 쿨다운을 정리한다."""
        # 오래된 Gratuitous 추적 항목 제거
        now = time.time()
        cutoff = now - self._gratuitous_window
        keys_to_delete = []
        for mac, timestamps in self._gratuitous_timestamps.items():
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            if not timestamps:
                keys_to_delete.append(mac)
        for key in keys_to_delete:
            del self._gratuitous_timestamps[key]

        # 만료된 쿨다운 제거
        expired = [
            mac for mac, ts in self._gratuitous_cooldown.items()
            if now - ts > self._cooldown_seconds
        ]
        for mac in expired:
            del self._gratuitous_cooldown[mac]

        return []

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._arp_table.clear()
        self._ip_to_mac.clear()
        self._gratuitous_timestamps.clear()
        self._gratuitous_cooldown.clear()
        self._ip_last_seen.clear()
