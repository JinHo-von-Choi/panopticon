"""MAC 스푸핑 탐지: 중복 MAC, 로컬 관리 MAC."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import ARP, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_src_ip

logger = logging.getLogger("netwatcher.detection.engines.mac_spoof")

# 알려진 VM/컨테이너 OUI 접두사 (이들의 로컬 관리 MAC은 정상)
_VM_OUIS = {
    "00:50:56", "00:0c:29",  # VMware
    "08:00:27", "0a:00:27",  # VirtualBox 가상머신
    "00:15:5d",              # Hyper-V 가상머신
    "00:16:3e",              # Xen 가상화
    "52:54:00",              # QEMU/KVM
    "02:42:ac",              # Docker 기본
}


def _is_locally_administered(mac: str) -> bool:
    """MAC에 로컬 관리 비트가 설정되어 있는지 확인한다."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def _is_vm_mac(mac: str) -> bool:
    """MAC이 알려진 VM/컨테이너 벤더에 속하는지 확인한다."""
    prefix = mac[:8].lower()
    return prefix in _VM_OUIS


class MACSpoofEngine(DetectionEngine):
    """MAC 주소 스푸핑 지표를 탐지한다.

    - 동일 MAC에서 동시에 다수의 IP 사용 (MAC 클로닝)
    - 비VM 출처의 로컬 관리 MAC
    """

    name = "mac_spoof"
    description = "MAC 주소 위조를 탐지합니다. OUI 불일치, 랜덤 MAC, 동일 MAC의 다중 IP 사용 등 스푸핑 징후를 식별합니다."
    config_schema = {
        "max_ips_per_mac": {
            "type": int, "default": 5, "min": 2, "max": 50,
            "label": "MAC당 최대 IP 수",
            "description": "단일 MAC 주소에서 윈도우 내 사용된 고유 IP 수가 이 값을 초과하면 MAC 스푸핑 의심. "
                           "DHCP 환경에서는 IP 변경이 정상이므로 적절히 조정.",
        },
        "ip_window_seconds": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "IP 추적 윈도우(초)",
            "description": "MAC-IP 바인딩을 추적하는 시간 윈도우. 기본값 5분.",
        },
        "max_tracked_macs": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 MAC 수",
            "description": "메모리에 유지하는 MAC 추적 테이블 크기.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진 설정을 초기화하고 MAC-IP 추적 상태를 구성한다."""
        super().__init__(config)
        self._max_ips_per_mac = config.get("max_ips_per_mac", 5)
        self._ip_window = config.get("ip_window_seconds", 300)

        # MAC -> (timestamp, ip) deque
        self._mac_ips: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._multi_ip_alerted: dict[str, float] = {}
        self._local_admin_alerted: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷에서 로컬 관리 MAC 및 MAC-IP 바인딩 이상을 분석한다."""
        src_mac = getattr(packet, "src", None)
        if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff":
            return None

        src_ip = get_src_ip(packet)
        if not src_ip and packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

        if not src_ip or src_ip == "0.0.0.0":
            return None

        now = time.time()
        self._mac_ips[src_mac].append((now, src_ip))

        # 비VM 출처의 로컬 관리 MAC 탐지
        if (
            _is_locally_administered(src_mac)
            and not _is_vm_mac(src_mac)
            and src_mac not in self._local_admin_alerted
        ):
            self._local_admin_alerted.add(src_mac)
            return Alert(
                engine=self.name,
                severity=Severity.INFO,
                title="Locally Administered MAC Detected",
                description=(
                    f"MAC {src_mac} (IP: {src_ip}) has locally administered bit "
                    "set but is not from a known VM/container vendor. "
                    "This may indicate MAC spoofing."
                ),
                source_ip=src_ip,
                source_mac=src_mac,
                confidence=0.4,
                metadata={"mac": src_mac, "ip": src_ip},
            )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 MAC당 고유 IP 수를 검사하여 MAC 클로닝 의심 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._ip_window

        keys_to_delete = []
        for mac, entries in self._mac_ips.items():
            # 오래된 항목 제거
            while entries and entries[0][0] < cutoff:
                entries.popleft()

            if not entries:
                keys_to_delete.append(mac)
                continue

            # 이 MAC의 고유 IP 수 계산
            unique_ips = set(ip for _, ip in entries)
            last_alert = self._multi_ip_alerted.get(mac, 0)

            if (
                len(unique_ips) > self._max_ips_per_mac
                and now - last_alert > self._ip_window
            ):
                self._multi_ip_alerted[mac] = now
                confidence = min(1.0, 0.5 + (len(unique_ips) - self._max_ips_per_mac) * 0.1)
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Possible MAC Cloning",
                    description=(
                        f"MAC {mac} is associated with {len(unique_ips)} "
                        f"unique IPs in {self._ip_window}s: "
                        f"{sorted(unique_ips)[:10]}. "
                        "This may indicate MAC address cloning."
                    ),
                    source_mac=mac,
                    confidence=confidence,
                    metadata={
                        "mac": mac,
                        "unique_ips": sorted(unique_ips),
                        "count": len(unique_ips),
                        "window_seconds": self._ip_window,
                    },
                ))

        for key in keys_to_delete:
            del self._mac_ips[key]

        # 만료된 쿨다운 제거
        expired = [k for k, v in self._multi_ip_alerted.items() if now - v > self._ip_window * 2]
        for k in expired:
            del self._multi_ip_alerted[k]

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 상태를 초기화한다."""
        self._mac_ips.clear()
        self._multi_ip_alerted.clear()
        self._local_admin_alerted.clear()
