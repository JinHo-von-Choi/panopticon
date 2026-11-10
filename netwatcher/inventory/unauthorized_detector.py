"""비인가 디바이스 탐지 모듈.

인가 목록(MAC/IP/서브넷)에 없는 디바이스를 탐지한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

logger = logging.getLogger("netwatcher.inventory.unauthorized_detector")


class UnauthorizedDetector:
    """인가되지 않은 디바이스를 탐지한다.

    정책(authorized MACs, IPs, subnets)을 로드하고,
    관찰된 MAC/IP 조합을 검사하여 위반 여부를 판정한다.
    """

    def __init__(self) -> None:
        self._authorized_macs:    set[str] = set()
        self._authorized_ips:     set[str] = set()
        self._authorized_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._enabled: bool = False

    def load_policy(self, config: dict[str, Any]) -> None:
        """설정 dict에서 인가 디바이스 목록을 로드한다.

        config 형식 예시:
            {
                "enabled": true,
                "authorized_macs": ["aa:bb:cc:dd:ee:01", ...],
                "authorized_ips": ["192.168.1.100", ...],
                "authorized_subnets": ["192.168.1.0/24", ...]
            }
        """
        self._enabled = bool(config.get("enabled", False))

        raw_macs = config.get("authorized_macs", [])
        self._authorized_macs = {m.lower().strip() for m in raw_macs if m}

        raw_ips = config.get("authorized_ips", [])
        self._authorized_ips = {ip.strip() for ip in raw_ips if ip}

        raw_subnets = config.get("authorized_subnets", [])
        self._authorized_subnets = []
        for s in raw_subnets:
            try:
                self._authorized_subnets.append(ipaddress.ip_network(s, strict=False))
            except (ValueError, TypeError):
                logger.warning("무효한 서브넷 무시: %s", s)

        logger.info(
            "비인가 탐지 정책 로드: enabled=%s, MACs=%d, IPs=%d, subnets=%d",
            self._enabled,
            len(self._authorized_macs),
            len(self._authorized_ips),
            len(self._authorized_subnets),
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _ip_allowed(self, ip_str: str) -> bool:
        """주소 목록이 없거나 관측 주소가 없으면 주소 차원은 통과시킨다."""
        if not ip_str or (not self._authorized_ips and not self._authorized_subnets):
            return True
        if ip_str in self._authorized_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            return False
        return any(addr in net for net in self._authorized_subnets)

    def check_ip(self, ip: str) -> dict[str, Any] | None:
        """MAC 정보가 없는 관측을 주소 목록만으로 판정한다."""
        ip_str = ip.strip() if ip else ""
        if not self._enabled or self._ip_allowed(ip_str):
            return None
        return {"mac": "", "ip": ip_str, "reason": f"IP {ip_str} 미인가", "timestamp": time.time()}

    def check(self, mac: str, ip: str) -> dict[str, Any] | None:
        """MAC/IP 조합을 검사하여 비인가 시 위반 dict, 인가 시 None 반환.

        정책이 비활성화 상태이면 항상 None 반환.

        Returns:
            None: 인가된 디바이스 또는 정책 비활성화
            dict: {"mac", "ip", "reason", "timestamp"} 위반 정보
        """
        if not self._enabled:
            return None

        mac_lower = mac.lower().strip() if mac else ""
        ip_str    = ip.strip() if ip else ""

        # MAC 인가 확인
        mac_ok = not self._authorized_macs or mac_lower in self._authorized_macs

        ip_ok = self._ip_allowed(ip_str)

        # 인가 목록이 비어 있으면 해당 차원은 통과
        if not self._authorized_macs and not self._authorized_ips and not self._authorized_subnets:
            return None

        if mac_ok and ip_ok:
            return None

        reasons = []
        if not mac_ok:
            reasons.append(f"MAC {mac_lower} 미인가")
        if not ip_ok:
            reasons.append(f"IP {ip_str} 미인가")

        return {
            "mac":       mac_lower,
            "ip":        ip_str,
            "reason":    "; ".join(reasons),
            "timestamp": time.time(),
        }
