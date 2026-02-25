"""안전한 엔티티의 알림 억제를 위한 화이트리스트 시스템."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger("netwatcher.detection.whitelist")


class Whitelist:
    """설정 가능한 화이트리스트에 대해 IP, MAC, 도메인을 검사한다.

    지원 기능:
    - 정확한 IP 일치
    - CIDR 범위 일치 (예: "192.168.1.0/24")
    - 정확한 MAC 일치
    - 정확한 도메인 일치
    - 도메인 접미사 일치 (예: ".local")
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """설정 딕셔너리에서 화이트리스트를 초기화한다."""
        config = config or {}
        self._ips: set[str] = set(config.get("ips", []))
        self._macs: set[str] = {m.lower() for m in config.get("macs", [])}
        self._domains: set[str] = {d.lower() for d in config.get("domains", [])}
        self._domain_suffixes: list[str] = [
            s.lower() for s in config.get("domain_suffixes", [])
        ]

        # CIDR 범위 파싱
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in config.get("ip_ranges", []):
            try:
                self._ip_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR in whitelist: %s", cidr)

        logger.info(
            "Whitelist loaded: %d IPs, %d ranges, %d MACs, %d domains, %d suffixes",
            len(self._ips), len(self._ip_networks),
            len(self._macs), len(self._domains), len(self._domain_suffixes),
        )

    def is_ip_whitelisted(self, ip: str | None) -> bool:
        """IP 주소가 화이트리스트에 등록되어 있는지 확인한다."""
        if not ip:
            return False
        if ip in self._ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for network in self._ip_networks:
                if addr in network:
                    return True
        except ValueError:
            pass
        return False

    def is_mac_whitelisted(self, mac: str | None) -> bool:
        """MAC 주소가 화이트리스트에 등록되어 있는지 확인한다."""
        if not mac:
            return False
        return mac.lower() in self._macs

    def is_domain_whitelisted(self, domain: str | None) -> bool:
        """도메인이 화이트리스트에 등록되어 있는지 확인한다 (정확 일치 또는 접미사 일치)."""
        if not domain:
            return False
        lower = domain.lower()
        if lower in self._domains:
            return True
        for suffix in self._domain_suffixes:
            if lower.endswith(suffix):
                return True
        return False

    def is_whitelisted(
        self,
        source_ip: str | None = None,
        dest_ip: str | None = None,
        source_mac: str | None = None,
        dest_mac: str | None = None,
        domain: str | None = None,
    ) -> bool:
        """제공된 식별자 중 화이트리스트에 등록된 것이 있는지 확인한다."""
        if self.is_ip_whitelisted(source_ip):
            return True
        if self.is_ip_whitelisted(dest_ip):
            return True
        if self.is_mac_whitelisted(source_mac):
            return True
        if self.is_mac_whitelisted(dest_mac):
            return True
        if self.is_domain_whitelisted(domain):
            return True
        return False

    def add_ip(self, ip: str) -> None:
        """IP를 화이트리스트에 동적으로 추가한다."""
        self._ips.add(ip)

    def add_mac(self, mac: str) -> None:
        """MAC을 화이트리스트에 동적으로 추가한다."""
        self._macs.add(mac.lower())

    def add_domain(self, domain: str) -> None:
        """도메인을 화이트리스트에 동적으로 추가한다."""
        self._domains.add(domain.lower())

    def add_ip_range(self, cidr: str) -> None:
        """CIDR 범위를 화이트리스트에 동적으로 추가한다."""
        try:
            self._ip_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("Invalid CIDR: %s", cidr)

    def remove_ip(self, ip: str) -> None:
        """IP를 화이트리스트에서 제거한다."""
        self._ips.discard(ip)

    def remove_mac(self, mac: str) -> None:
        """MAC을 화이트리스트에서 제거한다."""
        self._macs.discard(mac.lower())

    def remove_domain(self, domain: str) -> None:
        """도메인을 화이트리스트에서 제거한다."""
        self._domains.discard(domain.lower())

    def to_dict(self) -> dict[str, Any]:
        """화이트리스트 상태를 직렬화한다."""
        return {
            "ips": sorted(self._ips),
            "ip_ranges": [str(n) for n in self._ip_networks],
            "macs": sorted(self._macs),
            "domains": sorted(self._domains),
            "domain_suffixes": self._domain_suffixes,
        }
