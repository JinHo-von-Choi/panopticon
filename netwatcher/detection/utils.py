"""탐지 엔진 공통 유틸리티."""

from __future__ import annotations

import ipaddress

from scapy.all import IP, Packet

try:
    from scapy.all import IPv6
except ImportError:
    IPv6 = None


def get_ip_addrs(packet: Packet) -> tuple[str | None, str | None]:
    """패킷에서 (src_ip, dst_ip) 추출. IPv4/IPv6 모두 지원."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if IPv6 is not None and packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return None, None


def get_src_ip(packet: Packet) -> str | None:
    """패킷에서 src_ip만 추출."""
    src, _ = get_ip_addrs(packet)
    return src


def is_internal(ip_str: str) -> bool:
    """IP가 사설/링크로컬 주소인지 검사. IPv4 + IPv6 지원."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False
