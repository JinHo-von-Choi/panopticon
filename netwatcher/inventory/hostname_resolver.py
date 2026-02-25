"""패킷 스트림에서 호스트명을 패시브로 추출한다.

지원 소스 (우선순위 높은 순):
  1. DHCP option 12  — UDP 67/68    대부분의 OS가 DISCOVER/REQUEST에 포함
  2. NetBIOS/NBNS    — UDP 137      Windows 전 버전
  3. mDNS            — UDP 5353     Apple, Linux(Avahi), 최신 Windows
  4. LLMNR           — UDP 5355     Windows Vista 이상 fallback

모두 패시브 관찰만 수행하며 탐색 패킷을 생성하지 않는다.
"""

from __future__ import annotations

import logging
import struct
from typing import NamedTuple

from scapy.all import BOOTP, DHCP, DNS, DNSRR, IP, UDP, Ether, Packet

logger = logging.getLogger("netwatcher.inventory.hostname_resolver")

# 호스트명 소스 우선순위 (낮은 인덱스가 더 신뢰할 수 있음)
SOURCE_PRIORITY: tuple[str, ...] = ("dhcp", "netbios", "mdns", "llmnr", "reverse_dns")


class HostnameHit(NamedTuple):
    """패킷에서 추출한 호스트명 정보."""

    source: str        # 'dhcp' | 'netbios' | 'mdns' | 'llmnr'
    name: str          # 추출된 호스트명
    mac: str           # 소스 MAC 주소 (소문자, 콜론 구분)
    ip: str | None     # 연관 IP (없으면 None)


def extract(packet: Packet) -> list[HostnameHit]:
    """패킷에서 호스트명 정보를 추출한다. 여러 소스에서 동시에 추출될 수 있다."""
    hits: list[HostnameHit] = []

    hit = _dhcp_hostname(packet)
    if hit:
        hits.append(hit)

    hit = _nbns_hostname(packet)
    if hit:
        hits.append(hit)

    hits.extend(_mdns_hostnames(packet))

    hit = _llmnr_hostname(packet)
    if hit:
        hits.append(hit)

    return hits


def best_name(hostname_sources: dict) -> str | None:
    """hostname_sources dict에서 우선순위에 따라 최적 호스트명을 반환한다."""
    for src in SOURCE_PRIORITY:
        entry = hostname_sources.get(src)
        if entry and entry.get("name"):
            return entry["name"]
    return None


# ---------------------------------------------------------------------------
# 개별 소스 추출 함수
# ---------------------------------------------------------------------------

def _src_mac(packet: Packet) -> str | None:
    """Ethernet 레이어에서 소문자 MAC 주소를 반환한다."""
    if packet.haslayer(Ether):
        return packet[Ether].src.lower()
    return None


def _src_ip(packet: Packet) -> str | None:
    """IP 레이어에서 소스 IP 주소를 반환한다."""
    if packet.haslayer(IP):
        return str(packet[IP].src)
    return None


def _dhcp_hostname(packet: Packet) -> HostnameHit | None:
    """DHCP DISCOVER/REQUEST의 option 12 (hostname)에서 호스트명을 추출한다."""
    if not packet.haslayer(DHCP):
        return None
    mac = _src_mac(packet)
    if not mac:
        return None

    for opt in packet[DHCP].options:
        if not (isinstance(opt, tuple) and opt[0] == "hostname"):
            continue
        raw = opt[1]
        try:
            name = (raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace"))
            name = name.strip("\x00").strip()
        except Exception:
            continue
        if not name:
            continue

        # BOOTP ciaddr: 클라이언트 IP (DISCOVER 시에는 0.0.0.0)
        client_ip: str | None = None
        if packet.haslayer(BOOTP):
            ciaddr = str(packet[BOOTP].ciaddr)
            if ciaddr != "0.0.0.0":
                client_ip = ciaddr
        if client_ip is None:
            client_ip = _src_ip(packet)

        return HostnameHit("dhcp", name, mac, client_ip)

    return None


def _nbns_hostname(packet: Packet) -> HostnameHit | None:
    """NetBIOS Name Service (UDP 137)에서 호스트명을 추출한다.

    Registration(opcode=5) 및 Refresh(opcode=8) 패킷에서
    호스트가 자신의 이름을 네트워크에 등록할 때 추출한다.
    """
    if not (packet.haslayer(UDP) and packet[UDP].dport == 137):
        return None

    mac = _src_mac(packet)
    if not mac:
        return None

    try:
        raw = bytes(packet[UDP].payload)
        if len(raw) < 13:
            return None

        # NBNS 헤더: FLAGS(2바이트), opcode는 bits 14-11
        flags = struct.unpack("!H", raw[2:4])[0]
        opcode = (flags >> 11) & 0xF
        # 5 = NAME REGISTRATION REQUEST, 8 = NAME REFRESH REQUEST
        if opcode not in (5, 8):
            return None

        name = _decode_nbns_name(raw[12:])
        if name:
            return HostnameHit("netbios", name, mac, _src_ip(packet))

    except Exception:
        pass

    return None


def _decode_nbns_name(data: bytes) -> str | None:
    """NetBIOS Level 2 인코딩된 이름을 디코딩한다.

    RFC 1001/1002: 각 문자는 2바이트로 인코딩 (0x41 기반 nibble pair).
    총 32바이트(16문자 × 2)에 앞에 0x20 길이 바이트가 붙는다.
    """
    try:
        if not data or data[0] != 0x20:
            return None
        encoded = data[1:33]
        if len(encoded) < 32:
            return None

        chars = []
        for i in range(0, 32, 2):
            hi = encoded[i] - 0x41
            lo = encoded[i + 1] - 0x41
            if not (0 <= hi <= 15 and 0 <= lo <= 15):
                return None
            chars.append(chr((hi << 4) | lo))

        # 마지막 바이트는 NetBIOS suffix (서비스 타입), 제거
        raw_name = "".join(chars[:-1]).rstrip("\x00").strip()
        return raw_name if raw_name else None

    except Exception:
        return None


def _iter_dns_records(dns: DNS) -> list:
    """dns.an을 안전하게 순회 가능한 리스트로 반환한다.

    Scapy 버전에 따라 dns.an이 단일 DNSRR이거나 리스트일 수 있다.
    """
    an = dns.an
    if an is None:
        return []
    if isinstance(an, list):
        return an
    # 구버전: 단일 DNSRR → payload 체인 순회
    records = []
    rr = an
    while rr and isinstance(rr, DNSRR):
        records.append(rr)
        rr = rr.payload if hasattr(rr, "payload") else None
    return records


def _extract_rr_name(rr: DNSRR) -> str | None:
    """DNSRR에서 호스트명 문자열을 추출한다. .local 접미사를 제거한다."""
    try:
        raw_name = rr.rrname
        name = (
            raw_name if isinstance(raw_name, str)
            else raw_name.decode("utf-8", errors="replace")
        )
        name = name.rstrip(".").strip()
        if name.lower().endswith(".local"):
            name = name[:-6]
        return name if name else None
    except Exception:
        return None


def _mdns_hostnames(packet: Packet) -> list[HostnameHit]:
    """mDNS (UDP 5353) 응답 패킷의 Answer 섹션에서 호스트명을 추출한다.

    A(타입1) 및 AAAA(타입28) 레코드의 rrname을 수집한다.
    """
    hits: list[HostnameHit] = []

    if not (packet.haslayer(UDP) and packet[UDP].dport == 5353):
        return hits
    if not packet.haslayer(DNS):
        return hits

    dns = packet[DNS]
    if dns.qr != 1:  # 응답(QR=1)만 처리
        return hits

    mac = _src_mac(packet)
    if not mac:
        return hits
    ip = _src_ip(packet)

    for rr in _iter_dns_records(dns):
        if not isinstance(rr, DNSRR):
            continue
        if rr.type not in (1, 28):  # A or AAAA
            continue
        name = _extract_rr_name(rr)
        if name:
            hits.append(HostnameHit("mdns", name, mac, ip))

    return hits


def _llmnr_hostname(packet: Packet) -> HostnameHit | None:
    """LLMNR (UDP 5355) 응답에서 호스트명을 추출한다.

    Windows Vista 이상에서 DNS 실패 시 fallback으로 사용한다.
    """
    if not (packet.haslayer(UDP) and packet[UDP].dport == 5355):
        return None
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    if dns.qr != 1:
        return None

    mac = _src_mac(packet)
    if not mac:
        return None

    try:
        for rr in _iter_dns_records(dns):
            if not isinstance(rr, DNSRR):
                continue
            if rr.type not in (1, 28):
                continue
            name = _extract_rr_name(rr)
            if name:
                return HostnameHit("llmnr", name, mac, _src_ip(packet))
    except Exception:
        pass

    return None
