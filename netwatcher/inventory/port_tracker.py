"""패시브 포트/서비스 탐지 — TCP SYN-ACK 관찰을 통한 개방 포트 추론.

TCP 핸드셰이크에서 SYN-ACK 응답을 관찰하면 서버가 해당 포트를 수신 중임을
확인할 수 있다. 별도의 능동 스캔 없이 일반 트래픽에서 포트 정보를 축적한다.

관찰 원리:
    클라이언트 → 서버: SYN  (dport = 서버 포트)
    서버 → 클라이언트: SYN-ACK  (sport = 서버 포트, 즉 열린 포트)

ephemeral 포트(RFC 6335: 49152~65535)는 클라이언트 임시 포트이므로 제외한다.
"""

from __future__ import annotations

from typing import NamedTuple

from scapy.all import TCP, Packet

# ---------------------------------------------------------------------------
# 서비스 이름 매핑 (well-known + registered 포트)
# ---------------------------------------------------------------------------
_SERVICE_MAP: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    69:    "TFTP",
    80:    "HTTP",
    110:   "POP3",
    119:   "NNTP",
    123:   "NTP",
    143:   "IMAP",
    161:   "SNMP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    514:   "Syslog",
    515:   "LPD",
    587:   "SMTP/TLS",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    1521:  "Oracle",
    1883:  "MQTT",
    2375:  "Docker",
    2376:  "Docker-TLS",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    7001:  "WebLogic",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8883:  "MQTTS",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
}

# RFC 6335 — ephemeral 포트 시작 경계 (이 이상은 클라이언트 임시 포트)
_EPHEMERAL_START = 49152


class PortHit(NamedTuple):
    """패킷에서 감지된 개방 포트 단위."""

    mac:  str
    port: int


def service_name(port: int) -> str:
    """포트 번호에 해당하는 서비스 이름을 반환한다.

    Args:
        port: 포트 번호 (0~65535)

    Returns:
        서비스 이름 문자열. 알 수 없는 포트이면 빈 문자열.
    """
    return _SERVICE_MAP.get(port, "")


def extract(packet: Packet) -> list[PortHit]:
    """패킷에서 개방 포트 정보를 추출한다.

    TCP SYN-ACK(flags & 0x12 == 0x12) 패킷의 source port를 관찰한다.
    ephemeral 포트(>= 49152)는 제외한다.

    Args:
        packet: Scapy 패킷 객체.

    Returns:
        PortHit 리스트. 해당 없으면 빈 리스트.
    """
    if not packet.haslayer(TCP):
        return []

    tcp = packet[TCP]
    # SYN-ACK: SYN(0x02) | ACK(0x10) = 0x12
    if tcp.flags & 0x12 != 0x12:
        return []

    src_mac = getattr(packet, "src", None)
    if not src_mac:
        return []

    port = tcp.sport
    if port >= _EPHEMERAL_START:
        return []

    return [PortHit(mac=src_mac, port=port)]
