"""패킷 검사 유틸리티: 프로토콜 추출 및 OS 핑거프린팅."""

from __future__ import annotations

from scapy.all import (
    ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, Packet,
)

try:
    from scapy.all import IPv6
except ImportError:
    IPv6 = None

# 패킷당 캡처할 최대 페이로드 바이트
MAX_PAYLOAD_CAPTURE = 512


def extract_packet_info(packet: Packet) -> dict:
    """저장/표시를 위해 패킷에서 상세 프로토콜 정보를 추출한다."""
    info: dict = {
        "length": len(packet),
        "layers": [],
    }

    # Ethernet 레이어
    if packet.haslayer(Ether):
        info["eth_src"]  = packet[Ether].src
        info["eth_dst"]  = packet[Ether].dst
        info["eth_type"] = hex(packet[Ether].type)
        info["layers"].append("Ethernet")

    # IP 레이어
    if packet.haslayer(IP):
        ip = packet[IP]
        info["ip_src"]   = ip.src
        info["ip_dst"]   = ip.dst
        info["ip_ttl"]   = ip.ttl
        info["ip_proto"] = ip.proto
        info["ip_id"]    = ip.id
        info["ip_flags"] = str(ip.flags)
        info["layers"].append("IP")

    # IPv6 레이어
    if IPv6 is not None and packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        info["ip_src"]  = ipv6.src
        info["ip_dst"]  = ipv6.dst
        info["ip_hlim"] = ipv6.hlim
        info["ip_nh"]   = ipv6.nh
        info["layers"].append("IPv6")

    # TCP 레이어
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info["src_port"]   = tcp.sport
        info["dst_port"]   = tcp.dport
        info["tcp_flags"]  = str(tcp.flags)
        info["tcp_seq"]    = tcp.seq
        info["tcp_ack"]    = tcp.ack
        info["tcp_window"] = tcp.window
        info["layers"].append("TCP")

        # 주요 TCP 플래그 디코딩
        flags = []
        if tcp.flags & 0x01: flags.append("FIN")
        if tcp.flags & 0x02: flags.append("SYN")
        if tcp.flags & 0x04: flags.append("RST")
        if tcp.flags & 0x08: flags.append("PSH")
        if tcp.flags & 0x10: flags.append("ACK")
        if tcp.flags & 0x20: flags.append("URG")
        info["tcp_flags_list"] = flags

    # UDP 레이어
    if packet.haslayer(UDP):
        udp = packet[UDP]
        info["src_port"]   = udp.sport
        info["dst_port"]   = udp.dport
        info["udp_length"] = udp.len
        info["layers"].append("UDP")

    # ICMP 레이어
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        info["icmp_type"] = icmp.type
        info["icmp_code"] = icmp.code
        info["layers"].append("ICMP")

    # ARP 레이어
    if packet.haslayer(ARP):
        arp = packet[ARP]
        info["arp_op"]    = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
        info["arp_hwsrc"] = arp.hwsrc
        info["arp_psrc"]  = arp.psrc
        info["arp_hwdst"] = arp.hwdst
        info["arp_pdst"]  = arp.pdst
        info["layers"].append("ARP")

    # DNS 레이어
    if packet.haslayer(DNS):
        dns = packet[DNS]
        info["dns_qr"]     = "response" if dns.qr else "query"
        info["dns_opcode"] = dns.opcode
        info["layers"].append("DNS")
        if packet.haslayer(DNSQR):
            qname = dns[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            info["dns_qname"] = str(qname).rstrip(".")
            info["dns_qtype"] = dns[DNSQR].qtype
        if dns.ancount and dns.ancount > 0:
            answers = []
            for i in range(min(dns.ancount, 10)):
                try:
                    rr = dns.an[i]
                    answers.append({
                        "rrname": str(getattr(rr, "rrname", b""), "utf-8", "ignore").rstrip(".") if isinstance(getattr(rr, "rrname", ""), bytes) else str(getattr(rr, "rrname", "")),
                        "rdata": str(getattr(rr, "rdata", "")),
                        "ttl": getattr(rr, "ttl", 0),
                    })
                except Exception:
                    break
            info["dns_answers"] = answers

    # Raw 페이로드
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        info["payload_size"] = len(raw_data)

        # UTF-8 텍스트 미리보기 시도
        try:
            text = raw_data[:MAX_PAYLOAD_CAPTURE].decode("utf-8", errors="replace")
            # 텍스트처럼 보이는지 확인 (HTTP 등)
            printable_ratio = sum(1 for c in text if c.isprintable() or c in "\r\n\t") / max(len(text), 1)
            if printable_ratio > 0.7:
                info["payload_text"] = text
        except Exception:
            pass

        # 16진수 덤프 (처음 256바이트)
        info["payload_hex"] = raw_data[:256].hex()

        # HTTP 감지
        if raw_data[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"HTTP"):
            info["layers"].append("HTTP")
            # HTTP 헤더 추출
            try:
                header_end = raw_data.find(b"\r\n\r\n")
                if header_end > 0:
                    headers_raw  = raw_data[:min(header_end, MAX_PAYLOAD_CAPTURE)]
                    headers_text = headers_raw.decode("utf-8", errors="replace")
                    info["http_headers"] = headers_text
                    # 주요 헤더 파싱
                    for line in headers_text.split("\r\n"):
                        lower = line.lower()
                        if lower.startswith("host:"):
                            info["http_host"] = line.split(":", 1)[1].strip()
                        elif lower.startswith("user-agent:"):
                            info["http_user_agent"] = line.split(":", 1)[1].strip()
                        elif lower.startswith("content-type:"):
                            info["http_content_type"] = line.split(":", 1)[1].strip()
                        elif lower.startswith("content-length:"):
                            info["http_content_length"] = line.split(":", 1)[1].strip()

                    # HTTP 바디 미리보기
                    body_start = header_end + 4
                    if body_start < len(raw_data):
                        body = raw_data[body_start:body_start + MAX_PAYLOAD_CAPTURE]
                        try:
                            body_text = body.decode("utf-8", errors="replace")
                            info["http_body_preview"] = body_text
                        except Exception:
                            info["http_body_hex"] = body.hex()
            except Exception:
                pass

    return info


def guess_os(packet: Packet) -> str | None:
    """TCP/IP 필드 기반 기초적 OS 핑거프린팅."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None
    ip     = packet[IP]
    tcp    = packet[TCP]
    ttl    = ip.ttl
    window = tcp.window

    if ttl <= 64:
        if window == 65535 or window == 65228:
            return "macOS/iOS"
        if window == 29200 or window == 5840:
            return "Linux"
        return "Linux/Unix"
    elif ttl <= 128:
        if window == 65535 or window == 8192:
            return "Windows"
        return "Windows"
    return None
