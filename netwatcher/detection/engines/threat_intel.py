"""위협 인텔리전스 매칭 엔진: IP/도메인 차단 목록."""

from __future__ import annotations

import logging
from typing import Any

from scapy.all import DNS, DNSQR, IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.threat_intel")


class ThreatIntelEngine(DetectionEngine):
    """위협 인텔리전스 피드에 대해 네트워크 트래픽을 매칭한다.

    검사 항목:
    - IP 차단 목록에 대한 목적지 IP 검사
    - 도메인 차단 목록에 대한 DNS 쿼리 검사
    """

    name = "threat_intel"
    requires_span = True
    description = "위협 인텔리전스 피드 기반으로 악성 IP/도메인 통신을 탐지합니다. 알려진 C2 서버, 봇넷, 피싱 사이트 접속을 실시간 차단합니다."
    config_schema = {}

    def __init__(self, config: dict[str, Any]) -> None:
        """위협 인텔리전스 엔진을 초기화한다. 차단 IP/도메인 집합을 빈 상태로 생성한다."""
        super().__init__(config)
        self._blocked_ips: set[str] = set()
        self._blocked_domains: set[str] = set()
        self._feed_manager = None

    def set_feeds(self, feed_manager: Any) -> None:
        """초기화 후 피드 매니저를 주입한다.

        FeedManager의 집합에 대한 실시간 참조를 사용하여
        런타임에 추가/제거된 커스텀 항목이 즉시 반영된다.
        """
        self._feed_manager = feed_manager
        self._blocked_ips = feed_manager._blocked_ips
        self._blocked_domains = feed_manager._blocked_domains
        logger.info(
            "Threat intel loaded: %d IPs, %d domains",
            len(self._blocked_ips), len(self._blocked_domains),
        )

    def _get_feed_name(self, indicator: str, indicator_type: str) -> str | None:
        """지표가 어떤 피드에서 왔는지 조회한다."""
        if self._feed_manager is None:
            return None
        if indicator_type == "ip":
            return self._feed_manager.get_feed_for_ip(indicator)
        elif indicator_type == "domain":
            return self._feed_manager.get_feed_for_domain(indicator)
        return None

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷의 IP와 DNS 쿼리를 위협 인텔리전스 차단 목록과 매칭한다."""
        # 목적지 IP 검사
        src_ip, dst_ip = get_ip_addrs(packet)
        if src_ip and dst_ip:

            if dst_ip in self._blocked_ips:
                if self.is_whitelisted(dest_ip=dst_ip):
                    return None

                # SYN-ACK 패킷은 인바운드 스캔에 대한 서버 응답(TCP 핸드쉐이크)이므로
                # 아웃바운드 연결로 오탐하지 않도록 억제한다.
                # 해당 인바운드 SYN은 src_ip 분기에서 별도 탐지된다.
                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    is_syn_ack = bool(flags & 0x02) and bool(flags & 0x10)
                    if is_syn_ack:
                        return None

                feed_name = self._get_feed_name(dst_ip, "ip")
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Connection to Blocklisted IP",
                    description=(
                        f"Outbound connection to known malicious IP: {dst_ip}"
                        + (f" (feed: {feed_name})" if feed_name else "")
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.95,
                    metadata={
                        "blocklisted_ip": dst_ip,
                        "direction": "outbound",
                        "feed": feed_name,
                    },
                )

            if src_ip in self._blocked_ips:
                if self.is_whitelisted(source_ip=src_ip):
                    return None
                feed_name = self._get_feed_name(src_ip, "ip")

                # TCP 상태 기반 심각도 분류:
                #   SYN-only (스캔/시도) → INFO
                #   연결 성립 (ACK/PSH/데이터) → WARNING
                #   TCP 미포함 (UDP/ICMP 등) → WARNING
                severity = Severity.WARNING
                confidence = 0.7
                tcp_state = "unknown"
                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
                    if is_syn_only:
                        severity = Severity.INFO
                        confidence = 0.3
                        tcp_state = "syn_only"
                    else:
                        tcp_state = "established"

                return Alert(
                    engine=self.name,
                    severity=severity,
                    title="Connection from Blocklisted IP",
                    description=(
                        f"Inbound connection from known malicious IP: {src_ip}"
                        + (f" (feed: {feed_name})" if feed_name else "")
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=confidence,
                    metadata={
                        "blocklisted_ip": src_ip,
                        "direction": "inbound",
                        "feed": feed_name,
                        "tcp_state": tcp_state,
                    },
                )

        # 도메인 차단 목록에 대한 DNS 쿼리 검사
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNS]
            if dns.qr == 0:  # 쿼리
                qname_raw = dns[DNSQR].qname
                if isinstance(qname_raw, bytes):
                    qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
                else:
                    qname = str(qname_raw).rstrip(".")

                # 전체 도메인 및 상위 도메인 검사
                if self.is_whitelisted(domain=qname):
                    return None
                parts = qname.split(".")
                for i in range(len(parts)):
                    check_domain = ".".join(parts[i:])
                    if check_domain in self._blocked_domains:
                        dns_src_ip, _ = get_ip_addrs(packet)
                        feed_name = self._get_feed_name(check_domain, "domain")
                        return Alert(
                            engine=self.name,
                            severity=Severity.CRITICAL,
                            title="DNS Query to Blocklisted Domain",
                            description=(
                                f"DNS query for known malicious domain: {qname}"
                                + (f" (feed: {feed_name})" if feed_name else "")
                            ),
                            source_ip=dns_src_ip,
                            confidence=0.95,
                            metadata={
                                "qname": qname,
                                "matched_domain": check_domain,
                                "feed": feed_name,
                            },
                        )

        return None

    def shutdown(self) -> None:
        """엔진 종료 시 차단 목록을 정리한다."""
        self._blocked_ips.clear()
        self._blocked_domains.clear()
