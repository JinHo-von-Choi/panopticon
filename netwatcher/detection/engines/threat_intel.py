"""위협 인텔리전스 매칭: IP/도메인 블랙리스트, JA3 핑거프린트."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from scapy.all import DNS, DNSQR, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.threatintel.feed_manager import FeedManager

logger = logging.getLogger("netwatcher.detection.engines.threat_intel")


class ThreatIntelEngine(DetectionEngine):
    """실시간 트래픽을 외부 위협 피드와 대조하여 알려진 위협을 탐지한다.

    - Malicious IP: 알려진 C2, 스패머, 스캐너 IP와 통신 탐지
    - Malicious Domain: 블랙리스트 도메인에 대한 DNS 쿼리 탐지
    """

    name = "threat_intel"
    description = "외부 위협 피드와 실시간 트래픽을 대조합니다. 알려진 악성 IP, 도메인과의 통신을 식별합니다."
    description_key = "engines.threat_intel.description"
    config_schema = {}

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다. 피드 매니저는 외부에서 주입받는다."""
        super().__init__(config)
        self._feed_mgr: FeedManager | None = None

    def set_feeds(self, feed_mgr: FeedManager) -> None:
        """피드 매니저 인스턴스를 주입한다."""
        self._feed_mgr = feed_mgr

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷의 IP 및 도메인을 위협 피드와 대조한다."""
        if not self._feed_mgr or not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 1. IP 매칭 (출발지 및 목적지)
        for ip in (src_ip, dst_ip):
            match = self._feed_mgr.match_ip(ip)
            if match:
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Threat Intelligence IP Match",
                    title_key="engines.threat_intel.alerts.ip_match.title",
                    description=(
                        f"Communication with known malicious IP {ip}. "
                        f"Feed Source: {match.get('source', 'unknown')}. "
                        f"Category: {match.get('category', 'malware')}."
                    ),
                    description_key="engines.threat_intel.alerts.ip_match.description",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=1.0,
                    metadata={
                        "matched_ip": ip,
                        "feed_source": match.get("source"),
                        "category": match.get("category"),
                    },
                )

        # 2. 도메인 매칭 (DNS 쿼리)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            match = self._feed_mgr.match_domain(qname)
            if match:
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Threat Intelligence Domain Match",
                    title_key="engines.threat_intel.alerts.domain_match.title",
                    description=(
                        f"DNS query for known malicious domain '{qname}'. "
                        f"Feed Source: {match.get('source', 'unknown')}."
                    ),
                    description_key="engines.threat_intel.alerts.domain_match.description",
                    source_ip=src_ip,
                    confidence=1.0,
                    metadata={
                        "domain": qname,
                        "feed_source": match.get("source"),
                        "category": match.get("category"),
                    },
                )

        return None
