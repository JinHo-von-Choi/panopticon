"""DNS 응답 분석: NXDOMAIN 폭주 (DGA 징후), Fast-flux 탐지."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.dns_response")


class DNSResponseEngine(DetectionEngine):
    """DNS 응답 패킷을 분석하여 위협 지표를 탐지한다.

    - NXDOMAIN Burst: 존재하지 않는 도메인 응답 폭주 (DGA 스캐닝 징후)
    - Fast-flux Indicator: 단일 도메인에 대해 짧은 시간 내 다수의 고유 IP 응답
    """

    name = "dns_response"
    description = "DNS 응답을 분석합니다. 존재하지 않는 도메인(NXDOMAIN) 응답 폭주 및 Fast-flux 봇넷 징후를 식별합니다."
    description_key = "engines.dns_response.description"
    config_schema = {
        "nxdomain_threshold": {
            "type": int, "default": 20, "min": 5, "max": 200,
            "label": "NXDOMAIN 임계값",
            "label_key": "engines.dns_response.nxdomain_threshold.label",
            "description": "윈도우 내 NXDOMAIN 응답 수가 이 값을 초과하면 DGA 활동 의심.",
            "description_key": "engines.dns_response.nxdomain_threshold.description",
        },
        "fastflux_threshold": {
            "type": int, "default": 10, "min": 3, "max": 50,
            "label": "Fast-flux IP 임계값",
            "label_key": "engines.dns_response.fastflux_threshold.label",
            "description": "단일 도메인에 대해 윈도우 내 반환된 고유 IP 수가 이 값을 초과하면 Fast-flux 의심.",
            "description_key": "engines.dns_response.fastflux_threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "탐지 윈도우(초)",
            "label_key": "engines.dns_response.window_seconds.label",
            "description": "DNS 응답 활동을 집계하는 시간 윈도우.",
            "description_key": "engines.dns_response.window_seconds.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화하고 응답 추적 상태를 구성한다."""
        super().__init__(config)
        self._nx_threshold = config.get("nxdomain_threshold", 20)
        self._ff_threshold = config.get("fastflux_threshold", 10)
        self._window = config.get("window_seconds", 300)

        # src_ip (클라이언트) -> deque of NXDOMAIN timestamps
        self._nx_counts: dict[str, deque[float]] = defaultdict(deque)
        # domain -> deque of (timestamp, resolved_ip)
        self._ff_ips: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """DNS 응답 패킷에서 NXDOMAIN 폭주 및 다중 IP 할당을 분석한다."""
        if not packet.haslayer(DNS) or packet[DNS].qr != 1:  # 응답 패킷만 처리
            return None

        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        rcode = packet[DNS].rcode
        now = time.time()

        # 1. NXDOMAIN (rcode=3) 탐지
        if rcode == 3:
            self._nx_counts[dst_ip].append(now)

        # 2. Fast-flux 탐지 (A 레코드 응답 분석)
        if rcode == 0 and packet.haslayer(DNSRR):
            # 질문 섹션에서 도메인 추출
            try:
                qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            except (IndexError, AttributeError):
                return None

            # 응답 섹션 순회하며 IP 추출
            for i in range(packet[DNS].ancount):
                res = packet.getlayer(DNSRR, i + 1)
                if res and res.type == 1:  # A 레코드
                    res_ip = res.rdata
                    self._ff_ips[qname].append((now, res_ip))

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 응답 통계를 검사하여 NXDOMAIN Burst 및 Fast-flux 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        # NXDOMAIN Burst 검사
        for client_ip, times in list(self._nx_counts.items()):
            while times and times[0] < cutoff:
                times.popleft()
            if len(times) >= self._nx_threshold:
                if now - self._alerted.get(f"{client_ip}:nx", 0) > self._window:
                    self._alerted[f"{client_ip}:nx"] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="DNS NXDOMAIN Burst Detected",
                        title_key="engines.dns_response.alerts.nxdomain_burst.title",
                        description=(
                            f"Client {client_ip} received {len(times)} NXDOMAIN responses "
                            f"in {self._window}s. Often indicates DGA scanning activity."
                        ),
                        description_key="engines.dns_response.alerts.nxdomain_burst.description",
                        source_ip=client_ip,
                        confidence=0.7,
                        metadata={"nx_count": len(times), "window_seconds": self._window},
                    ))

        # Fast-flux 검사
        for domain, entries in list(self._ff_ips.items()):
            while entries and entries[0][0] < cutoff:
                entries.popleft()
            unique_ips = set(ip for _, ip in entries)
            if len(unique_ips) >= self._ff_threshold:
                if now - self._alerted.get(f"ff:{domain}", 0) > self._window:
                    self._alerted[f"ff:{domain}"] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.INFO,
                        title="Possible Fast-flux Domain Detected",
                        title_key="engines.dns_response.alerts.fast_flux.title",
                        description=(
                            f"Domain '{domain}' resolved to {len(unique_ips)} unique IPs "
                            f"in {self._window}s. May indicate a Fast-flux botnet."
                        ),
                        description_key="engines.dns_response.alerts.fast_flux.description",
                        confidence=0.5,
                        metadata={"domain": domain, "ip_count": len(unique_ips), "ips": list(unique_ips)[:10]},
                    ))

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._nx_counts.clear()
        self._ff_ips.clear()
        self._alerted.clear()
