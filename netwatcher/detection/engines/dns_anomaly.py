"""DNS 이상 탐지: DGA 도메인, DNS 터널링, 대량 질의."""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import DNS, DNSQR, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.dns_anomaly")


def _calculate_entropy(text: str) -> float:
    """문자열의 Shannon Entropy를 계산한다 (무작위성 측정)."""
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


class DNSAnomalyEngine(DetectionEngine):
    """DNS 쿼리 패턴의 이상 징후를 탐지한다.

    - DGA (Domain Generation Algorithm): 무작위성이 높은 긴 도메인 이름
    - DNS Tunneling: 비정상적으로 긴 라벨, 깊은 서브도메인 (데이터 인코딩)
    - DNS Flood: 짧은 시간 내 대량의 쿼리 발생
    """

    name = "dns_anomaly"
    description = "DNS 쿼리의 이상을 탐지합니다. 무작위 도메인(DGA), DNS 터널링, 비정상 대량 질의 등을 식별합니다."
    description_key = "engines.dns_anomaly.description"
    config_schema = {
        "entropy_threshold": {
            "type": float, "default": 3.8, "min": 2.0, "max": 5.0,
            "label": "Entropy 임계값",
            "label_key": "engines.dns_anomaly.entropy_threshold.label",
            "description": "도메인 라벨의 무작위성(Entropy)이 이 값을 초과하면 DGA 의심.",
            "description_key": "engines.dns_anomaly.entropy_threshold.description",
        },
        "label_length_threshold": {
            "type": int, "default": 50, "min": 10, "max": 63,
            "label": "최대 라벨 길이",
            "label_key": "engines.dns_anomaly.label_length_threshold.label",
            "description": "DNS 라벨 하나가 이 길이를 초과하면 데이터 인코딩(터널링) 의심.",
            "description_key": "engines.dns_anomaly.label_length_threshold.description",
        },
        "query_rate_threshold": {
            "type": int, "default": 200, "min": 50, "max": 2000,
            "label": "초당 쿼리 임계값",
            "label_key": "engines.dns_anomaly.query_rate_threshold.label",
            "description": "단일 호스트의 초당 DNS 쿼리 수가 이 값을 초과하면 DNS Flood로 판단.",
            "description_key": "engines.dns_anomaly.query_rate_threshold.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화하고 쿼리 추적 상태를 구성한다."""
        super().__init__(config)
        self._entropy_threshold = config.get("entropy_threshold", 3.8)
        self._label_len_threshold = config.get("label_length_threshold", 50)
        self._rate_threshold = config.get("query_rate_threshold", 200)

        # src_ip -> deque of timestamps
        self._query_times: dict[str, deque[float]] = defaultdict(deque)
        self._alerted_domains: set[str] = set()
        self._flood_alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """DNS 쿼리 패킷에서 DGA 및 터널링 징후를 분석한다."""
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        now = time.time()

        # 1. DNS Flood 추적
        self._query_times[src_ip].append(now)

        # 2. DGA & 터널링 검사 (라벨별 분석)
        labels = qname.split(".")
        for label in labels:
            if not label:
                continue

            # 라벨 길이 검사 (터널링 지표)
            if len(label) >= self._label_len_threshold:
                if qname not in self._alerted_domains:
                    self._alerted_domains.add(qname)
                    return Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Potential DNS Tunneling",
                        title_key="engines.dns_anomaly.alerts.tunneling.title",
                        description=(
                            f"Abnormally long DNS label ({len(label)} chars) in '{qname}' from {src_ip}. "
                            "May indicate data exfiltration via DNS."
                        ),
                        description_key="engines.dns_anomaly.alerts.tunneling.description",
                        source_ip=src_ip,
                        confidence=0.7,
                        metadata={"qname": qname, "label_length": len(label), "label": label},
                    )

            # 무작위성 검사 (DGA 지표)
            if len(label) > 10:
                entropy = _calculate_entropy(label)
                if entropy > self._entropy_threshold:
                    if qname not in self._alerted_domains:
                        self._alerted_domains.add(qname)
                        return Alert(
                            engine=self.name,
                            severity=Severity.INFO,
                            title="Potential DGA Domain Detected",
                            title_key="engines.dns_anomaly.alerts.dga.title",
                            description=(
                                f"High entropy ({entropy:.2f}) in DNS label '{label}' ('{qname}'). "
                                "May indicate a Domain Generation Algorithm (malware C2)."
                            ),
                            description_key="engines.dns_anomaly.alerts.dga.description",
                            source_ip=src_ip,
                            confidence=0.5,
                            metadata={"qname": qname, "entropy": round(entropy, 2), "label": label},
                        )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 초당 쿼리 전송률을 검사하여 Flood를 탐지한다."""
        alerts = []
        now = time.time()
        cutoff = now - 1.0  # 1초 윈도우

        for src_ip, times in list(self._query_times.items()):
            while times and times[0] < cutoff:
                times.popleft()

            if not times:
                continue

            if len(times) >= self._rate_threshold:
                last_alert = self._flood_alerted.get(src_ip, 0)
                if now - last_alert > 60:
                    self._flood_alerted[src_ip] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="DNS Query Flood Detected",
                        title_key="engines.dns_anomaly.alerts.flood.title",
                        description=(
                            f"High DNS query rate ({len(times)}/s) from {src_ip}. "
                            "Possible DNS-based DoS or massive data exfiltration."
                        ),
                        description_key="engines.dns_anomaly.alerts.flood.description",
                        source_ip=src_ip,
                        confidence=0.9,
                        metadata={"query_count": len(times)},
                    ))

        # 정리: 오래된 IP 데이터 제거
        if len(self._query_times) > 1000:
            inactive = [ip for ip, times in self._query_times.items() if not times]
            for ip in inactive:
                self._query_times.pop(ip, None)

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._query_times.clear()
        self._alerted_domains.clear()
        self._flood_alerted.clear()
