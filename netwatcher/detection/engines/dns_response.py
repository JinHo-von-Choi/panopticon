"""DNS 응답 분석: Fast-flux 탐지 및 NXDOMAIN DGA 버스트 탐지."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.engines.dns_anomaly import _is_safe_domain
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.dns_response")


class DNSResponseEngine(DetectionEngine):
    """DNS 응답에서 고급 위협을 분석한다.

    - Fast-flux: 낮은 TTL로 다수의 고유 IP에 해석되는 도메인 탐지.
      봇넷이 감염된 호스트를 순환하는 패턴.
    - NXDOMAIN DGA 버스트: 짧은 시간 내 다수의 NXDOMAIN 응답을 수신하는
      호스트 탐지. DGA 악성코드가 C2 도메인을 탐색하는 징후.
    """

    name = "dns_response"
    description = "DNS 응답의 이상 징후를 분석합니다. DNS 캐시 포이즈닝, 스푸핑된 응답, 비정상 TTL 등을 탐지합니다."
    config_schema = {
        "flux_min_ips": {
            "type": int, "default": 10, "min": 3, "max": 100,
            "label": "Fast-flux 최소 IP 수",
            "description": "단일 도메인에 매핑된 고유 IP 수가 이 값을 초과하면 Fast-flux 의심. "
                           "CDN 도메인도 다수 IP를 사용하므로 화이트리스트와 병행 권장.",
        },
        "flux_max_ttl": {
            "type": int, "default": 300, "min": 10, "max": 3600,
            "label": "Fast-flux 최대 TTL(초)",
            "description": "DNS 응답 TTL이 이 값 이하이면서 다수 IP가 관측되면 Fast-flux로 판정. "
                           "Fast-flux 도메인은 짧은 TTL로 빠르게 IP를 교체함.",
        },
        "flux_window_seconds": {
            "type": int, "default": 3600, "min": 300, "max": 86400,
            "label": "Fast-flux 분석 윈도우(초)",
            "description": "Fast-flux IP 수를 집계하는 시간 윈도우. "
                           "기본값 1시간. 길게 설정하면 느린 flux도 탐지하나 메모리 사용 증가.",
        },
        "nxdomain_threshold": {
            "type": int, "default": 10, "min": 3, "max": 1000,
            "label": "NXDOMAIN 임계값",
            "description": "윈도우 내 단일 IP의 NXDOMAIN 응답 수가 이 값을 초과하면 알림 발생. "
                           "DGA 악성코드는 다수의 무작위 도메인을 질의하여 NXDOMAIN을 유발함.",
        },
        "nxdomain_window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "NXDOMAIN 윈도우(초)",
            "description": "NXDOMAIN 응답을 집계하는 시간 윈도우.",
        },
        "max_domains": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 도메인 수",
            "description": "메모리에 유지하는 도메인 추적 테이블 크기. "
                           "네트워크 트래픽 규모에 맞게 조정.",
        },
        "max_tracked_ips": {
            "type": int, "default": 5000, "min": 100, "max": 100000,
            "label": "최대 추적 IP 수",
            "description": "NXDOMAIN 추적용 IP 테이블 크기.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """DNS 응답 분석 엔진을 초기화한다. Fast-flux 및 NXDOMAIN 관련 설정을 적용한다."""
        super().__init__(config)

        # Fast-flux 탐지 설정
        self._flux_min_ips = config.get("flux_min_ips", 10)
        self._flux_max_ttl = config.get("flux_max_ttl", 300)
        self._flux_window = config.get("flux_window_seconds", 3600)

        # NXDOMAIN 버스트 설정
        self._nxdomain_threshold = config.get("nxdomain_threshold", 10)
        self._nxdomain_window = config.get("nxdomain_window_seconds", 60)

        # 메모리 제한
        self._max_domains = 10000
        self._max_tracked_ips = 5000

        # Fast-flux 추적: domain -> {ips: set, min_ttl: int, first_seen: float}
        self._domain_records: dict[str, dict[str, Any]] = {}

        # NXDOMAIN 추적: dst_ip (질의자) -> (timestamp, domain) deque
        self._nxdomain_tracker: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

        # 중복 알림 방지용 쿨다운 집합
        self._flux_alerted: set[str] = set()
        self._nxdomain_alerted: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """DNS 응답 패킷에서 NXDOMAIN 버스트와 Fast-flux 패턴을 추적한다."""
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]
        if dns.qr != 1:  # 응답만 처리
            return None

        # NXDOMAIN 추적 (rcode 3)
        if dns.rcode == 3:
            return self._track_nxdomain(packet, dns)

        # Fast-flux: A 레코드 응답 분석
        if dns.an is not None:
            return self._track_dns_answers(packet, dns)

        return None

    def _track_nxdomain(self, packet: Packet, dns) -> Alert | None:
        """목적지 호스트(원래 질의자)별 NXDOMAIN 응답을 추적한다."""
        # DNS 응답은 질의자에게 전송 — dst_ip가 질의자
        _, dst_ip = get_ip_addrs(packet)
        if not dst_ip:
            return None

        qname = ""
        if packet.haslayer(DNSQR):
            qname_raw = dns[DNSQR].qname
            if isinstance(qname_raw, bytes):
                qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
            else:
                qname = str(qname_raw).rstrip(".")

        if _is_safe_domain(qname):
            return None

        now = time.time()

        # 메모리 제한: 용량 초과 시 가장 짧은 deque의 IP 제거
        if dst_ip not in self._nxdomain_tracker and len(self._nxdomain_tracker) >= self._max_tracked_ips:
            shortest_ip = min(self._nxdomain_tracker, key=lambda k: len(self._nxdomain_tracker[k]))
            del self._nxdomain_tracker[shortest_ip]
            self._nxdomain_alerted.discard(shortest_ip)

        tracker = self._nxdomain_tracker[dst_ip]
        tracker.append((now, qname))

        # 오래된 항목 제거
        cutoff = now - self._nxdomain_window
        while tracker and tracker[0][0] < cutoff:
            tracker.popleft()

        # 임계값 검사
        if len(tracker) >= self._nxdomain_threshold and dst_ip not in self._nxdomain_alerted:
            self._nxdomain_alerted.add(dst_ip)
            domains = [d for _, d in tracker]
            sample = domains[-5:]  # 최근 5개 도메인을 샘플로
            return Alert(
                engine=self.name,
                severity=Severity.WARNING,
                title="NXDOMAIN DGA Burst",
                description=(
                    f"Host {dst_ip} received {len(tracker)} NXDOMAIN responses "
                    f"in {self._nxdomain_window}s. "
                    f"Sample domains: {', '.join(sample)}"
                ),
                source_ip=dst_ip,
                confidence=0.70,
                metadata={
                    "nxdomain_count": len(tracker),
                    "window_seconds": self._nxdomain_window,
                    "sample_domains": sample,
                    "unique_domains": len(set(domains)),
                },
            )

        return None

    def _track_dns_answers(self, packet: Packet, dns) -> Alert | None:
        """Fast-flux 탐지를 위해 A 레코드 응답을 추적한다."""
        qname = ""
        if packet.haslayer(DNSQR):
            qname_raw = dns[DNSQR].qname
            if isinstance(qname_raw, bytes):
                qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
            else:
                qname = str(qname_raw).rstrip(".")

        if not qname or _is_safe_domain(qname):
            return None

        now = time.time()

        # A 레코드 IP 및 TTL 추출
        ancount = dns.ancount if dns.ancount is not None else 1
        for i in range(min(ancount, 20)):
            try:
                rr = dns.an[i]
                # A 레코드만 (타입 1)
                rr_type = getattr(rr, "type", None)
                if rr_type != 1:
                    continue

                rdata = getattr(rr, "rdata", None)
                ttl = getattr(rr, "ttl", 0)

                if rdata is None:
                    continue

                ip_str = str(rdata)

                if qname not in self._domain_records:
                    # 메모리 제한: 용량 초과 시 가장 오래된 도메인 제거
                    if len(self._domain_records) >= self._max_domains:
                        oldest_domain = min(
                            self._domain_records,
                            key=lambda k: self._domain_records[k]["first_seen"],
                        )
                        del self._domain_records[oldest_domain]
                        self._flux_alerted.discard(oldest_domain)

                    self._domain_records[qname] = {
                        "ips": set(),
                        "min_ttl": ttl,
                        "first_seen": now,
                    }

                record = self._domain_records[qname]
                record["ips"].add(ip_str)
                record["min_ttl"] = min(record["min_ttl"], ttl)

            except Exception:
                continue

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """Fast-flux 도메인 검사 및 NXDOMAIN 추적 데이터를 정리한다."""
        alerts: list[Alert] = []
        now = time.time()

        # Fast-flux 검사: 추적 중인 도메인 스캔
        expired_domains = []
        for domain, record in self._domain_records.items():
            age = now - record["first_seen"]

            # 오래된 항목 만료
            if age > self._flux_window:
                expired_domains.append(domain)
                continue

            # Fast-flux 조건 검사
            if (
                len(record["ips"]) >= self._flux_min_ips
                and record["min_ttl"] < self._flux_max_ttl
                and domain not in self._flux_alerted
            ):
                self._flux_alerted.add(domain)
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Fast-flux DNS Pattern",
                    description=(
                        f"Domain {domain} resolved to {len(record['ips'])} "
                        f"unique IPs with min TTL={record['min_ttl']}s "
                        f"in {age:.0f}s window"
                    ),
                    confidence=0.75,
                    metadata={
                        "domain": domain,
                        "unique_ips": len(record["ips"]),
                        "min_ttl": record["min_ttl"],
                        "sample_ips": list(record["ips"])[:10],
                        "window_seconds": age,
                    },
                ))

        for domain in expired_domains:
            del self._domain_records[domain]
            self._flux_alerted.discard(domain)

        # NXDOMAIN 정리: 만료된 항목 제거 및 알림 리셋
        cutoff = now - self._nxdomain_window
        expired_hosts = []
        for host_ip, tracker in self._nxdomain_tracker.items():
            while tracker and tracker[0][0] < cutoff:
                tracker.popleft()
            if not tracker:
                expired_hosts.append(host_ip)

        for host_ip in expired_hosts:
            del self._nxdomain_tracker[host_ip]
            self._nxdomain_alerted.discard(host_ip)

        # 과대해진 쿨다운 집합 정리
        if len(self._flux_alerted) > 5000:
            self._flux_alerted.clear()
        if len(self._nxdomain_alerted) > 5000:
            self._nxdomain_alerted.clear()

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._domain_records.clear()
        self._nxdomain_tracker.clear()
        self._flux_alerted.clear()
        self._nxdomain_alerted.clear()
