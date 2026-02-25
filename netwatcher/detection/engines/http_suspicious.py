"""의심스러운 HTTP 트래픽 탐지: 애드웨어 도메인, 비컨 패턴."""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, Raw, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.http_suspicious")

# 일반적인 애드웨어 / 추적 / 의심 도메인 패턴
SUSPICIOUS_PATTERNS = [
    re.compile(rb"Host:\s*(.*?(?:adserv|clicktrack|tracking|malware|adware|doubleclick"
               rb"|spyware|adnxs|taboola|outbrain).*?)\r\n", re.IGNORECASE),
]

# 비컨 탐지: 동일 호스트에 대한 규칙적 간격
BEACON_PATTERN = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)

# 주기적 연결을 수행하는 알려진 정상 서비스.
# OS 연결 확인, 업데이트 서비스, keepalive 메커니즘으로
# 비컨과 유사한 패턴을 생성하지만 C2 트래픽이 아님.
_KNOWN_PERIODIC_DOMAINS: set[str] = {
    # Ubuntu / Debian 계열
    "connectivity-check.ubuntu.com",
    "changelogs.ubuntu.com",
    "security.ubuntu.com",
    # Google / ChromeOS 계열
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "www.gstatic.com",
    # Apple 계열
    "captive.apple.com",
    "www.apple.com",
    # Microsoft / Windows 계열
    "www.msftncsi.com",
    "www.msftconnecttest.com",
    "dns.msftncsi.com",
    # Firefox 계열
    "detectportal.firefox.com",
    # GNOME
    "nmcheck.gnome.org",
    # Fedora / Red Hat 계열
    "fedoraproject.org",
    # 일반 NTP / 시간 동기화
    "time.google.com",
    "time.windows.com",
}


class HTTPSuspiciousEngine(DetectionEngine):
    """의심스러운 HTTP 트래픽 패턴을 탐지한다.

    - 알려진 애드웨어 / 추적 도메인 접근
    - 비컨과 유사한 주기적 접속 (C2 지표)
    """

    name = "http_suspicious"
    requires_span = True
    description = "HTTP 트래픽에서 의심스러운 패턴을 탐지합니다. SQL Injection, XSS, 디렉토리 트래버설 등 웹 공격 시도를 식별합니다."
    config_schema = {
        "beacon_interval_tolerance": {
            "type": float, "default": 0.15, "min": 0.01, "max": 0.5,
            "label": "비컨 간격 허용 편차",
            "description": "C2 비컨 판정 시 접속 간격의 변동계수(CV) 임계값. "
                           "0.15 = 15% 이내 편차면 규칙적 접속으로 판단. "
                           "낮추면 엄격한 판정(정확한 주기만 탐지), 높이면 느슨한 판정.",
        },
        "min_beacon_count": {
            "type": int, "default": 5, "min": 3, "max": 50,
            "label": "최소 비컨 횟수",
            "description": "C2 비컨 판정에 필요한 최소 접속 횟수. "
                           "낮추면 빠른 탐지(오탐 가능), 높이면 확실한 패턴만 탐지.",
        },
        "beacon_window_seconds": {
            "type": int, "default": 3600, "min": 300, "max": 86400,
            "label": "비컨 분석 윈도우(초)",
            "description": "C2 비컨 패턴을 분석하는 시간 윈도우. "
                           "기본값 1시간. 길게 설정하면 긴 주기 비컨도 탐지.",
        },
        "max_tracked_pairs": {
            "type": int, "default": 5000, "min": 100, "max": 100000,
            "label": "최대 추적 쌍 수",
            "description": "메모리에 유지하는 (출발지IP, 호스트) 쌍의 최대 수.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진 설정을 초기화하고 비컨 탐지 상태를 구성한다."""
        super().__init__(config)
        self._beacon_tolerance = config.get("beacon_interval_tolerance", 0.15)
        self._min_beacon_count = config.get("min_beacon_count", 5)
        self._beacon_window = config.get("beacon_window_seconds", 3600)
        self._max_tracked_pairs = config.get("max_tracked_pairs", 5000)

        # 비컨 탐지용 src_ip -> {host -> [timestamps]}
        self._host_times: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._total_pairs = 0

    def analyze(self, packet: Packet) -> Alert | None:
        """HTTP 패킷에서 의심스러운 도메인 접근 및 비컨 패턴을 분석한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        tcp = packet[TCP]
        if tcp.dport not in (80, 8080, 8000):
            return None

        payload = bytes(packet[Raw].load)

        # HTTP 요청만 처리
        if not payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ")):
            return None

        src_ip, dst_ip = get_ip_addrs(packet)

        # 의심스러운 도메인 검사
        for pattern in SUSPICIOUS_PATTERNS:
            match = pattern.search(payload)
            if match:
                host = match.group(1).decode("utf-8", errors="ignore").strip()
                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Suspicious HTTP Request",
                    description=(
                        f"HTTP request to suspicious domain: {host}"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.7,
                    metadata={"host": host, "confidence": 0.7},
                )

        # 비컨 탐지를 위한 호스트 접근 시간 추적
        host_match = BEACON_PATTERN.search(payload)
        if host_match and src_ip:
            host = host_match.group(1).decode("utf-8", errors="ignore").strip()

            # 조기 필터: 추적 전에 알려진 주기적 도메인 건너뛰기
            host_lower = host.lower().rstrip(".")
            if host_lower in _KNOWN_PERIODIC_DOMAINS:
                return None
            if self.is_whitelisted(domain=host_lower):
                return None

            # 새 쌍 추가 시 제한 초과 여부 확인
            if host not in self._host_times[src_ip]:
                if self._total_pairs >= self._max_tracked_pairs:
                    # 용량 초과 시 새 쌍 추가 건너뛰기
                    return None
                self._total_pairs += 1

            self._host_times[src_ip][host].append(time.time())

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 비컨 패턴을 검사하여 C2 통신 의심 알림을 생성한다."""
        alerts = []
        cutoff = time.time() - self._beacon_window

        src_ips_to_delete = []
        for src_ip, hosts in self._host_times.items():
            hosts_to_delete = []
            for host, times in hosts.items():
                # 오래된 항목 제거
                times[:] = [t for t in times if t > cutoff]
                if len(times) < self._min_beacon_count:
                    if not times:
                        hosts_to_delete.append(host)
                    continue

                # 규칙적 간격 검사 (비컨 패턴)
                intervals = [
                    times[i + 1] - times[i] for i in range(len(times) - 1)
                ]
                if not intervals:
                    continue

                avg_interval = sum(intervals) / len(intervals)
                if avg_interval < 1:
                    continue

                # 간격이 일관적인지 확인 (낮은 분산)
                deviations = [
                    abs(iv - avg_interval) / avg_interval for iv in intervals
                ]
                avg_deviation = sum(deviations) / len(deviations)

                if avg_deviation < self._beacon_tolerance:
                    # 알려진 정상 주기적 서비스 건너뛰기
                    host_lower = host.lower().rstrip(".")
                    if host_lower in _KNOWN_PERIODIC_DOMAINS:
                        times.clear()
                        continue
                    if self.is_whitelisted(domain=host_lower):
                        times.clear()
                        continue

                    confidence = max(0.5, 1.0 - avg_deviation * 2)
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="Beacon Pattern Detected",
                        description=(
                            f"{src_ip} connecting to {host} at regular intervals "
                            f"(~{avg_interval:.1f}s, {len(times)} connections). "
                            "Possible C2 communication."
                        ),
                        source_ip=src_ip,
                        metadata={
                            "host": host,
                            "avg_interval": round(avg_interval, 2),
                            "connection_count": len(times),
                            "deviation": round(avg_deviation, 3),
                            "confidence": round(confidence, 2),
                        },
                    ))
                    times.clear()

            for h in hosts_to_delete:
                del hosts[h]
                self._total_pairs -= 1

            if not hosts:
                src_ips_to_delete.append(src_ip)

        for ip in src_ips_to_delete:
            del self._host_times[ip]

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 추적 상태를 초기화한다."""
        self._host_times.clear()
        self._total_pairs = 0
