"""HTTP 이상 탐지: 스캐너 탐지, C2 비컨 패턴 분석."""

from __future__ import annotations

import logging
import statistics
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, Packet, TCP

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.http_suspicious")

# 알려진 취약점 스캐너 키워드
_SCANNER_AGENTS = ["sqlmap", "nikto", "dirbuster", "nmap", "zgrab", "masscan", "gobuster"]


class HTTPSuspiciousEngine(DetectionEngine):
    """HTTP 트래픽의 의심스러운 패턴을 탐지한다.

    - Scanner Detection: User-Agent 기반의 알려진 보안 스캐너 식별
    - Beaconing Analysis: 동일 목적지에 대해 일정한 시간 간격으로 반복되는 접속 (C2 징후)
    """

    name = "http_suspicious"
    description = "HTTP 트래픽의 이상을 탐지합니다. 보안 스캐너 사용 및 악성코드의 C2 비컨 통신 패턴을 식별합니다."
    description_key = "engines.http_suspicious.description"
    config_schema = {
        "beacon_threshold": {
            "type": int, "default": 10, "min": 5, "max": 100,
            "label": "비컨 접속 횟수",
            "label_key": "engines.http_suspicious.beacon_threshold.label",
            "description": "동일 목적지에 대해 이 횟수 이상의 규칙적인 접속이 발생하면 비컨으로 의심.",
            "description_key": "engines.http_suspicious.beacon_threshold.description",
        },
        "max_jitter_pct": {
            "type": float, "default": 0.15, "min": 0.05, "max": 0.5,
            "label": "최대 지터 편차",
            "label_key": "engines.http_suspicious.max_jitter_pct.label",
            "description": "접속 간격의 표준편차가 평균의 이 비율 이내여야 규칙적인 비컨으로 판단.",
            "description_key": "engines.http_suspicious.max_jitter_pct.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화하고 비컨 추적 버퍼를 생성한다."""
        super().__init__(config)
        self._beacon_threshold = config.get("beacon_threshold", 10)
        self._max_jitter = config.get("max_jitter_pct", 0.15)

        # (src_ip, host) -> deque of timestamps
        self._connections: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """HTTP 패킷(추정)에서 스캐너 및 주기적 접속을 분석한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None

        # HTTP 분석 (단순 문자열 매칭 방식)
        payload = bytes(packet[TCP].payload)
        if not payload.startswith(b"GET ") and not payload.startswith(b"POST "):
            return None

        src_ip = packet[IP].src
        text = payload.decode("utf-8", errors="ignore")
        
        # 1. 스캐너 탐지
        ua_match = None
        for line in text.split("\r\n"):
            if line.lower().startswith("user-agent:"):
                ua = line[11:].strip()
                for scanner in _SCANNER_AGENTS:
                    if scanner in ua.lower():
                        ua_match = ua
                        break
                break

        if ua_match:
            now = time.time()
            if now - self._alerted.get(f"{src_ip}:scanner", 0) > 300:
                self._alerted[f"{src_ip}:scanner"] = now
                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Security Scanner Detected",
                    title_key="engines.http_suspicious.alerts.scanner.title",
                    description=(
                        f"Host {src_ip} is using a known security scanner: {ua_match}. "
                        "Possible reconnaissance or automated attack."
                    ),
                    description_key="engines.http_suspicious.alerts.scanner.description",
                    source_ip=src_ip,
                    confidence=0.8,
                    metadata={"user_agent": ua_match},
                )

        # 2. 비컨 추적 (Host 헤더 기반)
        host = ""
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line[5:].strip()
                break
        
        if host:
            self._connections[(src_ip, host)].append(time.time())

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 접속 간격을 분석하여 비컨 패턴을 식별한다."""
        alerts = []
        now = time.time()

        for (src_ip, host), times in list(self._connections.items()):
            if len(times) < self._beacon_threshold:
                # 윈도우 밖의 오래된 데이터는 analyze 시점이 아닌 tick에서 정리
                while times and now - times[0] > 3600:
                    times.popleft()
                continue

            # 간격 분석
            intervals = []
            for i in range(1, len(times)):
                intervals.append(times[i] - times[i-1])
            
            if not intervals: continue
            
            avg_interval = statistics.mean(intervals)
            std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            
            # 지터(편차)가 매우 낮으면 규칙적인 비컨으로 판단
            if avg_interval > 5 and (std_dev / avg_interval) < self._max_jitter:
                if now - self._alerted.get(f"{src_ip}:beacon:{host}", 0) > 1800:
                    self._alerted[f"{src_ip}:beacon:{host}"] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="HTTP Beaconing Detected",
                        title_key="engines.http_suspicious.alerts.beacon.title",
                        description=(
                            f"Host {src_ip} is beaconing to '{host}' every {avg_interval:.1f}s "
                            f"(deviation: {std_dev/avg_interval:.1%}). Likely C2 communication."
                        ),
                        description_key="engines.http_suspicious.alerts.beacon.description",
                        source_ip=src_ip,
                        confidence=0.9,
                        metadata={
                            "host": host, 
                            "avg_interval": round(avg_interval, 1),
                            "deviation": round(std_dev / avg_interval, 3),
                            "connection_count": len(times)
                        },
                    ))
            
            # 분석 후 데이터 정리
            while len(times) > self._beacon_threshold * 2:
                times.popleft()

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._connections.clear()
        self._alerted.clear()
