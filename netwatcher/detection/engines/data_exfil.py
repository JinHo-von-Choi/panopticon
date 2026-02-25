"""데이터 유출 탐지: 대용량 외부 전송, DNS 터널링 지표."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs, is_internal


class DataExfilEngine(DetectionEngine):
    """잠재적 데이터 유출을 탐지한다.

    - 단일 외부 IP로의 대용량 아웃바운드 데이터 전송
    - DNS TXT 레코드 대용량 응답 (DNS 터널링 지표)
    """

    name = "data_exfil"
    description = "대용량 데이터 유출을 탐지합니다. 외부로 전송되는 비정상적 데이터 볼륨을 모니터링하여 정보 탈취를 식별합니다."
    config_schema = {
        "byte_threshold": {
            "type": int, "default": 104857600, "min": 1048576, "max": 10737418240,
            "label": "전송량 임계값(bytes)",
            "description": "윈도우 내 단일 (출발지->목적지) 쌍의 전송량이 이 값을 초과하면 데이터 유출 의심 알림. "
                           "기본값 100MB/시간. 네트워크 정상 트래픽 규모에 맞게 조정.",
        },
        "window_seconds": {
            "type": int, "default": 3600, "min": 300, "max": 86400,
            "label": "분석 윈도우(초)",
            "description": "데이터 전송량을 집계하는 시간 윈도우. 기본값 1시간.",
        },
        "dns_txt_size_threshold": {
            "type": int, "default": 500, "min": 50, "max": 5000,
            "label": "DNS TXT 크기 임계값(bytes)",
            "description": "DNS TXT 레코드 크기가 이 값을 초과하면 DNS 터널링 통한 데이터 유출 의심. "
                           "정상 TXT 레코드는 보통 수십~수백 bytes.",
        },
        "max_tracked_pairs": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 쌍 수",
            "description": "메모리에 유지하는 (출발지, 목적지) 쌍의 최대 수.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진 설정을 초기화하고 데이터 전송량 추적 상태를 구성한다."""
        super().__init__(config)
        self._byte_threshold = config.get("byte_threshold", 100 * 1024 * 1024)  # 100MB
        self._window = config.get("window_seconds", 3600)
        self._dns_txt_threshold = config.get("dns_txt_size_threshold", 500)

        # (src_ip, dst_ip) -> (timestamp, bytes) deque
        self._outbound_bytes: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self._alerted: dict[tuple[str, str], float] = {}
        self._dns_txt_alerted: set[tuple[str, str]] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷에서 외부 전송량 추적 및 DNS TXT 대용량 응답을 분석한다."""
        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip or not dst_ip:
            return None

        pkt_len = len(packet)

        # 아웃바운드 바이트 추적 (내부 -> 외부)
        if is_internal(src_ip) and not is_internal(dst_ip):
            now = time.time()
            key = (src_ip, dst_ip)
            self._outbound_bytes[key].append((now, pkt_len))

        # DNS TXT 레코드 대용량 응답 탐지
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 1 and dns.ancount:  # 응답
                for i in range(min(dns.ancount, 10)):
                    try:
                        rr = dns.an[i]
                        if getattr(rr, "type", 0) == 16:  # TXT 레코드
                            rdata = getattr(rr, "rdata", b"")
                            if isinstance(rdata, list):
                                total_len = sum(len(r) for r in rdata)
                            elif isinstance(rdata, bytes):
                                total_len = len(rdata)
                            else:
                                total_len = len(str(rdata))

                            if total_len > self._dns_txt_threshold:
                                qname = ""
                                if packet.haslayer(DNSQR):
                                    qname_raw = dns[DNSQR].qname
                                    if isinstance(qname_raw, bytes):
                                        qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
                                    else:
                                        qname = str(qname_raw).rstrip(".")

                                alert_key = (src_ip, qname)
                                if alert_key not in self._dns_txt_alerted:
                                    self._dns_txt_alerted.add(alert_key)
                                    return Alert(
                                        engine=self.name,
                                        severity=Severity.WARNING,
                                        title="Large DNS TXT Response",
                                        description=(
                                            f"DNS TXT response of {total_len} bytes "
                                            f"for {qname}. Large TXT records may "
                                            "indicate DNS tunneling for data exfiltration."
                                        ),
                                        source_ip=dst_ip,  # DNS server
                                        dest_ip=src_ip,    # 내부 요청자
                                        confidence=0.65,
                                        metadata={
                                            "qname": qname,
                                            "txt_size": total_len,
                                            "threshold": self._dns_txt_threshold,
                                        },
                                    )
                    except Exception:
                        break

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 누적 전송량을 검사하여 데이터 유출 의심 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        keys_to_delete = []
        for key, entries in self._outbound_bytes.items():
            # 오래된 항목 제거
            while entries and entries[0][0] < cutoff:
                entries.popleft()

            if not entries:
                keys_to_delete.append(key)
                continue

            total_bytes = sum(b for _, b in entries)
            src_ip, dst_ip = key
            last_alert = self._alerted.get(key, 0)

            if total_bytes > self._byte_threshold and now - last_alert > self._window:
                self._alerted[key] = now
                mb = total_bytes / (1024 * 1024)
                threshold_mb = self._byte_threshold / (1024 * 1024)
                confidence = min(1.0, 0.6 + (total_bytes / self._byte_threshold - 1) * 0.2)
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Potential Data Exfiltration",
                    description=(
                        f"Internal host {src_ip} transferred {mb:.1f}MB to "
                        f"external IP {dst_ip} in {self._window // 3600}h "
                        f"(threshold: {threshold_mb:.0f}MB)."
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=confidence,
                    metadata={
                        "total_bytes": total_bytes,
                        "threshold_bytes": self._byte_threshold,
                        "window_seconds": self._window,
                    },
                ))

        for key in keys_to_delete:
            del self._outbound_bytes[key]

        # 만료된 쿨다운 제거
        expired = [k for k, v in self._alerted.items() if now - v > self._window * 2]
        for k in expired:
            del self._alerted[k]

        # DNS TXT 알림 캐시 주기적 정리
        if len(self._dns_txt_alerted) > 1000:
            self._dns_txt_alerted.clear()

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 상태를 초기화한다."""
        self._outbound_bytes.clear()
        self._alerted.clear()
        self._dns_txt_alerted.clear()
