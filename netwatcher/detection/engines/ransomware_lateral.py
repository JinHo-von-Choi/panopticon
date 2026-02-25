"""랜섬웨어 내부 확산 탐지: SMB 워드 스캔, RDP 브루트포스, 허니팟 접근."""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs, is_internal

logger = logging.getLogger("netwatcher.detection.engines.ransomware_lateral")


class RansomwareLateralEngine(DetectionEngine):
    """랜섬웨어 내부 확산 패턴에 특화된 탐지 엔진.

    탐지 시나리오:
    - SMB 워드 스캔: 내부 호스트가 30초 내 다수 내부 IP의 445 포트에 SYN 전송
    - RDP 브루트포스: 동일 src→dst 쌍으로 60초 내 3389 SYN 반복
    - 허니팟 접근: 설정된 허니팟 IP에 대한 모든 접근
    """

    name = "ransomware_lateral"
    description = (
        "랜섬웨어 내부 확산 패턴을 탐지합니다. "
        "SMB 워드 스캔(WannaCry 패턴), RDP 브루트포스, 허니팟 접근을 감시합니다."
    )
    config_schema = {
        "smb_scan_window_seconds": {
            "type": int, "default": 30, "min": 10, "max": 300,
            "label": "SMB 스캔 윈도우(초)",
            "description": "SMB 스캔 탐지 슬라이딩 윈도우 크기.",
        },
        "smb_scan_threshold": {
            "type": int, "default": 15, "min": 3, "max": 200,
            "label": "SMB 스캔 임계값",
            "description": "윈도우 내 단일 소스의 고유 내부 445 대상 IP 수 임계값.",
        },
        "rdp_brute_window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "RDP 브루트포스 윈도우(초)",
            "description": "RDP 반복 시도 탐지 슬라이딩 윈도우 크기.",
        },
        "rdp_brute_threshold": {
            "type": int, "default": 10, "min": 3, "max": 200,
            "label": "RDP 브루트포스 임계값",
            "description": "윈도우 내 동일 src→dst 쌍의 3389 SYN 횟수 임계값.",
        },
        "alert_cooldown_seconds": {
            "type": int, "default": 300, "min": 30, "max": 3600,
            "label": "재알림 쿨다운(초)",
            "description": "동일 소스에 대한 알림 재발송 대기 시간.",
        },
        "honeypot_ips": {
            "type": list, "default": [],
            "label": "허니팟 IP 목록",
            "description": "접근 즉시 CRITICAL 알림을 발생시키는 허니팟 IP 주소 목록.",
        },
        "max_tracked_sources": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 소스 수",
            "description": "메모리에 유지하는 추적 소스 수 상한.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._smb_window    = config.get("smb_scan_window_seconds",  30)
        self._smb_threshold = config.get("smb_scan_threshold",       15)
        self._rdp_window    = config.get("rdp_brute_window_seconds", 60)
        self._rdp_threshold = config.get("rdp_brute_threshold",      10)
        self._cooldown      = config.get("alert_cooldown_seconds",   300)
        self._honeypot_ips  = set(config.get("honeypot_ips", []))
        self._max_tracked   = config.get("max_tracked_sources",    10000)

        # SMB: src_ip → deque[(timestamp, dst_ip)]
        self._smb: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        # RDP: (src_ip, dst_ip) → deque[timestamp]
        self._rdp: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        # 쿨다운: key → last_alerted_timestamp
        self._alerted: dict[str, float] = {}
        # 허니팟 쿨다운: src_ip → last_alerted_timestamp
        self._honeypot_alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷당 즉시 탐지: 허니팟 접근 확인 + SMB/RDP 데이터 수집."""
        pass  # Task 2, 3, 4에서 구현

    def on_tick(self, timestamp: float) -> list[Alert]:
        """슬라이딩 윈도우 집계 결과를 바탕으로 알림을 생성한다."""
        return []  # Task 3, 4에서 구현

    def shutdown(self) -> None:
        """종료 시 모든 추적 자료구조를 정리한다."""
        self._smb.clear()
        self._rdp.clear()
        self._alerted.clear()
        self._honeypot_alerted.clear()
