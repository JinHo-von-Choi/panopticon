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
        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip or not dst_ip:
            return None

        # ── 허니팟 접근 즉시 탐지 ──────────────────────────────────────────
        honeypot_hit = (
            (dst_ip in self._honeypot_ips and src_ip != dst_ip)
            or (src_ip in self._honeypot_ips and src_ip != dst_ip)
        )
        if honeypot_hit:
            attacker_ip = src_ip  # 항상 src_ip가 이상 행위의 주체
            now = time.time()
            last = self._honeypot_alerted.get(attacker_ip, 0.0)
            if now - last < self._cooldown:
                return None  # 쿨다운 적용
            self._honeypot_alerted[attacker_ip] = now
            return Alert(
                engine      = self.name,
                severity    = Severity.CRITICAL,
                title       = f"Honeypot Access Detected: {attacker_ip}",
                description = (
                    f"Host {attacker_ip} accessed honeypot resource "
                    f"({src_ip} → {dst_ip}). "
                    "This is a high-confidence indicator of lateral movement."
                ),
                source_ip   = attacker_ip,
                confidence  = 1.0,
                metadata    = {
                    "src_ip":       src_ip,
                    "dst_ip":       dst_ip,
                    "honeypot_ips": sorted(self._honeypot_ips),
                },
            )

        # ── SMB / RDP 데이터 수집 (on_tick에서 분석) ──────────────────────
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]
        # SYN only (SYN=1, ACK=0)
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return None

        # 양쪽 모두 내부 IP여야 함
        if not is_internal(src_ip) or not is_internal(dst_ip):
            return None

        dst_port = tcp.dport
        now = time.time()

        if dst_port == 445:
            if len(self._smb) < self._max_tracked:
                self._smb[src_ip].append((now, dst_ip))

        elif dst_port == 3389:
            key = (src_ip, dst_ip)
            if len(self._rdp) < self._max_tracked:
                self._rdp[key].append(now)

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """슬라이딩 윈도우 집계 결과를 바탕으로 알림을 생성한다."""
        alerts: list[Alert] = []
        now    = time.time()

        # ── SMB 워드 스캔 탐지 ───────────────────────────────────────────
        smb_cutoff = now - self._smb_window
        dead_smb: list[str] = []

        for src_ip, entries in self._smb.items():
            # 화이트리스트 확인
            if self.is_whitelisted(source_ip=src_ip):
                dead_smb.append(src_ip)
                continue

            # 윈도우 밖 항목 제거
            while entries and entries[0][0] < smb_cutoff:
                entries.popleft()

            if not entries:
                dead_smb.append(src_ip)
                continue

            unique_targets = {dst for _, dst in entries}
            if len(unique_targets) >= self._smb_threshold:
                key  = f"smb:{src_ip}"
                last = self._alerted.get(key, 0.0)
                if now - last >= self._cooldown:
                    self._alerted[key] = now
                    confidence = min(1.0, 0.6 + len(unique_targets) * 0.02)
                    alerts.append(Alert(
                        engine      = self.name,
                        severity    = Severity.WARNING,
                        title       = f"SMB Worm Scan: {src_ip}",
                        description = (
                            f"Internal host {src_ip} sent TCP/445 SYN to "
                            f"{len(unique_targets)} unique internal hosts in "
                            f"{self._smb_window}s. "
                            "Pattern consistent with SMB worm propagation (WannaCry/EternalBlue)."
                        ),
                        source_ip   = src_ip,
                        confidence  = confidence,
                        metadata    = {
                            "unique_targets": len(unique_targets),
                            "target_sample":  sorted(unique_targets)[:10],
                            "window_seconds": self._smb_window,
                            "threshold":      self._smb_threshold,
                        },
                    ))

        for k in dead_smb:
            del self._smb[k]

        # ── RDP 브루트포스 탐지 ──────────────────────────────────────────
        rdp_cutoff = now - self._rdp_window
        dead_rdp: list[tuple[str, str]] = []

        for (src_ip, dst_ip), timestamps in self._rdp.items():
            # 화이트리스트 확인
            if self.is_whitelisted(source_ip=src_ip):
                dead_rdp.append((src_ip, dst_ip))
                continue

            # 윈도우 밖 타임스탬프 제거
            while timestamps and timestamps[0] < rdp_cutoff:
                timestamps.popleft()

            if not timestamps:
                dead_rdp.append((src_ip, dst_ip))
                continue

            if len(timestamps) >= self._rdp_threshold:
                key = f"rdp:{src_ip}:{dst_ip}"
                last = self._alerted.get(key, 0.0)
                if now - last >= self._cooldown:
                    self._alerted[key] = now
                    confidence = min(1.0, 0.5 + len(timestamps) * 0.03)
                    alerts.append(Alert(
                        engine      = self.name,
                        severity    = Severity.WARNING,
                        title       = f"RDP Brute Force: {src_ip} → {dst_ip}",
                        description = (
                            f"Host {src_ip} attempted {len(timestamps)} TCP/3389 "
                            f"connections to {dst_ip} in {self._rdp_window}s. "
                            "Pattern consistent with RDP brute force."
                        ),
                        source_ip   = src_ip,
                        dest_ip     = dst_ip,
                        confidence  = confidence,
                        metadata    = {
                            "attempt_count":  len(timestamps),
                            "window_seconds": self._rdp_window,
                            "threshold":      self._rdp_threshold,
                        },
                    ))

        for k in dead_rdp:
            del self._rdp[k]

        # ── 만료된 쿨다운 정리 ───────────────────────────────────────────
        expired = [k for k, t in self._alerted.items() if now - t > self._cooldown * 2]
        for k in expired:
            del self._alerted[k]

        return alerts

    def shutdown(self) -> None:
        """종료 시 모든 추적 자료구조를 정리한다."""
        self._smb.clear()
        self._rdp.clear()
        self._alerted.clear()
        self._honeypot_alerted.clear()
