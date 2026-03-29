"""다크 IP 탐지 엔진 — 내부 네트워크의 미사용(dark) IP 공간으로 향하는 트래픽을 탐지한다."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict

from netwatcher.detection.eviction import BoundedDefaultDict, prune_expired_entries
from typing import Any

from scapy.all import IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.dark_ip")


def _parse_networks(raw: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """CIDR 문자열 목록을 네트워크 객체 목록으로 변환한다. 파싱 불가 항목은 건너뛴다."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in raw:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            logger.warning("DarkIPEngine: 잘못된 CIDR 항목 무시: %r", entry)
    return networks


def _ip_in_networks(
    ip: str,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """IP 문자열이 네트워크 목록 중 하나에 속하는지 확인한다."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


class DarkIPEngine(DetectionEngine):
    """내부 네트워크(monitored_networks)에 속하지만 알려지지 않은 호스트로 향하는 트래픽을 탐지한다.

    설정된 CIDR 블록(`monitored_networks`) 내에서 실제로 통신한 적 없는
    목적지 IP로 패킷이 전송되면 경고를 발생시킨다.

    동작 방식:
    - `known_hosts` 목록에 있는 IP는 항상 정상으로 처리한다.
    - `auto_learn`이 활성화된 경우, 패킷 소스 IP를 학습하여 정상 호스트 목록에 추가한다.
    - `learn_seconds` 동안은 학습만 하고 경고를 발생시키지 않는다.
    - 학습 기간 이후, monitored_networks에 속하지만 학습 목록에 없는 dst_ip를 탐지한다.
    """

    name = "dark_ip"
    description = "내부 네트워크에서 사용되지 않는 IP 공간(다크 스페이스)으로의 트래픽을 탐지합니다."
    description_key = "engines.dark_ip.description"
    mitre_attack_ids = ["T1018"]   # Remote System Discovery
    requires_span = True
    config_schema = {
        "learn_seconds": {
            "type": int, "default": 300, "min": 0, "max": 3600,
            "label": "학습 기간(초)",
            "description": "엔진 시작 후 이 시간 동안은 경고 없이 활성 호스트를 학습한다.",
        },
        "cooldown_seconds": {
            "type": int, "default": 3600, "min": 60, "max": 86400,
            "label": "쿨다운(초)",
            "description": "동일 목적지 IP에 대한 알림 재발생 억제 시간.",
        },
        "auto_learn": {
            "type": bool, "default": True,
            "label": "자동 학습",
            "description": "관찰된 소스 IP를 활성 호스트로 자동 등록한다.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._learn_seconds: int = config.get("learn_seconds", 300)
        self._cooldown: int = config.get("cooldown_seconds", 3600)
        self._auto_learn: bool = config.get("auto_learn", True)

        raw_nets: list[str] = config.get("monitored_networks", [])
        self._monitored: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = _parse_networks(raw_nets)

        raw_hosts: list[str] = config.get("known_hosts", [])
        # 정적으로 알려진 호스트 (재시작 시 복원 기준)
        self._static_hosts: frozenset[str] = frozenset(str(h).strip() for h in raw_hosts if h)
        # 정적 + 동적으로 학습한 호스트를 합산 관리
        self._known_ips: set[str] = set(self._static_hosts)

        # (dst_ip) -> 마지막 알림 시각
        self._alerted: BoundedDefaultDict = BoundedDefaultDict(float, max_keys=10_000)
        self._start_time: float = time.time()

        if self._monitored:
            logger.info(
                "DarkIPEngine: %d monitored network(s) loaded, learn_seconds=%d",
                len(self._monitored),
                self._learn_seconds,
            )
        else:
            logger.info("DarkIPEngine: no monitored_networks configured — detection disabled")

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _is_learning(self) -> bool:
        """엔진이 아직 학습 기간 중인지 반환한다."""
        if self._learn_seconds <= 0:
            return False
        return (time.time() - self._start_time) < self._learn_seconds

    def _record_active(self, ip: str) -> None:
        """IP를 활성(정상) 호스트로 등록한다."""
        if self._auto_learn:
            self._known_ips.add(ip)

    # ------------------------------------------------------------------
    # DetectionEngine 인터페이스
    # ------------------------------------------------------------------

    def analyze(self, packet: Packet) -> Alert | None:
        """IP 패킷의 목적지가 모니터링 대역 내 미지 호스트이면 Alert를 반환한다."""
        if not self._monitored:
            return None
        if not packet.haslayer(IP):
            return None

        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst

        # 소스 IP를 활성 호스트로 등록 (항상 수행)
        self._record_active(src_ip)

        # 목적지가 모니터링 대역에 속하는지 확인
        if not _ip_in_networks(dst_ip, self._monitored):
            return None

        # 알려진 호스트이면 정상
        if dst_ip in self._known_ips:
            return None

        # 학습 기간 중에는 목적지도 활성 호스트로 등록하고 경고 생략
        if self._is_learning():
            self._record_active(dst_ip)
            return None

        # 쿨다운 확인
        now = time.time()
        if now - self._alerted.get(dst_ip, 0.0) < self._cooldown:
            return None
        self._alerted[dst_ip] = now

        return Alert(
            engine=self.name,
            severity=Severity.WARNING,
            title="Dark IP Access Detected",
            title_key="engines.dark_ip.alerts.dark_ip.title",
            description=(
                f"{src_ip} → {dst_ip} targets an unrecognised host "
                "in the monitored internal network. Possible internal reconnaissance."
            ),
            description_key="engines.dark_ip.alerts.dark_ip.description",
            source_ip=src_ip,
            dest_ip=dst_ip,
            confidence=0.7,
            metadata={
                "monitored_networks": [str(n) for n in self._monitored],
                "known_hosts_count": len(self._known_ips),
            },
        )

    def on_tick(self, timestamp: float) -> list[Alert]:
        """만료된 알림 쿨다운 항목을 정리한다."""
        prune_expired_entries(self._alerted, max_age=self._cooldown * 2)
        return []

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._alerted.clear()
        self._known_ips = set(self._static_hosts)
        self._start_time = time.time()
