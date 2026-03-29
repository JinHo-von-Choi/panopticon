"""시그니처 규칙 매칭 엔진.

패킷과 페이로드를 SignatureRule에 대해 검사한다.
프로토콜, 포트, TCP 플래그, 콘텐츠, PCRE, 임계값을 포괄적으로 검증한다.
"""

from __future__ import annotations

import time
from collections import deque

from scapy.all import ICMP, IP, Packet, TCP, UDP

from netwatcher.detection.engines.signature_rule import SignatureRule


class RuleMatcher:
    """패킷-규칙 매칭을 수행한다."""

    def __init__(self) -> None:
        self._threshold_counters: dict[str, deque[float]] = {}

    def matches(
        self,
        rule: SignatureRule,
        packet: Packet,
        payload: bytes,
    ) -> bool:
        """규칙의 모든 조건이 패킷/페이로드와 일치하는지 검사한다."""
        if not self._check_protocol(rule, packet):
            return False
        if not self._check_ports(rule, packet):
            return False
        if not self._check_flags(rule, packet):
            return False
        if not self._check_content(rule, payload):
            return False
        if not self._check_pcre(rule, payload):
            return False

        src_ip = packet[IP].src if packet.haslayer(IP) else ""
        now    = time.monotonic()
        if not self._check_threshold(rule, src_ip, now):
            return False

        return True

    def _check_protocol(self, rule: SignatureRule, packet: Packet) -> bool:
        """프로토콜 조건을 검사한다."""
        if rule.protocol is None:
            return True
        proto = rule.protocol.lower()
        if proto == "tcp":
            return packet.haslayer(TCP)
        if proto == "udp":
            return packet.haslayer(UDP)
        if proto == "icmp":
            return packet.haslayer(ICMP)
        return True

    def _check_ports(self, rule: SignatureRule, packet: Packet) -> bool:
        """소스/대상 포트 조건을 검사한다."""
        if rule.src_port is not None:
            pkt_sport = self._get_sport(packet)
            if pkt_sport is None:
                return False
            if not self._port_matches(rule.src_port, pkt_sport):
                return False

        if rule.dst_port is not None:
            pkt_dport = self._get_dport(packet)
            if pkt_dport is None:
                return False
            if not self._port_matches(rule.dst_port, pkt_dport):
                return False

        return True

    @staticmethod
    def _port_matches(rule_port: int | list[int], actual_port: int) -> bool:
        """규칙의 포트 조건과 실제 포트를 비교한다."""
        if isinstance(rule_port, list):
            return actual_port in rule_port
        return actual_port == rule_port

    @staticmethod
    def _get_sport(packet: Packet) -> int | None:
        """패킷의 소스 포트를 추출한다."""
        if packet.haslayer(TCP):
            return packet[TCP].sport
        if packet.haslayer(UDP):
            return packet[UDP].sport
        return None

    @staticmethod
    def _get_dport(packet: Packet) -> int | None:
        """패킷의 대상 포트를 추출한다."""
        if packet.haslayer(TCP):
            return packet[TCP].dport
        if packet.haslayer(UDP):
            return packet[UDP].dport
        return None

    def _check_flags(self, rule: SignatureRule, packet: Packet) -> bool:
        """TCP 플래그 조건을 검사한다."""
        if rule.flags is None:
            return True
        if not packet.haslayer(TCP):
            return False

        pkt_flags = str(packet[TCP].flags)
        for flag_char in rule.flags:
            if flag_char not in pkt_flags:
                return False
        return True

    def _check_content(self, rule: SignatureRule, payload: bytes) -> bool:
        """content 키워드 매칭을 수행한다."""
        if not rule.content:
            return True
        if not payload:
            return False

        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = payload.decode("latin-1")

        check_text = text.lower() if rule.content_nocase else text
        for pattern in rule.content:
            check_pattern = pattern.lower() if rule.content_nocase else pattern
            if check_pattern not in check_text:
                return False
        return True

    def _check_pcre(self, rule: SignatureRule, payload: bytes) -> bool:
        """PCRE 패턴 매칭을 수행한다."""
        if not rule.pcre:
            return True
        if not payload:
            return False

        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = payload.decode("latin-1")

        for pcre_pat in rule.pcre:
            if not pcre_pat.search(text):
                return False
        return True

    def _check_threshold(
        self,
        rule: SignatureRule,
        src_ip: str,
        now: float,
    ) -> bool:
        """임계값/속도 제한을 검사한다.

        threshold가 설정된 규칙은 지정된 시간 윈도우 내 count 이상
        히트가 발생해야 매치로 처리한다.
        """
        if rule.threshold is None:
            return True

        count   = rule.threshold.get("count", 1)
        seconds = rule.threshold.get("seconds", 60)
        by      = rule.threshold.get("by", "src_ip")

        key = f"{rule.id}:{by}:{src_ip}"
        if key not in self._threshold_counters:
            self._threshold_counters[key] = deque()

        dq       = self._threshold_counters[key]
        cutoff   = now - seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        dq.append(now)
        return len(dq) >= count

    def prune(self, max_keys: int = 50_000) -> None:
        """임계값 카운터가 과도하게 증가하는 것을 방지한다."""
        if len(self._threshold_counters) > max_keys:
            now    = time.monotonic()
            stale  = [
                k for k, dq in self._threshold_counters.items()
                if not dq or dq[-1] < now - 3600
            ]
            for k in stale:
                del self._threshold_counters[k]
