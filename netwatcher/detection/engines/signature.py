"""YAML 기반 시그니처 탐지 엔진.

사용자 정의 YAML 규칙으로 패킷을 매칭하는 탐지 엔진.
규칙 파일의 hot-reload, threshold 기반 탐지, content/regex 매칭 지원.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from scapy.all import ICMP, IP, TCP, UDP, Packet, Raw

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.signature")

# TCP 플래그 이름 -> 비트마스크 매핑
_FLAG_MAP: dict[str, int] = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}


# ---------------------------------------------------------------------------
# SignatureRule 데이터클래스
# ---------------------------------------------------------------------------
@dataclass
class SignatureRule:
    """단일 시그니처 규칙."""

    id: str
    name: str
    severity: Severity
    protocol: str | None = None          # "tcp", "udp", "icmp", "any" or None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | list[int] | None = None
    dst_port: int | list[int] | None = None
    flags: str | None = None             # "SYN", "FIN", "ACK", etc.
    content: list[bytes] = field(default_factory=list)
    content_nocase: bool = False
    regex: re.Pattern | None = None
    threshold: dict | None = None        # {"count": N, "seconds": S, "by": "src_ip"}
    enabled: bool = True

    # 빠른 매칭을 위한 사전 계산 필드
    _flags_mask: int = field(default=0, repr=False)
    _content_lower: list[bytes] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        """매칭 헬퍼를 사전 계산한다."""
        if self.flags:
            flag_name = self.flags.upper().strip()
            self._flags_mask = _FLAG_MAP.get(flag_name, 0)
        if self.content_nocase:
            self._content_lower = [c.lower() for c in self.content]


# ---------------------------------------------------------------------------
# 규칙 파서
# ---------------------------------------------------------------------------
class RuleParser:
    """YAML 규칙 파일 파싱."""

    @staticmethod
    def _parse_content(raw_content: str | bytes) -> bytes:
        """Content 문자열을 bytes로 변환. hex escape(\x00\xfc) 지원."""
        if isinstance(raw_content, bytes):
            return raw_content
        # Python-style escape sequence 처리 (\\x00 -> \x00)
        try:
            return raw_content.encode("utf-8").decode("unicode_escape").encode("latin-1")
        except (UnicodeDecodeError, ValueError):
            return raw_content.encode("utf-8")

    # 치명적 역추적(ReDoS) 가능성을 나타내는 패턴
    _REDOS_PATTERNS = re.compile(
        rb"(\([^)]*[+*][^)]*\)[+*])"   # nested quantifiers: (a+)+, (a*)*
        rb"|(\([^)]*\|[^)]*\)[+*])"     # alternation with quantifier: (a|b)+
    )
    _MAX_REGEX_LEN = 1024

    @classmethod
    def _parse_regex(cls, raw: str) -> re.Pattern:
        """Regex 문자열 컴파일. PCRE 스타일 /pattern/flags 지원.

        패턴 길이를 검증하고, 치명적 역추적(ReDoS)을 유발할 수 있는
        중첩 수량자 패턴을 거부한다.
        """
        if raw.startswith("/") and "/" in raw[1:]:
            # /pattern/flags 형식 처리
            last_slash = raw.rfind("/")
            pattern = raw[1:last_slash]
            flags_str = raw[last_slash + 1:]
            flags = 0
            if "i" in flags_str:
                flags |= re.IGNORECASE
            if "s" in flags_str:
                flags |= re.DOTALL
            if "m" in flags_str:
                flags |= re.MULTILINE
            pattern_bytes = pattern.encode("utf-8")
        else:
            pattern_bytes = raw.encode("utf-8")
            flags = 0

        # 길이 제한
        if len(pattern_bytes) > cls._MAX_REGEX_LEN:
            raise ValueError(
                f"Regex pattern too long ({len(pattern_bytes)} > {cls._MAX_REGEX_LEN})"
            )

        # ReDoS 패턴 탐지
        if cls._REDOS_PATTERNS.search(pattern_bytes):
            raise ValueError(
                f"Regex pattern rejected: potential catastrophic backtracking (ReDoS)"
            )

        return re.compile(pattern_bytes, flags)

    @staticmethod
    def _parse_severity(raw: str) -> Severity:
        """문자열을 Severity enum으로 변환."""
        mapping = {
            "INFO": Severity.INFO,
            "WARNING": Severity.WARNING,
            "CRITICAL": Severity.CRITICAL,
        }
        upper = raw.upper().strip()
        if upper not in mapping:
            raise ValueError(f"Unknown severity: {raw!r}")
        return mapping[upper]

    @classmethod
    def parse(cls, raw: dict) -> SignatureRule:
        """단일 규칙 dict를 SignatureRule로 파싱."""
        rule_id = str(raw.get("id", ""))
        if not rule_id:
            raise ValueError("Rule must have an 'id' field")

        name = str(raw.get("name", rule_id))
        severity = cls._parse_severity(raw.get("severity", "WARNING"))

        protocol = raw.get("protocol")
        if protocol is not None:
            protocol = str(protocol).lower()

        # Content 파싱
        content: list[bytes] = []
        raw_content = raw.get("content", [])
        if isinstance(raw_content, str):
            raw_content = [raw_content]
        for c in raw_content:
            content.append(cls._parse_content(c))

        # Regex 파싱
        regex = None
        raw_regex = raw.get("regex")
        if raw_regex:
            regex = cls._parse_regex(str(raw_regex))

        # Threshold 파싱
        threshold = raw.get("threshold")
        if threshold is not None:
            if not isinstance(threshold, dict):
                raise ValueError(f"Rule {rule_id}: threshold must be a dict")
            if "count" not in threshold or "seconds" not in threshold:
                raise ValueError(
                    f"Rule {rule_id}: threshold must have 'count' and 'seconds'"
                )
            threshold.setdefault("by", "src_ip")

        # Port 파싱 (int 또는 list[int])
        src_port = raw.get("src_port")
        dst_port = raw.get("dst_port")
        if isinstance(src_port, list):
            src_port = [int(p) for p in src_port]
        elif src_port is not None:
            src_port = int(src_port)
        if isinstance(dst_port, list):
            dst_port = [int(p) for p in dst_port]
        elif dst_port is not None:
            dst_port = int(dst_port)

        return SignatureRule(
            id=rule_id,
            name=name,
            severity=severity,
            protocol=protocol,
            src_ip=raw.get("src_ip"),
            dst_ip=raw.get("dst_ip"),
            src_port=src_port,
            dst_port=dst_port,
            flags=raw.get("flags"),
            content=content,
            content_nocase=bool(raw.get("content_nocase", False)),
            regex=regex,
            threshold=threshold,
            enabled=bool(raw.get("enabled", True)),
        )

    @classmethod
    def load_file(cls, path: str) -> list[SignatureRule]:
        """YAML 파일에서 규칙 로드."""
        rules: list[SignatureRule] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            logger.exception("Failed to load rules file: %s", path)
            return rules

        if not isinstance(data, dict) or "rules" not in data:
            logger.warning("Rules file has no 'rules' key: %s", path)
            return rules

        raw_rules = data["rules"]
        if not isinstance(raw_rules, list):
            logger.warning("'rules' is not a list in %s", path)
            return rules

        for i, raw in enumerate(raw_rules):
            try:
                rule = cls.parse(raw)
                rules.append(rule)
            except Exception:
                logger.exception(
                    "Failed to parse rule #%d in %s", i, path,
                )
        return rules

    @classmethod
    def load_directory(cls, dir_path: str) -> list[SignatureRule]:
        """디렉토리 내 모든 .yaml/.yml 파일에서 규칙 로드."""
        rules: list[SignatureRule] = []
        p = Path(dir_path)
        if not p.is_dir():
            logger.warning("Rules directory does not exist: %s", dir_path)
            return rules

        for fp in sorted(p.iterdir()):
            if fp.suffix in (".yaml", ".yml") and fp.is_file():
                loaded = cls.load_file(str(fp))
                rules.extend(loaded)
                logger.info(
                    "Loaded %d rules from %s", len(loaded), fp.name,
                )
        return rules


# ---------------------------------------------------------------------------
# 시그니처 엔진
# ---------------------------------------------------------------------------
class SignatureEngine(DetectionEngine):
    """YAML 시그니처 기반 패킷 매칭 탐지 엔진."""

    name = "signature"
    description = "YARA 규칙 기반 시그니처 매칭을 수행합니다. 패킷 페이로드에서 알려진 악성코드 패턴, 익스플로잇 코드를 탐지합니다."
    config_schema = {
        "rules_dir": {
            "type": str, "default": "config/rules",
            "label": "규칙 디렉토리 경로",
            "description": "YAML 시그니처 규칙 파일이 위치한 디렉토리. "
                           "이 경로의 *.yaml 파일을 모두 로드함.",
        },
        "hot_reload": {
            "type": bool, "default": True,
            "label": "핫 리로드",
            "description": "활성화 시 규칙 파일 변경을 자동 감지하여 리로드. "
                           "비활성화하면 엔진 재시작 시에만 규칙 로드.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._rules_dir = config.get("rules_dir", "config/rules")
        self._hot_reload = config.get("hot_reload", True)

        # 초기 규칙 로드
        self._rules: list[SignatureRule] = []
        self._rules_by_id: dict[str, SignatureRule] = {}
        self.reload_rules()

        # Threshold 추적: (rule_id, group_key) -> 타임스탬프 deque
        self._threshold_counters: dict[tuple[str, str], deque] = {}

        # 핫 리로드: 디렉토리 mtime 추적
        self._last_dir_mtime: float = self._get_dir_mtime()

    def _get_dir_mtime(self) -> float:
        """규칙 디렉토리의 최신 mtime 반환."""
        p = Path(self._rules_dir)
        if not p.is_dir():
            return 0.0
        mtime = 0.0
        try:
            # 디렉토리 자체 mtime
            mtime = max(mtime, p.stat().st_mtime)
            # 개별 파일 mtime
            for fp in p.iterdir():
                if fp.suffix in (".yaml", ".yml") and fp.is_file():
                    mtime = max(mtime, fp.stat().st_mtime)
        except OSError:
            pass
        return mtime

    def reload_rules(self) -> None:
        """규칙 디렉토리를 재스캔하여 규칙 다시 로드."""
        rules = RuleParser.load_directory(self._rules_dir)
        self._rules = rules
        self._rules_by_id = {r.id: r for r in rules}
        self._last_dir_mtime = self._get_dir_mtime()
        logger.info("Signature engine loaded %d rules", len(rules))

    @property
    def rules(self) -> list[SignatureRule]:
        return list(self._rules)

    @property
    def rules_by_id(self) -> dict[str, SignatureRule]:
        return dict(self._rules_by_id)

    def _match_protocol(self, rule: SignatureRule, packet: Packet) -> bool:
        """프로토콜 매칭."""
        if rule.protocol is None or rule.protocol == "any":
            return True
        if rule.protocol == "tcp":
            return packet.haslayer(TCP)
        if rule.protocol == "udp":
            return packet.haslayer(UDP)
        if rule.protocol == "icmp":
            return packet.haslayer(ICMP)
        return False

    def _match_ip(self, rule: SignatureRule, src_ip: str | None, dst_ip: str | None) -> bool:
        """IP 주소 매칭."""
        if rule.src_ip and rule.src_ip != src_ip:
            return False
        if rule.dst_ip and rule.dst_ip != dst_ip:
            return False
        return True

    def _match_port(self, rule_port: int | list[int] | None, actual_port: int | None) -> bool:
        """포트 매칭 (단일 값 또는 리스트)."""
        if rule_port is None:
            return True
        if actual_port is None:
            return False
        if isinstance(rule_port, list):
            return actual_port in rule_port
        return actual_port == rule_port

    def _match_ports(self, rule: SignatureRule, packet: Packet) -> bool:
        """src_port/dst_port 매칭."""
        sport: int | None = None
        dport: int | None = None
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        if not self._match_port(rule.src_port, sport):
            return False
        if not self._match_port(rule.dst_port, dport):
            return False
        return True

    def _match_flags(self, rule: SignatureRule, packet: Packet) -> bool:
        """TCP 플래그 매칭."""
        if not rule.flags:
            return True
        if not packet.haslayer(TCP):
            return False
        tcp_flags = int(packet[TCP].flags)
        return bool(tcp_flags & rule._flags_mask)

    def _match_content(self, rule: SignatureRule, payload: bytes) -> bool:
        """Content 패턴 매칭 (모든 패턴이 payload에 존재해야 함)."""
        if not rule.content:
            return True
        if not payload:
            return False

        if rule.content_nocase:
            payload_lower = payload.lower()
            return all(c in payload_lower for c in rule._content_lower)
        return all(c in payload for c in rule.content)

    _MAX_REGEX_SCAN_SIZE = 65536  # 64 KB payload limit for regex scan

    def _match_regex(self, rule: SignatureRule, payload: bytes) -> bool:
        """Regex 패턴 매칭.

        안전한 정규식 패턴이라도 큰 페이로드에서의 과도한 CPU 사용을
        방지하기 위해 스캔 페이로드 크기를 제한한다.
        """
        if rule.regex is None:
            return True
        if not payload:
            return False
        # 과도한 스캔 시간 방지를 위해 페이로드 잘라내기
        data = payload[:self._MAX_REGEX_SCAN_SIZE]
        return rule.regex.search(data) is not None

    def _get_group_key(self, rule: SignatureRule, packet: Packet) -> str:
        """Threshold 그룹 키 추출."""
        by_field = rule.threshold.get("by", "src_ip") if rule.threshold else "src_ip"
        src_ip, dst_ip = get_ip_addrs(packet)
        if by_field == "src_ip":
            return src_ip or "unknown"
        if by_field == "dst_ip":
            return dst_ip or "unknown"
        if by_field == "pair":
            return f"{src_ip or 'unknown'}->{dst_ip or 'unknown'}"
        return src_ip or "unknown"

    def _check_threshold(self, rule: SignatureRule, group_key: str, now: float) -> bool:
        """Threshold 조건 검사. 조건 충족 시 True 반환 후 카운터 리셋."""
        if not rule.threshold:
            return True  # threshold 없으면 즉시 매칭

        count_limit = rule.threshold["count"]
        window = rule.threshold["seconds"]
        key = (rule.id, group_key)

        if key not in self._threshold_counters:
            self._threshold_counters[key] = deque()

        dq = self._threshold_counters[key]
        # 만료된 엔트리 제거
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

        dq.append(now)

        if len(dq) >= count_limit:
            # Threshold 충족: 카운터 리셋
            dq.clear()
            return True
        return False

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷을 모든 활성 규칙에 대해 매칭. 첫 번째 매칭 규칙에서 Alert 반환."""
        if not self._rules:
            return None

        # 공통 필드 사전 추출
        src_ip, dst_ip = get_ip_addrs(packet)

        # 원시 페이로드 추출
        payload: bytes = b""
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)

        now = time.time()

        for rule in self._rules:
            if not rule.enabled:
                continue

            # 1. 프로토콜 매칭
            if not self._match_protocol(rule, packet):
                continue

            # 2. IP 매칭
            if not self._match_ip(rule, src_ip, dst_ip):
                continue

            # 3. 포트 매칭
            if not self._match_ports(rule, packet):
                continue

            # 4. TCP 플래그 매칭
            if not self._match_flags(rule, packet):
                continue

            # 5. Content 매칭
            if not self._match_content(rule, payload):
                continue

            # 6. Regex 매칭
            if not self._match_regex(rule, payload):
                continue

            # 7. Threshold 검사
            if rule.threshold:
                group_key = self._get_group_key(rule, packet)
                if not self._check_threshold(rule, group_key, now):
                    continue  # Threshold 미충족

            # 모든 조건 매칭됨
            return Alert(
                engine=self.name,
                severity=rule.severity,
                title=f"[{rule.id}] {rule.name}",
                description=(
                    f"Signature rule matched: {rule.name} "
                    f"(src={src_ip}, dst={dst_ip})"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.8,
                metadata={
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "confidence": 0.8,
                },
            )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적 처리: threshold 카운터 정리 + hot-reload 체크."""
        alerts: list[Alert] = []

        # 만료된 threshold 카운터 정리
        now = time.time()
        expired_keys = []
        for key, dq in self._threshold_counters.items():
            rule_id = key[0]
            rule = self._rules_by_id.get(rule_id)
            if rule and rule.threshold:
                cutoff = now - rule.threshold["seconds"]
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    expired_keys.append(key)
            else:
                expired_keys.append(key)
        for key in expired_keys:
            del self._threshold_counters[key]

        # 핫 리로드 검사
        if self._hot_reload:
            current_mtime = self._get_dir_mtime()
            if current_mtime > self._last_dir_mtime:
                logger.info("Rules directory changed, reloading...")
                self.reload_rules()

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 리소스 해제."""
        self._rules.clear()
        self._rules_by_id.clear()
        self._threshold_counters.clear()
