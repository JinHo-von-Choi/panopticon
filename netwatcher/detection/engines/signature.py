"""시그니처 기반 탐지: YAML 규칙, Suricata 규칙, YARA 규칙, 사용자 정의 패턴 매칭."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from scapy.all import IP, Packet, TCP, UDP

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.engines.rule_matcher import RuleMatcher
from netwatcher.detection.engines.signature_rule import SignatureRule
from netwatcher.detection.engines.suricata_parser import load_rules_file as load_suricata_rules
from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.analysis.yara_scanner import YaraScanner

logger = logging.getLogger("netwatcher.detection.engines.signature")


class SignatureEngine(DetectionEngine):
    """패킷 페이로드를 시그니처 및 YARA 규칙과 대조하여 탐지한다.

    - YAML Rules: config/rules/ 디렉토리의 YAML 규칙 파일 로드
    - Suricata Rules: config/rules/ 디렉토리의 .rules 파일 로드
    - Content Matching: 특정 텍스트 패턴(SQLi, XSS 등) 매칭
    - YARA Rules: 복잡한 바이너리 패턴 및 악성코드 시그니처 매칭
    """

    name = "signature"
    description = "시그니처 기반 탐지를 수행합니다. YARA 규칙 및 사용자 정의 패턴을 사용하여 알려진 공격 도구 및 악성 페이로드를 식별합니다."
    description_key = "engines.signature.description"
    mitre_attack_ids = []
    config_schema = {
        "enable_yara": {
            "type": bool, "default": True,
            "label": "YARA 활성화",
            "label_key": "engines.signature.enable_yara.label",
            "description": "YARA 엔진을 사용하여 정밀한 패턴 매칭을 수행합니다.",
            "description_key": "engines.signature.enable_yara.description",
        },
        "rules_dir": {
            "type": str, "default": "config/rules",
            "label": "규칙 디렉토리",
            "label_key": "engines.signature.rules_dir.label",
            "description": "시그니처 규칙 파일이 위치한 디렉토리 경로",
            "description_key": "engines.signature.rules_dir.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다. YARA 스캐너는 외부에서 주입받는다."""
        super().__init__(config)
        self._yara_scanner: YaraScanner | None = None
        self._enable_yara = config.get("enable_yara", True)
        self._rules_dir: str | None = config.get("rules_dir")
        self._rules: list[SignatureRule] = []
        self._rules_by_id: dict[str, SignatureRule] = {}
        self._matcher = RuleMatcher()
        self._suricata_variables: dict[str, str] = config.get("suricata_variables", {})
        if self._rules_dir:
            self._load_rules()

    def _load_rules(self) -> None:
        """rules_dir 내 모든 YAML 및 .rules 파일에서 규칙을 로드한다."""
        rules_dir = Path(self._rules_dir)
        if not rules_dir.is_dir():
            logger.warning("Rules directory does not exist: %s", rules_dir)
            return
        loaded: list[SignatureRule] = []

        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if not data or "rules" not in data:
                    continue
                for rule_data in data["rules"]:
                    loaded.append(SignatureRule.from_dict(rule_data))
            except Exception:
                logger.exception("Failed to load rules from %s", yaml_file)

        for rules_file in sorted(rules_dir.glob("*.rules")):
            try:
                suricata_rules = load_suricata_rules(rules_file, self._suricata_variables)
                loaded.extend(suricata_rules)
            except Exception:
                logger.exception("Failed to load Suricata rules from %s", rules_file)

        self._rules = loaded
        self._rules_by_id = {r.id: r for r in loaded}
        logger.info("Loaded %d signature rules from %s", len(loaded), rules_dir)

    @property
    def rules(self) -> list[SignatureRule]:
        """로드된 전체 규칙 목록을 반환한다."""
        return self._rules

    @property
    def rules_by_id(self) -> dict[str, SignatureRule]:
        """규칙 ID를 키로 하는 딕셔너리를 반환한다."""
        return self._rules_by_id

    def reload_rules(self) -> None:
        """규칙 디렉토리를 재스캔하여 규칙을 다시 로드한다."""
        if self._rules_dir:
            self._load_rules()

    def set_yara_scanner(self, scanner: YaraScanner) -> None:
        """YARA 스캐너 인스턴스를 주입한다."""
        self._yara_scanner = scanner

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷 페이로드에서 시그니처를 검색한다."""
        if not packet.haslayer(TCP) and not packet.haslayer(UDP):
            return None

        payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
        if not payload:
            return None

        # 1. YARA 스캐닝
        if self._enable_yara and self._yara_scanner:
            matches = self._yara_scanner.scan_data(payload)
            if matches:
                match_names = [m.rule for m in matches]
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="YARA Signature Match",
                    title_key="engines.signature.alerts.yara_match.title",
                    description=(
                        f"Packet payload matched YARA rules: {', '.join(match_names)}. "
                        "Known malicious pattern or exploit tool detected."
                    ),
                    description_key="engines.signature.alerts.yara_match.description",
                    confidence=1.0,
                    metadata={"rules": match_names, "tags": [t for m in matches for t in m.tags]},
                )

        # 2. 시그니처 규칙 매칭
        for rule in self._rules:
            if not rule.enabled:
                continue
            if self._matcher.matches(rule, packet, payload):
                src_ip = packet[IP].src if packet.haslayer(IP) else None
                dst_ip = packet[IP].dst if packet.haslayer(IP) else None
                return Alert(
                    engine=self.name,
                    severity=rule.severity,
                    title=f"Signature Match: {rule.name}",
                    title_key="engines.signature.alerts.rule_match.title",
                    description=(
                        f"Packet matched signature rule [{rule.id}] {rule.name}."
                    ),
                    description_key="engines.signature.alerts.rule_match.description",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.9,
                    metadata={
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        **rule.metadata,
                    },
                )

        return None
