"""시그니처 기반 탐지: YARA 규칙, 사용자 정의 패턴 매칭."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from scapy.all import Packet, TCP, UDP

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.analysis.yara_scanner import YaraScanner

logger = logging.getLogger("netwatcher.detection.engines.signature")


class SignatureEngine(DetectionEngine):
    """패킷 페이로드를 시그니처 및 YARA 규칙과 대조하여 탐지한다.

    - Content Matching: 특정 텍스트 패턴(SQLi, XSS 등) 매칭
    - YARA Rules: 복잡한 바이너리 패턴 및 악성코드 시그니처 매칭
    """

    name = "signature"
    description = "시그니처 기반 탐지를 수행합니다. YARA 규칙 및 사용자 정의 패턴을 사용하여 알려진 공격 도구 및 악성 페이로드를 식별합니다."
    description_key = "engines.signature.description"
    config_schema = {
        "enable_yara": {
            "type": bool, "default": True,
            "label": "YARA 활성화",
            "label_key": "engines.signature.enable_yara.label",
            "description": "YARA 엔진을 사용하여 정밀한 패턴 매칭을 수행합니다.",
            "description_key": "engines.signature.enable_yara.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다. YARA 스캐너는 외부에서 주입받는다."""
        super().__init__(config)
        self._yara_scanner: YaraScanner | None = None
        self._enable_yara = config.get("enable_yara", True)

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

        return None
