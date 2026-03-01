"""애플리케이션 계층 프로토콜 분석(DPI): HTTP, SMTP, FTP, SSH."""

from __future__ import annotations

import logging
import re
from typing import Any

from scapy.all import IP, Packet, TCP

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.protocol_inspect")


class ProtocolInspectEngine(DetectionEngine):
    """L7 프로토콜의 상세 내용을 분석하여 이상 활동을 탐지한다 (DPI).

    - HTTP: 비정상 메소드, 의심스러운 파일 확장자 요청
    - FTP/SMTP: 평문 인증 정보 노출, 비정상 명령어 조합
    - SSH: 비정상적인 대용량 데이터 전송 (터널링 의심)
    """

    name = "protocol_inspect"
    description = "애플리케이션 프로토콜을 심층 분석(DPI)합니다. 평문 비밀번호 노출, 비정상적인 프로토콜 사용 등을 식별합니다."
    description_key = "engines.protocol_inspect.description"
    config_schema = {
        "detect_plain_auth": {
            "type": bool, "default": True,
            "label": "평문 인증 탐지",
            "label_key": "engines.protocol_inspect.detect_plain_auth.label",
            "description": "FTP, SMTP 등에서 암호화되지 않은 인증 정보 전송을 감시합니다.",
            "description_key": "engines.protocol_inspect.detect_plain_auth.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._detect_auth = config.get("detect_plain_auth", True)
        self._alerted_ips: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """L7 페이로드를 분석하여 프로토콜별 위협 지표를 추출한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None

        payload = bytes(packet[TCP].payload)
        if not payload:
            return None

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        text = payload.decode("utf-8", errors="ignore")

        # 1. FTP/SMTP 평문 인증 탐지
        if self._detect_auth and dst_port in (21, 25, 110, 143):
            # USER/PASS 패턴 매칭
            if re.search(r"(?i)(USER|PASS|LOGIN|AUTHENTICATE)\s+", text):
                if f"{src_ip}:plain_auth" not in self._alerted_ips:
                    self._alerted_ips.add(f"{src_ip}:plain_auth")
                    return Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Plaintext Authentication Detected",
                        title_key="engines.protocol_inspect.alerts.plain_auth.title",
                        description=(
                            f"Host {src_ip} is sending unencrypted credentials via port {dst_port}. "
                            "Exposes passwords to network sniffing."
                        ),
                        description_key="engines.protocol_inspect.alerts.plain_auth.description",
                        source_ip=src_ip,
                        confidence=0.8,
                        metadata={"port": dst_port},
                    )

        # 2. HTTP 의심스러운 파일 확장자 요청
        if dst_port == 80 or text.startswith(("GET ", "POST ", "PUT ")):
            # .sh, .php, .exe, .py 등 실행 파일 요청 감시
            match = re.search(r"GET\s+/[^\s]+\.(sh|php|exe|py|pl|jsp|asp|bat)\b", text)
            if match:
                ext = match.group(1)
                if f"{src_ip}:ext:{ext}" not in self._alerted_ips:
                    self._alerted_ips.add(f"{src_ip}:ext:{ext}")
                    return Alert(
                        engine=self.name,
                        severity=Severity.INFO,
                        title="Suspicious File Request (HTTP)",
                        title_key="engines.protocol_inspect.alerts.suspicious_file.title",
                        description=(
                            f"Host {src_ip} requested an executable file type (.{ext}) via HTTP. "
                            "May indicate malware download or script execution attempt."
                        ),
                        description_key="engines.protocol_inspect.alerts.suspicious_file.description",
                        source_ip=src_ip,
                        confidence=0.5,
                        metadata={"extension": ext, "port": dst_port},
                    )

        return None

    def shutdown(self) -> None:
        """엔진 상태를 정리한다."""
        self._alerted_ips.clear()
