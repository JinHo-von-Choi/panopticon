"""파일 추출 탐지 엔진: 네트워크 트래픽에서 파일을 추출하여 악성코드 분석.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any

from scapy.all import IP, Packet, TCP, Raw

from netwatcher.analysis.file_carver import FileCarver
from netwatcher.analysis.extraction_pipeline import ExtractionPipeline
from netwatcher.analysis.hash_lookup import HashLookupClient
from netwatcher.analysis.yara_scanner import YaraScanner
from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.file_extraction")


class FileExtractionEngine(DetectionEngine):
    """네트워크 트래픽에서 파일을 추출하여 YARA 및 해시 기반 악성코드 분석을 수행한다."""

    name = "file_extraction"
    description = (
        "네트워크 트래픽에서 파일을 추출하여 YARA 및 해시 기반 악성코드 분석을 수행합니다."
    )
    description_key = "engines.file_extraction.description"
    requires_span   = True
    mitre_attack_ids = ["T1105", "T1071.001"]

    config_schema = {
        "enable_http_carving": {
            "type": bool, "default": True,
            "label": "HTTP 파일 추출",
            "label_key": "engines.file_extraction.enable_http_carving.label",
            "description": "HTTP 응답에서 파일을 추출합니다.",
            "description_key": "engines.file_extraction.enable_http_carving.description",
        },
        "enable_smtp_carving": {
            "type": bool, "default": True,
            "label": "SMTP 첨부 추출",
            "label_key": "engines.file_extraction.enable_smtp_carving.label",
            "description": "SMTP 트래픽에서 첨부 파일을 추출합니다.",
            "description_key": "engines.file_extraction.enable_smtp_carving.description",
        },
        "max_file_size_mb": {
            "type": int, "default": 10, "min": 1, "max": 100,
            "label": "최대 파일 크기(MB)",
            "label_key": "engines.file_extraction.max_file_size_mb.label",
            "description": "추출할 파일의 최대 크기(MB).",
            "description_key": "engines.file_extraction.max_file_size_mb.description",
        },
        "vt_api_key": {
            "type": str, "default": "",
            "label": "VirusTotal API 키",
            "label_key": "engines.file_extraction.vt_api_key.label",
            "description": "VirusTotal API v3 키. 비어 있으면 VT 조회를 건너뜁니다.",
            "description_key": "engines.file_extraction.vt_api_key.description",
        },
        "yara_rules_dir": {
            "type": str, "default": "config/yara",
            "label": "YARA 규칙 디렉토리",
            "label_key": "engines.file_extraction.yara_rules_dir.label",
            "description": "YARA 규칙 파일(.yar/.yara)이 위치한 디렉토리.",
            "description_key": "engines.file_extraction.yara_rules_dir.description",
        },
        "output_dir": {
            "type": str, "default": "data/extracted",
            "label": "추출 파일 저장 디렉토리",
            "label_key": "engines.file_extraction.output_dir.label",
            "description": "의심스러운 파일이 저장되는 디렉토리.",
            "description_key": "engines.file_extraction.output_dir.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        max_size_mb = config.get("max_file_size_mb", 10)
        output_dir  = config.get("output_dir", "data/extracted")

        self._enable_http = config.get("enable_http_carving", True)
        self._enable_smtp = config.get("enable_smtp_carving", True)

        self._carver = FileCarver(
            output_dir=output_dir,
            max_file_size=max_size_mb * 1_000_000,
        )

        self._yara_scanner = YaraScanner(
            rules_dir=config.get("yara_rules_dir", "config/yara"),
        )

        self._hash_client = HashLookupClient(
            vt_api_key=config.get("vt_api_key", ""),
            mb_enabled=True,
        )

        # 콜백 기반 알림 수집: on_tick()에서 반환
        self._pending_alerts: deque[Alert] = deque(maxlen=100)

        self._pipeline = ExtractionPipeline(
            yara_scanner=self._yara_scanner,
            hash_client=self._hash_client,
            alert_callback=self._on_pipeline_alert,
            output_dir=output_dir,
        )

        self._pipeline_started = False
        self._last_flush       = time.time()

    # ------------------------------------------------------------------
    # DetectionEngine 인터페이스
    # ------------------------------------------------------------------

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷에서 TCP 페이로드를 추출하여 파일 카버에 전달한다."""
        if not self.enabled:
            return None

        if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        ip  = packet[IP]
        tcp = packet[TCP]
        raw = packet[Raw].load

        if not raw:
            return None

        src_port = tcp.sport
        dst_port = tcp.dport

        # HTTP 포트 필터
        if self._enable_http and dst_port not in (80, 8080, 8443) and src_port not in (80, 8080, 8443):
            if not self._enable_smtp:
                return None
            # SMTP 포트 필터
            if dst_port not in (25, 587, 465) and src_port not in (25, 587, 465):
                return None

        extracted = self._carver.feed_packet(
            src_ip=ip.src,
            src_port=src_port,
            dst_ip=ip.dst,
            dst_port=dst_port,
            payload=raw,
        )

        if extracted:
            self._submit_to_pipeline(extracted)

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """만료된 스트림을 플러시하고 파이프라인 알림을 수집한다."""
        alerts: list[Alert] = []

        # 주기적 만료 스트림 플러시 (10초마다)
        if timestamp - self._last_flush > 10.0:
            self._last_flush = timestamp
            expired = self._carver.flush_expired(max_age=60.0)
            if expired:
                self._submit_to_pipeline(expired)

        # 파이프라인에서 축적된 알림 반환
        while self._pending_alerts:
            alerts.append(self._pending_alerts.popleft())

        return alerts

    def shutdown(self) -> None:
        """파이프라인을 중지한다."""
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop and self._pipeline_started:
            loop.create_task(self._pipeline.stop())

    # ------------------------------------------------------------------
    # 내부 메서드
    # ------------------------------------------------------------------

    def _submit_to_pipeline(self, files: list) -> None:
        """추출된 파일을 파이프라인에 제출한다."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        if not self._pipeline_started:
            loop.create_task(self._pipeline.start())
            self._pipeline_started = True

        for ef in files:
            loop.create_task(self._pipeline.submit(ef))

    def _on_pipeline_alert(self, alert_data: dict[str, Any]) -> None:
        """파이프라인에서 알림이 생성되면 호출된다."""
        severity_str = alert_data.get("severity", "WARNING")
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.WARNING

        alert = Alert(
            engine=self.name,
            severity=severity,
            title=alert_data.get("title", "Suspicious file detected"),
            description=alert_data.get("description", ""),
            source_ip=alert_data.get("source_ip"),
            dest_ip=alert_data.get("dest_ip"),
            mitre_attack_id="T1105",
            threat_level=2 if severity == Severity.CRITICAL else 1,
            metadata=alert_data.get("metadata", {}),
        )
        self._pending_alerts.append(alert)
