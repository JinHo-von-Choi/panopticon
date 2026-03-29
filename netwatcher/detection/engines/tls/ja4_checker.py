"""JA4 해시 매칭 검사기.

TLS ClientHello의 JA4 핑거프린트를 차단 목록과 매칭한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.detection.engines.tls.engine import TLSFingerprintEngine


class JA4Checker:
    """JA4 해시 기반 악성 TLS 클라이언트 탐지."""

    def __init__(self, engine: TLSFingerprintEngine) -> None:
        self._engine = engine

    def check(
        self,
        ja4_hash: str | None,
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """JA4 해시를 차단 목록과 매칭한다.

        Returns:
            매칭되면 CRITICAL Alert, 아니면 None.
        """
        if not ja4_hash or ja4_hash not in self._engine._blocked_ja4:
            return None

        if self._engine.is_whitelisted(source_ip=src_ip):
            return None

        malware_name = self._engine._ja4_to_malware.get(ja4_hash, "Unknown")
        return Alert(
            engine=self._engine.name,
            severity=Severity.CRITICAL,
            title="Malicious TLS Fingerprint (JA4 Match)",
            title_key="engines.tls_fingerprint.alerts.ja4_match.title",
            description=(
                f"TLS ClientHello matches known malware JA4 fingerprint: "
                f"{ja4_hash} (malware: {malware_name})"
            ),
            description_key="engines.tls_fingerprint.alerts.ja4_match.description",
            source_ip=src_ip,
            dest_ip=dst_ip,
            confidence=0.92,
            metadata={
                "ja4_hash": ja4_hash,
                "malware": malware_name,
            },
        )
