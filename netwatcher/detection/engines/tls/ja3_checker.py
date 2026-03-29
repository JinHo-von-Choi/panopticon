"""JA3 해시 매칭 검사기.

TLS ClientHello의 JA3 핑거프린트를 계산하여
알려진 악성코드 차단 목록과 매칭한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from netwatcher.detection.engines.tls.helpers import compute_ja3
from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.detection.engines.tls.engine import TLSFingerprintEngine


class JA3Checker:
    """JA3 해시 기반 악성 TLS 클라이언트 탐지."""

    def __init__(self, engine: TLSFingerprintEngine) -> None:
        self._engine = engine

    def check(
        self,
        client_hello,
        src_ip: str | None,
        dst_ip: str | None,
        ja4_hash: str | None = None,
    ) -> Alert | None:
        """JA3 해시를 계산하고 차단 목록과 매칭한다.

        Returns:
            매칭되면 CRITICAL Alert, 아니면 None.
        """
        ja3_hash = compute_ja3(client_hello)
        if not ja3_hash or ja3_hash not in self._engine._blocked_ja3:
            return None

        if self._engine.is_whitelisted(source_ip=src_ip):
            return None

        malware_name = self._engine._ja3_to_malware.get(ja3_hash, "Unknown")
        metadata: dict[str, Any] = {
            "ja3_hash": ja3_hash,
            "malware": malware_name,
        }
        if ja4_hash:
            metadata["ja4_hash"] = ja4_hash

        return Alert(
            engine=self._engine.name,
            severity=Severity.CRITICAL,
            title="Malicious TLS Fingerprint (JA3 Match)",
            title_key="engines.tls_fingerprint.alerts.ja3_match.title",
            description=(
                f"TLS ClientHello matches known malware JA3 fingerprint: "
                f"{ja3_hash} (malware: {malware_name})"
            ),
            description_key="engines.tls_fingerprint.alerts.ja3_match.description",
            source_ip=src_ip,
            dest_ip=dst_ip,
            confidence=0.90,
            metadata=metadata,
        )
