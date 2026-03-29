"""ESNI/ECH 탐지 검사기.

TLS ClientHello 확장에서 Encrypted Client Hello (ECH) 또는
레거시 ESNI 사용을 감지한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
from typing import Any

from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.tls_fingerprint")

# ECH 및 레거시 ESNI 확장 타입 ID
_EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
_EXT_LEGACY_ESNI            = 0xFFCE


class ESNIChecker:
    """ESNI/ECH 사용 탐지."""

    def __init__(self, engine_name: str) -> None:
        self._engine_name = engine_name

    def check(
        self,
        client_hello: Any,
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """ClientHello 확장에서 ECH 또는 레거시 ESNI 사용을 검사한다.

        ECH (0xFE0D) 또는 ESNI (0xFFCE) 확장이 감지되면 INFO 수준 알림을
        반환한다. 이는 정보성 알림으로 -- ECH는 서버 이름 가시성을 줄이지만
        본질적으로 악성은 아니다.
        """
        try:
            if not client_hello.ext:
                return None

            for ext in client_hello.ext:
                ext_type = getattr(ext, "type", None)
                if ext_type is None:
                    continue
                ext_val = ext_type if isinstance(ext_type, int) else int(ext_type)

                if ext_val == _EXT_ENCRYPTED_CLIENT_HELLO:
                    return Alert(
                        engine=self._engine_name,
                        severity=Severity.INFO,
                        title="ECH/ESNI Detected",
                        description=(
                            f"TLS ClientHello from {src_ip} contains Encrypted "
                            f"Client Hello (ECH) extension (0xFE0D), reducing "
                            f"SNI visibility"
                        ),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.3,
                        metadata={"extension_type": "ECH", "extension_id": 0xFE0D},
                    )

                if ext_val == _EXT_LEGACY_ESNI:
                    return Alert(
                        engine=self._engine_name,
                        severity=Severity.INFO,
                        title="ECH/ESNI Detected",
                        description=(
                            f"TLS ClientHello from {src_ip} contains legacy "
                            f"ESNI extension (0xFFCE), reducing SNI visibility"
                        ),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.3,
                        metadata={"extension_type": "ESNI", "extension_id": 0xFFCE},
                    )

        except Exception:
            logger.debug("Failed to check for ESNI/ECH extensions", exc_info=True)

        return None
