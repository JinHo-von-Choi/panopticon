"""TLS 인증서 분석 검사기.

TLS Certificate 메시지에서 인증서 정보를 추출하고,
SNI 불일치, 만료, 자체 서명, 단기 유효 등의 이상을 탐지한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from scapy.all import Packet

from netwatcher.detection.engines.tls.helpers import (
    _cert_matches_hostname,
    _parse_x509_time,
    _x509_name_to_str,
)
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.tls_fingerprint")


class CertChecker:
    """TLS 인증서 이상 탐지."""

    def __init__(
        self,
        engine_name: str,
        sni_cache: OrderedDict[tuple[str | None, str | None], str],
    ) -> None:
        self._engine_name = engine_name
        self._sni_cache   = sni_cache

    def check(
        self,
        packet: Packet,
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """패킷에서 인증서를 추출하여 이상 여부를 분석한다.

        Returns:
            이상 발견 시 Alert, 아니면 None.
        """
        cert_info = self._extract_cert_info(packet)
        if cert_info is None:
            return None
        return self._analyze_certificate(cert_info, src_ip, dst_ip)

    @staticmethod
    def _extract_cert_info(packet: Packet) -> dict[str, Any] | None:
        """TLS Certificate 메시지에서 인증서 정보를 추출한다.

        Scapy의 TLS 레이어에서 인증서 파싱을 시도한다.
        subject, issuer, not_before, not_after, serial, san_list 키를 가진
        dict를 반환한다. 인증서를 추출할 수 없으면 None을 반환한다.
        """
        try:
            from scapy.layers.tls.handshake import TLSCertificate

            if not packet.haslayer(TLSCertificate):
                return None

            tls_cert_layer = packet[TLSCertificate]

            # TLSCertificate.certs는 Cert 객체 리스트 (Scapy >= 2.5)
            certs = getattr(tls_cert_layer, "certs", None)
            if not certs:
                return None

            # 첫 번째 인증서가 서버(리프) 인증서
            leaf = certs[0]

            # Scapy는 원시 인증서를 Cert()/X509Cert로 래핑 -- 여러 접근 패턴 시도
            cert_obj = leaf
            # 일부 Scapy 버전은 중첩: certs[0].cert가 실제 X.509 객체
            if hasattr(leaf, "cert"):
                cert_obj = leaf.cert

            subject = _x509_name_to_str(getattr(cert_obj, "subject", None))
            issuer  = _x509_name_to_str(getattr(cert_obj, "issuer", None))

            not_before = _parse_x509_time(getattr(cert_obj, "notBefore", None))
            not_after  = _parse_x509_time(getattr(cert_obj, "notAfter", None))
            serial     = getattr(cert_obj, "serial", None)

            # 주체 대체 이름 (SAN)
            san_list: list[str] = []
            extensions = getattr(cert_obj, "extensions", None) or []
            for ext in extensions:
                ext_oid = getattr(ext, "oid", None)
                # OID 2.5.29.17 = subjectAltName
                if ext_oid and str(ext_oid) == "2.5.29.17":
                    san_value = getattr(ext, "value", None)
                    if isinstance(san_value, (list, tuple)):
                        san_list.extend(str(v) for v in san_value)
                    elif isinstance(san_value, str):
                        san_list.append(san_value)

            return {
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "serial": serial,
                "san_list": san_list,
            }

        except ImportError:
            logger.debug(
                "Scapy TLS certificate layer not available; skipping cert extraction"
            )
            return None
        except Exception:
            logger.debug("Failed to extract certificate info", exc_info=True)
            return None

    def _analyze_certificate(
        self,
        cert_info: dict[str, Any],
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """추출된 인증서의 이상 여부를 분석한다.

        검사 항목 (우선순위 순):
        1. SNI 불일치 -- 인증서 CN/SAN이 이전 관측된 SNI와 불일치.
           (CRITICAL, 신뢰도 0.85)
        2. 만료된 인증서 -- not_after가 과거. (WARNING, 0.7)
        3. 자체 서명 -- 발급자와 주체가 동일. (WARNING, 0.6)
        4. 단기 유효 -- 유효 기간 30일 미만. (INFO, 0.4)

        발견된 최고 우선순위 Alert를 반환하거나, 없으면 None을 반환한다.
        """
        subject   = cert_info.get("subject") or ""
        issuer    = cert_info.get("issuer") or ""
        not_before: datetime | None = cert_info.get("not_before")
        not_after:  datetime | None = cert_info.get("not_after")
        san_list: list[str] = cert_info.get("san_list") or []

        now = datetime.now(timezone.utc)

        # --- SNI 불일치 (최고 우선순위) ---
        # 서버->클라이언트 패킷에서 src_ip는 서버, dst_ip는 클라이언트.
        # SNI 캐시 키는 (client_ip, server_ip).
        flow_key = (dst_ip, src_ip)
        cached_sni = self._sni_cache.get(flow_key)
        if cached_sni:
            if not _cert_matches_hostname(cached_sni, subject, san_list):
                return Alert(
                    engine=self._engine_name,
                    severity=Severity.CRITICAL,
                    title="TLS Certificate SNI Mismatch",
                    description=(
                        f"Certificate subject '{subject}' and SANs {san_list} "
                        f"do not match expected SNI '{cached_sni}'"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.85,
                    metadata={
                        "expected_sni": cached_sni,
                        "cert_subject": subject,
                        "cert_san_list": san_list,
                    },
                )

        # --- 만료된 인증서 ---
        if not_after is not None and not_after < now:
            return Alert(
                engine=self._engine_name,
                severity=Severity.WARNING,
                title="Expired TLS Certificate",
                description=(
                    f"Certificate for '{subject}' expired on "
                    f"{not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.7,
                metadata={
                    "cert_subject": subject,
                    "not_after": not_after.isoformat(),
                },
            )

        # --- 자체 서명 인증서 ---
        if subject and issuer and subject == issuer:
            return Alert(
                engine=self._engine_name,
                severity=Severity.WARNING,
                title="Self-Signed TLS Certificate",
                description=(
                    f"Certificate for '{subject}' is self-signed "
                    f"(issuer equals subject)"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.6,
                metadata={
                    "cert_subject": subject,
                    "cert_issuer": issuer,
                },
            )

        # --- 단기 유효 인증서 (유효 기간 30일 미만) ---
        if not_before is not None and not_after is not None:
            validity_days = (not_after - not_before).total_seconds() / 86400
            if validity_days < 30:
                return Alert(
                    engine=self._engine_name,
                    severity=Severity.INFO,
                    title="Short-Lived TLS Certificate",
                    description=(
                        f"Certificate for '{subject}' has a validity period of "
                        f"{validity_days:.1f} days (threshold: 30 days)"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.4,
                    metadata={
                        "cert_subject": subject,
                        "validity_days": round(validity_days, 1),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                    },
                )

        return None
