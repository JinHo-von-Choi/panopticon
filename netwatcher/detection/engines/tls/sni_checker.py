"""SNI 도메인 검사기.

TLS ClientHello의 SNI 필드를 도메인 차단 목록과 매칭하고,
인증서 불일치 탐지를 위해 SNI를 캐싱한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from netwatcher.detection.engines.tls.helpers import extract_sni
from netwatcher.detection.models import Alert, Severity

if TYPE_CHECKING:
    from netwatcher.detection.engines.tls.engine import TLSFingerprintEngine

# SNI 캐시 최대 항목 수 (플로우별 SNI 추적)
_SNI_CACHE_MAX = 5000


class SNIChecker:
    """SNI 도메인 기반 악성 TLS 접속 탐지."""

    def __init__(
        self,
        engine: TLSFingerprintEngine,
        sni_cache: OrderedDict[tuple[str | None, str | None], str],
    ) -> None:
        self._engine    = engine
        self._sni_cache = sni_cache

    def check(
        self,
        client_hello,
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """SNI를 추출하여 차단 목록과 매칭한다.

        SNI를 인증서 불일치 탐지용 캐시에도 저장한다.

        Returns:
            매칭되면 CRITICAL Alert, 아니면 None.
        """
        sni = extract_sni(client_hello)
        if not sni:
            return None

        # 인증서 CN/SAN 불일치 탐지를 위해 SNI 캐싱.
        # 키: (client_ip, server_ip)
        self._cache_sni(src_ip, dst_ip, sni)

        if self._engine.is_whitelisted(domain=sni):
            return None

        # 전체 도메인 및 상위 도메인 검사
        parts = sni.lower().split(".")
        for i in range(len(parts)):
            check_domain = ".".join(parts[i:])
            if check_domain in self._engine._blocked_domains:
                feed_name = None
                if self._engine._feed_manager:
                    feed_name = self._engine._feed_manager.get_feed_for_domain(
                        check_domain
                    )
                return Alert(
                    engine=self._engine.name,
                    severity=Severity.CRITICAL,
                    title="TLS Connection to Blocklisted Domain (SNI)",
                    title_key="engines.tls_fingerprint.alerts.sni_blocked.title",
                    description=(
                        f"TLS handshake to known malicious domain: {sni}"
                        + (f" (feed: {feed_name})" if feed_name else "")
                    ),
                    description_key="engines.tls_fingerprint.alerts.sni_blocked.description",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.95,
                    metadata={
                        "sni": sni,
                        "matched_domain": check_domain,
                        "feed": feed_name,
                    },
                )

        return None

    def _cache_sni(
        self, client_ip: str | None, server_ip: str | None, sni: str
    ) -> None:
        """(client, server) 플로우에 대해 관측된 SNI를 저장한다.

        ``_SNI_CACHE_MAX`` 항목으로 제한된 OrderedDict를 사용한다.
        제한을 초과하면 가장 오래된 항목을 제거한다.
        """
        key = (client_ip, server_ip)
        # 이미 존재하면 끝으로 이동 (LRU 갱신)
        if key in self._sni_cache:
            self._sni_cache.move_to_end(key)
        self._sni_cache[key] = sni
        # 용량 초과 시 가장 오래된 항목 제거
        max_size = getattr(self._engine, "_SNI_CACHE_MAX", _SNI_CACHE_MAX)
        while len(self._sni_cache) > max_size:
            self._sni_cache.popitem(last=False)
