"""DNS 이상 탐지: DGA 도메인, DNS 터널링, 악성 도메인."""

from __future__ import annotations

import math
import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import DNS, DNSQR, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_src_ip

logger = logging.getLogger("netwatcher.detection.engines.dns_anomaly")

# 깊은 서브도메인을 흔히 가지는 정상 도메인
_SAFE_SUFFIXES = {
    "in-addr.arpa", "ip6.arpa", "local", "localhost",
    "internal", "corp", "lan", "home", "localdomain",
    # CDNs / Cloud
    "cloudfront.net", "amazonaws.com", "azure.com", "azurewebsites.net",
    "cloudflare.net", "cloudflare.com", "akamaized.net", "akamai.net",
    "fastly.net", "cdn.cloudflare.net", "edgekey.net", "edgesuite.net",
    "googleusercontent.com", "googleapis.com", "gstatic.com",
    "1e100.net",  # Google 내부
    # 서비스 디스커버리
    "_tcp", "_udp", "_tls",
    # 메일
    "protection.outlook.com", "_domainkey",
    # OS updates / telemetry
    "windowsupdate.com", "apple.com", "icloud.com",
    "ubuntu.com", "debian.org", "fedoraproject.org",
}

_VOWELS = set("aeiouAEIOU")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
_CONSONANTS_LOWER = set("bcdfghjklmnpqrstvwxyz")

# 발음 가능성 점수 산정용 일반적인 영어 바이그램
_COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
}


def _is_safe_domain(qname: str) -> bool:
    """도메인이 깊은 서브도메인의 알려진 안전 패턴과 일치하는지 확인한다."""
    lower = qname.lower()
    for suffix in _SAFE_SUFFIXES:
        if lower.endswith("." + suffix) or lower == suffix:
            return True
    # _로 시작하는 mDNS / 서비스 디스커버리 라벨
    if any(label.startswith("_") for label in lower.split(".")):
        return True
    return False


def _entropy(s: str) -> float:
    """문자열의 Shannon 엔트로피를 계산한다."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _consonant_vowel_ratio(s: str) -> float:
    """자음 대 모음 비율을 계산한다. 높은 비율은 DGA를 시사한다."""
    vowels = sum(1 for c in s if c in _VOWELS)
    consonants = sum(1 for c in s if c in _CONSONANTS)
    if vowels == 0:
        return float(consonants) if consonants > 0 else 0.0
    return consonants / vowels


def _pronounceability_score(s: str) -> float:
    """바이그램 빈도 기반으로 문자열의 발음 가능성을 점수화한다.

    0.0 (발음 불가) ~ 1.0 (매우 발음 가능) 범위를 반환한다.
    """
    s_lower = s.lower()
    if len(s_lower) < 2:
        return 1.0
    bigrams = [s_lower[i:i+2] for i in range(len(s_lower) - 1)]
    if not bigrams:
        return 1.0
    common_count = sum(1 for bg in bigrams if bg in _COMMON_BIGRAMS)
    bigram_ratio = common_count / len(bigrams)

    # 연속 자음 패널티: 3개 이상 연속 자음은 발음 불가 지표
    max_consonant_run = 0
    current_run = 0
    for c in s_lower:
        if c in _CONSONANTS_LOWER:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0
    consonant_penalty = max(0.0, (max_consonant_run - 2) * 0.15)

    return max(0.0, bigram_ratio - consonant_penalty)


def _dga_composite_score(label: str, entropy_threshold: float) -> float:
    """여러 신호를 결합한 복합 DGA 점수를 계산한다.

    0.0 ~ 1.0 범위의 신뢰도 값을 반환한다.
    """
    ent = _entropy(label)
    cv_ratio = _consonant_vowel_ratio(label)
    pronounce = _pronounceability_score(label)
    length_factor = min(len(label) / 20.0, 1.0)  # 길수록 의심

    # 가중 결합
    # 높은 엔트로피 → 의심 (완만한 곡선: threshold 근처에서 점진적 증가)
    entropy_score = max(0.0, min(1.0, (ent - entropy_threshold + 0.3) / 1.5))
    # 높은 자음 비율 → 의심 (정상 영어 ~1.5-2.0, DGA는 종종 >3)
    cv_score = max(0.0, min(1.0, (cv_ratio - 2.0) / 3.0))
    # 낮은 발음 가능성 → 의심
    unpronounceable_score = 1.0 - pronounce
    # 숫자 비율: DGA는 종종 숫자+문자 혼합
    digit_ratio = sum(1 for c in label if c.isdigit()) / len(label) if label else 0.0
    digit_score = min(1.0, digit_ratio * 3.0)  # 33% 이상 숫자면 1.0

    composite = (
        0.25 * entropy_score
        + 0.20 * cv_score
        + 0.30 * unpronounceable_score
        + 0.10 * length_factor
        + 0.15 * digit_score
    )
    return max(0.0, min(1.0, composite))


class DNSAnomalyEngine(DetectionEngine):
    """DNS 기반 위협을 탐지한다.

    - 엔트로피 + 복합 점수를 통한 DGA (Domain Generation Algorithm) 탐지
    - 비정상적으로 긴 라벨 / 깊은 서브도메인을 통한 DNS 터널링 탐지
    - 단일 호스트의 대량 쿼리 볼륨 탐지 (슬라이딩 윈도우)
    """

    name = "dns_anomaly"
    requires_span = True
    description = "DNS 터널링, DGA 도메인, 비정상 쿼리 패턴을 탐지합니다. DNS를 이용한 데이터 유출 및 C2 통신을 식별합니다."
    config_schema = {
        "max_label_length": {
            "type": int, "default": 50, "min": 10, "max": 253,
            "label": "최대 라벨 길이",
            "description": "DNS 라벨(서브도메인 구성요소) 길이가 이 값을 초과하면 DNS 터널링 의심 알림 발생. "
                           "정상 도메인은 보통 30자 미만.",
        },
        "max_subdomain_depth": {
            "type": int, "default": 7, "min": 3, "max": 20,
            "label": "최대 서브도메인 깊이",
            "description": "서브도메인 깊이(점으로 구분된 단계 수)가 이 값을 초과하면 알림 발생. "
                           "CDN/클라우드 도메인은 5~6단계가 정상일 수 있으므로 7 권장.",
        },
        "entropy_threshold": {
            "type": float, "default": 3.8, "min": 2.0, "max": 5.0,
            "label": "Shannon 엔트로피 임계값",
            "description": "DNS 라벨의 Shannon 엔트로피가 이 값을 초과하면 DGA(Domain Generation Algorithm) 의심. "
                           "높은 엔트로피 = 무작위 문자열. 낮추면 오탐 증가, 높이면 미탐 증가.",
        },
        "high_volume_threshold": {
            "type": int, "default": 200, "min": 10, "max": 10000,
            "label": "대량 쿼리 임계값",
            "description": "윈도우 내 단일 호스트의 DNS 쿼리 수가 이 값을 초과하면 알림 발생. "
                           "DNS 터널링이나 데이터 유출 시 대량 쿼리가 발생함.",
        },
        "high_volume_window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "대량 쿼리 윈도우(초)",
            "description": "DNS 쿼리 볼륨을 집계하는 시간 윈도우. "
                           "짧으면 순간 버스트 탐지, 길면 평균적 과다 사용 탐지.",
        },
        "dga_min_label_length": {
            "type": int, "default": 10, "min": 4, "max": 30,
            "label": "DGA 최소 라벨 길이",
            "description": "DGA 분석을 수행할 최소 라벨 길이. "
                           "짧은 라벨은 엔트로피 분석이 부정확하므로 10자 이상 권장.",
        },
        "dga_confidence_threshold": {
            "type": float, "default": 0.5, "min": 0.1, "max": 1.0,
            "label": "DGA 신뢰도 임계값",
            "description": "복합 DGA 점수(엔트로피+자음비율+길이)가 이 값을 초과하면 DGA로 판정. "
                           "낮추면 민감도 증가(오탐 증가), 높이면 확실한 DGA만 탐지.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._max_label_length = config.get("max_label_length", 50)
        self._max_subdomain_depth = config.get("max_subdomain_depth", 7)
        self._entropy_threshold = config.get("entropy_threshold", 3.8)
        self._high_volume_threshold = config.get("high_volume_threshold", 200)
        self._high_volume_window = config.get("high_volume_window_seconds", 60)
        self._dga_min_label_length = config.get("dga_min_label_length", 10)
        self._dga_confidence_threshold = config.get("dga_confidence_threshold", 0.5)

        # 출발지별 슬라이딩 윈도우 쿼리 추적: src_ip -> deque of timestamps
        self._query_timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._high_volume_alerted: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        dns = packet[DNS]
        if dns.qr != 0:  # 쿼리만 처리
            return None

        qname_raw = dns[DNSQR].qname
        if isinstance(qname_raw, bytes):
            qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
        else:
            qname = str(qname_raw).rstrip(".")

        if not qname:
            return None

        src_ip = get_src_ip(packet)

        # 슬라이딩 윈도우에서 쿼리 타임스탬프 추적
        if src_ip:
            now = time.time()
            self._query_timestamps[src_ip].append(now)

        # 알려진 안전 도메인 건너뛰기
        if _is_safe_domain(qname):
            return None

        # DNS 터널링 지표 검사
        labels = qname.split(".")
        subdomain_depth = len(labels)

        # 긴 라벨 검사 (터널링은 종종 라벨에 데이터를 인코딩함)
        for label in labels:
            if len(label) > self._max_label_length:
                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Possible DNS Tunneling (Long Label)",
                    description=(
                        f"DNS query with unusually long label ({len(label)} chars): "
                        f"{qname[:100]}"
                    ),
                    source_ip=src_ip,
                    confidence=0.8,
                    metadata={
                        "qname": qname,
                        "label_length": len(label),
                        "confidence": 0.8,
                    },
                )

        # 깊은 서브도메인 검사
        if subdomain_depth > self._max_subdomain_depth:
            return Alert(
                engine=self.name,
                severity=Severity.WARNING,
                title="Possible DNS Tunneling (Deep Subdomain)",
                description=(
                    f"DNS query with {subdomain_depth} subdomain levels: "
                    f"{qname[:100]}"
                ),
                source_ip=src_ip,
                confidence=0.7,
                metadata={
                    "qname": qname,
                    "depth": subdomain_depth,
                    "confidence": 0.7,
                },
            )

        # 최좌측 라벨에 대한 복합 점수를 통한 DGA 탐지
        if len(labels) >= 2:
            domain_part = labels[0]
            if len(domain_part) >= self._dga_min_label_length:
                ent = _entropy(domain_part)
                if ent > self._entropy_threshold:
                    confidence = _dga_composite_score(
                        domain_part, self._entropy_threshold
                    )
                    if confidence >= self._dga_confidence_threshold:
                        return Alert(
                            engine=self.name,
                            severity=Severity.WARNING,
                            title="Possible DGA Domain",
                            description=(
                                f"High-entropy domain name (entropy={ent:.2f}, "
                                f"confidence={confidence:.2f}): {qname}"
                            ),
                            source_ip=src_ip,
                            metadata={
                                "qname": qname,
                                "entropy": round(ent, 2),
                                "label": domain_part,
                                "confidence": round(confidence, 2),
                                "cv_ratio": round(
                                    _consonant_vowel_ratio(domain_part), 2
                                ),
                                "pronounceability": round(
                                    _pronounceability_score(domain_part), 2
                                ),
                            },
                        )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        alerts = []
        now = time.time()
        cutoff = now - self._high_volume_window

        keys_to_delete = []
        for src_ip, timestamps in self._query_timestamps.items():
            # 슬라이딩 윈도우 밖의 항목 제거
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if not timestamps:
                keys_to_delete.append(src_ip)
                continue

            count = len(timestamps)
            if (
                count > self._high_volume_threshold
                and src_ip not in self._high_volume_alerted
            ):
                conf = min(0.9, 0.5 + (count / self._high_volume_threshold - 1) * 0.2)
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="High Volume DNS Queries",
                    description=(
                        f"Host {src_ip} made {count} DNS queries in "
                        f"{self._high_volume_window}s window. "
                        "This may indicate DNS tunneling or malware activity."
                    ),
                    source_ip=src_ip,
                    confidence=conf,
                    metadata={
                        "query_count": count,
                        "window_seconds": self._high_volume_window,
                        "confidence": conf,
                    },
                ))
                self._high_volume_alerted.add(src_ip)

        for key in keys_to_delete:
            del self._query_timestamps[key]
            self._high_volume_alerted.discard(key)

        return alerts

    def shutdown(self) -> None:
        self._query_timestamps.clear()
        self._high_volume_alerted.clear()
