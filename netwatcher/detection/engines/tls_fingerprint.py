"""TLS 핑거프린트 탐지의 호환 진입점.

구현은 `netwatcher.detection.engines.tls` 패키지에 있다. 이 모듈은 기존
import 경로를 유지하기 위한 재수출 계층이며, 엔진 클래스를 여기서 다시
정의하지 않는다.

작성자: 최진호
수정일: 2026-07-27
"""

from __future__ import annotations

from netwatcher.detection.engines.tls.engine import TLSFingerprintEngine
from netwatcher.detection.engines.tls.helpers import (
    _cert_matches_hostname,
    _extract_cn,
    _hostname_matches_pattern,
    _is_grease,
    _ja4_extract_sig_algs,
    _ja4_first_alpn,
    _ja4_sni_indicator,
    _ja4_tls_version,
    _parse_x509_time,
    _x509_name_to_str,
    compute_ja3,
    compute_ja3s,
    compute_ja4,
    extract_sni,
)

__all__ = [
    "TLSFingerprintEngine",
    "compute_ja3",
    "compute_ja3s",
    "compute_ja4",
    "extract_sni",
    "_cert_matches_hostname",
    "_extract_cn",
    "_hostname_matches_pattern",
    "_is_grease",
    "_ja4_extract_sig_algs",
    "_ja4_first_alpn",
    "_ja4_sni_indicator",
    "_ja4_tls_version",
    "_parse_x509_time",
    "_x509_name_to_str",
]
