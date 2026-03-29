"""TLS 핑거프린트 공용 유틸리티.

GREASE 필터링, X.509 인증서 헬퍼, JA3/JA3S/JA4 해시 계산,
SNI 추출 등 TLS 분석에 필요한 독립 함수를 모은다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("netwatcher.detection.engines.tls_fingerprint")

# RFC 8701에 정의된 GREASE 값 -- JA3 계산에서 필터링 필요
_GREASE_VALUES: frozenset[int] = frozenset({
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
    0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
    0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
})


def _is_grease(val: int) -> bool:
    """값이 GREASE 플레이스홀더인지 확인한다."""
    return val in _GREASE_VALUES


# ------------------------------------------------------------------
# X.509 인증서 헬퍼 유틸리티
# ------------------------------------------------------------------

def _x509_name_to_str(name: Any) -> str:
    """X.509 Name 객체를 사람이 읽을 수 있는 문자열로 변환한다.

    Scapy의 X509 RDN 시퀀스, 일반 문자열, bytes를 처리한다.
    실패 시 빈 문자열을 반환한다.
    """
    if name is None:
        return ""
    if isinstance(name, str):
        return name
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace")
    # Scapy X509_RDN 리스트: __repr__를 호출하는 str() 시도
    try:
        return str(name)
    except Exception:
        return ""


def _parse_x509_time(raw: Any) -> datetime | None:
    """X.509 시간 필드를 타임존 인식 datetime으로 파싱한다.

    일반적인 ASN.1 시간 형식을 시도한다: UTCTime 및 GeneralizedTime.
    파싱 실패 시 None을 반환한다.
    """
    if raw is None:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw

    raw_str = str(raw).strip()
    for fmt in (
        "%y%m%d%H%M%SZ",      # UTCTime: YYMMDDHHMMSSZ
        "%Y%m%d%H%M%SZ",      # 일반화 시간 형식: YYYYMMDDHHMMSSZ
        "%y%m%d%H%M%S",       # UTCTime without trailing Z
        "%Y%m%d%H%M%S",       # 끝 Z 없는 일반화 시간 형식
        "%Y-%m-%dT%H:%M:%S",  # ISO 8601
        "%Y-%m-%dT%H:%M:%SZ", # ISO 8601 with Z
    ):
        try:
            dt = datetime.strptime(raw_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _cert_matches_hostname(hostname: str, subject: str, san_list: list[str]) -> bool:
    """*hostname*이 인증서 subject CN 또는 SAN 항목과 일치하는지 확인한다.

    단순 와일드카드 매칭을 지원한다 (예: ``*.example.com``).
    모든 비교는 대소문자를 구분하지 않는다.
    """
    hostname_lower = hostname.lower().strip()

    # SAN 먼저 확인 (RFC 6125: SAN이 CN보다 우선)
    for san in san_list:
        if _hostname_matches_pattern(hostname_lower, san.lower().strip()):
            return True

    # subject 문자열에서 추출한 CN으로 폴백.
    cn = _extract_cn(subject)
    if cn and _hostname_matches_pattern(hostname_lower, cn.lower().strip()):
        return True

    return False


def _hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    """선행 와일드카드를 포함할 수 있는 패턴에 대해 hostname을 매칭한다."""
    if hostname == pattern:
        return True
    # 와일드카드: *.example.com은 foo.example.com 및 example.com과 매칭
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        # hostname은 접미사 앞에 최소 하나의 라벨이 있어야 함
        if hostname.endswith(suffix) and len(hostname) > len(suffix):
            return True
        # 도메인 자체도 매칭 (*.example.com -> example.com)
        if hostname == pattern[2:]:
            return True
    return False


def _extract_cn(subject: str) -> str:
    """X.509 subject 문자열에서 Common Name (CN) 값을 추출한다.

    쉼표/슬래시로 구분된 RDN 내의 ``CN=example.com`` 형식을 처리한다.
    """
    for part in subject.replace("/", ",").split(","):
        part = part.strip()
        upper = part.upper()
        if upper.startswith("CN=") or upper.startswith("CN ="):
            return part.split("=", 1)[1].strip()
    return ""


def _ja4_tls_version(version: int) -> str:
    """TLS 버전 필드를 JA4 2자리 버전 문자열로 매핑한다."""
    _VERSION_MAP = {
        0x0301: "10",  # TLS 1.0
        0x0302: "11",  # TLS 1.1
        0x0303: "12",  # TLS 1.2
        0x0304: "13",  # TLS 1.3
    }
    return _VERSION_MAP.get(version, "00")


def _ja4_sni_indicator(client_hello) -> str:
    """JA4 part_a용 SNI 지표를 결정한다.

    도메인 SNI가 있으면 'd', SNI가 IP 주소면 'i', SNI가 없으면 'x'를 반환한다.
    """
    import ipaddress as _ipaddress

    sni = extract_sni(client_hello)
    if not sni:
        return "x"
    try:
        _ipaddress.ip_address(sni)
        return "i"
    except ValueError:
        return "d"


def _ja4_first_alpn(client_hello) -> str:
    """JA4용 첫 번째 ALPN 프로토콜 값의 앞 2자를 추출한다.

    ALPN 확장이 없으면 '00'을 반환한다.
    """
    try:
        if not client_hello.ext:
            return "00"
        for ext in client_hello.ext:
            ext_type = getattr(ext, "type", None)
            if ext_type is not None and int(ext_type) == 16:
                protocols = getattr(ext, "protocols", None)
                if protocols:
                    first = protocols[0]
                    # ProtocolName 객체 또는 bytes
                    if hasattr(first, "protocol"):
                        val = first.protocol
                    else:
                        val = first
                    if isinstance(val, bytes):
                        val = val.decode("ascii", errors="replace")
                    val = str(val)
                    return (val[:2] if len(val) >= 2 else val.ljust(2, "0"))
        return "00"
    except Exception:
        return "00"


def _ja4_extract_sig_algs(client_hello) -> list[int]:
    """ClientHello 확장 타입 13에서 서명 알고리즘을 추출한다.

    정렬된 정수 서명 알고리즘 값 목록을 반환한다.
    """
    try:
        if not client_hello.ext:
            return []
        for ext in client_hello.ext:
            ext_type = getattr(ext, "type", None)
            if ext_type is not None and int(ext_type) == 13:
                sig_algs = getattr(ext, "sig_algs", None)
                if sig_algs:
                    result = []
                    for sa in sig_algs:
                        val = sa if isinstance(sa, int) else int(sa)
                        if not _is_grease(val):
                            result.append(val)
                    return sorted(result)
        return []
    except Exception:
        return []


def compute_ja4(client_hello) -> str | None:
    """TLS ClientHello 레이어에서 JA4 핑거프린트를 계산한다.

    JA4 형식: ``{part_a}_{part_b}_{part_c}``

    * **part_a** (10자): 프로토콜 + TLS 버전 + SNI 지표 + 암호 스위트 수
      (2자리) + 확장 수 (2자리) + 첫 번째 ALPN (2자)
    * **part_b** (12 hex): 정렬된 GREASE 제외 암호 스위트 목록의 SHA256 앞 12자
    * **part_c** (12 hex): 정렬된 GREASE 제외 확장 목록 + 언더스코어 +
      정렬된 서명 알고리즘 목록의 SHA256 앞 12자
    """
    try:
        version = client_hello.version
        if version is None:
            return None

        # --- Part a ---
        proto = "t"  # TCP (이 엔진에서는 항상 TCP)
        tls_ver = _ja4_tls_version(version)
        sni_ind = _ja4_sni_indicator(client_hello)

        # 암호 스위트 - GREASE 필터링
        ciphers: list[int] = []
        for cs in (client_hello.ciphers or []):
            val = cs if isinstance(cs, int) else int(cs)
            if not _is_grease(val):
                ciphers.append(val)

        # 확장 - GREASE 필터링
        ext_types: list[int] = []
        if client_hello.ext:
            for ext in client_hello.ext:
                ext_type = getattr(ext, "type", None)
                if ext_type is None:
                    continue
                ext_val = ext_type if isinstance(ext_type, int) else int(ext_type)
                if not _is_grease(ext_val):
                    ext_types.append(ext_val)

        cipher_count = f"{min(len(ciphers), 99):02d}"
        ext_count = f"{min(len(ext_types), 99):02d}"
        first_alpn = _ja4_first_alpn(client_hello)

        part_a = f"{proto}{tls_ver}{sni_ind}{cipher_count}{ext_count}{first_alpn}"

        # --- Part b: 정렬된 암호 스위트의 SHA256 ---
        sorted_ciphers = sorted(ciphers)
        ciphers_str = ",".join(str(c) for c in sorted_ciphers)
        part_b = hashlib.sha256(ciphers_str.encode()).hexdigest()[:12]

        # --- Part c: 정렬된 확장 + 정렬된 서명 알고리즘의 SHA256 ---
        sorted_exts = sorted(ext_types)
        exts_str = ",".join(str(e) for e in sorted_exts)
        sig_algs = _ja4_extract_sig_algs(client_hello)
        sig_algs_str = ",".join(str(s) for s in sig_algs)
        part_c_input = f"{exts_str}_{sig_algs_str}"
        part_c = hashlib.sha256(part_c_input.encode()).hexdigest()[:12]

        return f"{part_a}_{part_b}_{part_c}"

    except Exception:
        logger.debug("Failed to compute JA4 fingerprint", exc_info=True)
        return None


def compute_ja3(client_hello) -> str | None:
    """TLS ClientHello 레이어에서 JA3 해시를 계산한다.

    JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
    필드는 쉼표로 구분하고, 필드 내 값은 대시로 연결한다.
    GREASE 값은 필터링한다.
    """
    try:
        # TLS 버전
        version = client_hello.version
        if version is None:
            return None

        # 암호 스위트 -- GREASE 필터링
        ciphers = []
        for cs in (client_hello.ciphers or []):
            val = cs if isinstance(cs, int) else int(cs)
            if not _is_grease(val):
                ciphers.append(str(val))

        # 확장, 타원 곡선, EC 포인트 형식
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        if client_hello.ext:
            for ext in client_hello.ext:
                ext_type = ext.type if hasattr(ext, "type") else None
                if ext_type is None:
                    continue
                ext_val = ext_type if isinstance(ext_type, int) else int(ext_type)
                if _is_grease(ext_val):
                    continue
                extensions.append(str(ext_val))

                # Supported Groups (타원 곡선) -- 확장 타입 10
                if ext_val == 10 and hasattr(ext, "groups"):
                    for g in ext.groups:
                        gv = g if isinstance(g, int) else int(g)
                        if not _is_grease(gv):
                            elliptic_curves.append(str(gv))

                # EC 포인트 형식 -- 확장 타입 11
                if ext_val == 11 and hasattr(ext, "ecpl"):
                    for p in ext.ecpl:
                        pv = p if isinstance(p, int) else int(p)
                        if not _is_grease(pv):
                            ec_point_formats.append(str(pv))

        ja3_str = ",".join([
            str(version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(elliptic_curves),
            "-".join(ec_point_formats),
        ])

        return hashlib.md5(ja3_str.encode()).hexdigest()

    except Exception:
        logger.debug("Failed to compute JA3 hash", exc_info=True)
        return None


def compute_ja3s(server_hello) -> str | None:
    """TLS ServerHello 레이어에서 JA3S 해시를 계산한다.

    JA3S = MD5(SSLVersion,Cipher,Extensions)
    단일 암호 스위트 (리스트 아님), 확장은 대시로 연결한다.
    GREASE 값은 필터링한다.
    """
    try:
        version = server_hello.version
        if version is None:
            return None

        # 암호 스위트 -- 단일 값, 리스트 아님
        cipher = server_hello.cipher
        if cipher is None:
            return None
        cipher_val = cipher if isinstance(cipher, int) else int(cipher)

        # 확장 -- GREASE 필터링
        extensions = []
        if server_hello.ext:
            for ext in server_hello.ext:
                ext_type = getattr(ext, "type", None)
                if ext_type is None:
                    continue
                ext_val = ext_type if isinstance(ext_type, int) else int(ext_type)
                if _is_grease(ext_val):
                    continue
                extensions.append(str(ext_val))

        ja3s_str = ",".join([
            str(version),
            str(cipher_val),
            "-".join(extensions),
        ])

        return hashlib.md5(ja3s_str.encode()).hexdigest()

    except Exception:
        logger.debug("Failed to compute JA3S hash", exc_info=True)
        return None


def extract_sni(client_hello) -> str | None:
    """TLS ClientHello에서 Server Name Indication(SNI)을 추출한다."""
    try:
        if not client_hello.ext:
            return None
        # ServerName 확장 검색 (타입 0)
        for ext in client_hello.ext:
            ext_type = getattr(ext, "type", None)
            if ext_type is not None and int(ext_type) == 0:
                # TLS_Ext_ServerName
                servernames = getattr(ext, "servernames", None)
                if servernames:
                    sn = servernames[0]
                    name = getattr(sn, "servername", None)
                    if name:
                        if isinstance(name, bytes):
                            return name.decode("utf-8", errors="ignore")
                        return str(name)
        return None
    except Exception:
        logger.debug("Failed to extract SNI", exc_info=True)
        return None
