"""TLS 핑거프린트 탐지: JA3 해시 매칭, SNI 차단 목록, 인증서 분석."""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.tls_fingerprint")

# RFC 8701에 정의된 GREASE 값 — JA3 계산에서 필터링 필요
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

        # 암호 스위트 — GREASE 필터링
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

                # Supported Groups (타원 곡선) — 확장 타입 10
                if ext_val == 10 and hasattr(ext, "groups"):
                    for g in ext.groups:
                        gv = g if isinstance(g, int) else int(g)
                        if not _is_grease(gv):
                            elliptic_curves.append(str(gv))

                # EC 포인트 형식 — 확장 타입 11
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

        # 암호 스위트 — 단일 값, 리스트 아님
        cipher = server_hello.cipher
        if cipher is None:
            return None
        cipher_val = cipher if isinstance(cipher, int) else int(cipher)

        # 확장 — GREASE 필터링
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


class TLSFingerprintEngine(DetectionEngine):
    """JA3 핑거프린팅 및 SNI 차단 목록을 통해 악성 TLS 클라이언트를 탐지한다.

    - JA3: TLS ClientHello 구조의 MD5 해시를 계산하여 SSLBL 피드의
      알려진 악성코드 핑거프린트와 매칭한다.
    - SNI: ClientHello에서 평문 서버 이름을 추출하여 도메인 차단 목록과
      대조한다.
    """

    name = "tls_fingerprint"
    description = "TLS 핸드셰이크의 JA3/JA4 핑거프린트를 분석합니다. 알려진 악성 클라이언트, 자체서명 인증서, 의심스러운 암호화 설정을 탐지합니다."
    config_schema = {
        "check_ja3": {
            "type": bool, "default": True,
            "label": "JA3 핑거프린트 검사",
            "description": "TLS Client Hello의 JA3 핑거프린트를 수집/분석. "
                           "악성 도구(Cobalt Strike 등)의 알려진 JA3 해시와 매칭.",
        },
        "check_ja3s": {
            "type": bool, "default": True,
            "label": "JA3S 핑거프린트 검사",
            "description": "TLS Server Hello의 JA3S 핑거프린트를 수집/분석. "
                           "C2 서버의 특징적 TLS 응답 패턴을 탐지.",
        },
        "check_ja4": {
            "type": bool, "default": True,
            "label": "JA4 핑거프린트 검사",
            "description": "차세대 TLS 핑거프린트(JA4). JA3보다 정확한 클라이언트 식별 제공.",
        },
        "check_sni": {
            "type": bool, "default": True,
            "label": "SNI 검사",
            "description": "TLS Server Name Indication 필드를 분석. "
                           "SNI 누락 또는 IP 직접 접속 시 알림(정상 HTTPS는 SNI 포함).",
        },
        "check_cert": {
            "type": bool, "default": True,
            "label": "인증서 검사",
            "description": "TLS 인증서의 유효기간, 자체서명 여부, Subject 이상 등을 분석.",
        },
        "detect_tunnels": {
            "type": bool, "default": True,
            "label": "TLS 터널 탐지",
            "description": "TLS 트래픽 패턴으로 VPN/터널 사용을 탐지. "
                           "패킷 크기 분포의 변동계수(CV)가 낮으면 터널 의심.",
        },
        "tunnel_min_packets": {
            "type": int, "default": 30, "min": 10, "max": 500,
            "label": "터널 탐지 최소 패킷 수",
            "description": "터널 분석에 필요한 최소 패킷 수. 충분한 샘플이 있어야 정확한 판정 가능.",
        },
        "tunnel_cv_threshold": {
            "type": float, "default": 0.05, "min": 0.01, "max": 0.5,
            "label": "터널 CV 임계값",
            "description": "패킷 크기 변동계수(CV)가 이 값 이하이면 터널로 판정. "
                           "터널 트래픽은 패킷 크기가 매우 균일(낮은 CV).",
        },
        "max_tracked_flows": {
            "type": int, "default": 5000, "min": 100, "max": 100000,
            "label": "최대 추적 플로우 수",
            "description": "메모리에 유지하는 TLS 플로우 추적 테이블 크기.",
        },
        "detect_esni": {
            "type": bool, "default": True,
            "label": "ESNI/ECH 탐지",
            "description": "Encrypted SNI / Encrypted Client Hello 사용을 탐지. "
                           "정상 용도도 있으나 악성 트래픽 은닉에도 사용될 수 있음.",
        },
    }

    # SNI 캐시 최대 항목 수 (플로우별 SNI 추적)
    _SNI_CACHE_MAX = 5000

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진 설정을 초기화하고 JA3/JA4/SNI/인증서 검사 상태를 구성한다."""
        super().__init__(config)
        self._check_ja3 = config.get("check_ja3", True)
        self._check_ja3s = config.get("check_ja3s", True)
        self._check_ja4 = config.get("check_ja4", True)
        self._check_sni = config.get("check_sni", True)
        self._check_cert = config.get("check_cert", True)

        # 터널 탐지 설정
        self._detect_tunnels = config.get("detect_tunnels", True)
        self._tunnel_min_packets = config.get("tunnel_min_packets", 30)
        self._tunnel_cv_threshold = config.get("tunnel_cv_threshold", 0.05)
        self._max_tracked_flows = config.get("max_tracked_flows", 5000)

        # ESNI/ECH 탐지 설정
        self._detect_esni = config.get("detect_esni", True)

        # set_feeds()에 의해 채워짐
        self._blocked_ja3: set[str] = set()
        self._blocked_ja4: set[str] = set()
        self._ja3_to_malware: dict[str, str] = {}
        self._ja4_to_malware: dict[str, str] = {}
        self._blocked_domains: set[str] = set()
        self._feed_manager = None

        # SNI 캐시: (client_ip, server_ip) -> 인증서 불일치 탐지용 sni
        # _SNI_CACHE_MAX 항목에서 LRU 제거를 위해 OrderedDict 사용.
        self._sni_cache: OrderedDict[tuple[str | None, str | None], str] = OrderedDict()

        # 터널 탐지용 플로우 추적:
        # (src_ip, dst_ip, dst_port) -> (timestamp, pkt_size) deque
        self._flow_stats: dict[
            tuple[str | None, str | None, int], deque[tuple[float, int]]
        ] = {}

    def set_feeds(self, feed_manager: Any) -> None:
        """FeedManager의 실시간 차단 목록 참조를 주입한다."""
        self._feed_manager = feed_manager
        self._blocked_ja3 = feed_manager._blocked_ja3
        self._ja3_to_malware = feed_manager._ja3_to_malware
        self._blocked_domains = feed_manager._blocked_domains
        # JA4 피드 (이전 버전 FeedManager에는 없을 수 있음)
        self._blocked_ja4 = getattr(feed_manager, "_blocked_ja4", set())
        self._ja4_to_malware = getattr(feed_manager, "_ja4_to_malware", {})
        logger.info(
            "TLS fingerprint feeds loaded: %d JA3, %d JA4, %d blocked domains",
            len(self._blocked_ja3), len(self._blocked_ja4),
            len(self._blocked_domains),
        )

    def analyze(self, packet: Packet) -> Alert | None:
        """TLS 패킷에서 JA3/JA4 핑거프린트, SNI, 인증서 이상을 분석한다."""
        # TLS 포트의 TCP 패킷만 검사
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]
        tls_ports = (443, 8443, 993, 995, 465, 636)
        is_client_to_server = tcp.dport in tls_ports
        is_server_to_client = tcp.sport in tls_ports

        if not is_client_to_server and not is_server_to_client:
            return None

        src_ip, dst_ip = get_ip_addrs(packet)

        # --- 터널 탐지용 플로우 추적 (TLS 터널 포트만) ---
        _TUNNEL_PORTS = (443, 8443)
        if self._detect_tunnels:
            if is_client_to_server and tcp.dport in _TUNNEL_PORTS:
                pkt_size = len(packet)
                self._track_flow(src_ip, dst_ip, tcp.dport, pkt_size)
            elif is_server_to_client and tcp.sport in _TUNNEL_PORTS:
                pkt_size = len(packet)
                self._track_flow(src_ip, dst_ip, tcp.sport, pkt_size)

        # --- ServerHello / 인증서: JA3S + 인증서 분석 ---
        if is_server_to_client:
            if self._check_ja3s:
                server_hello = self._get_server_hello(packet)
                if server_hello is not None:
                    ja3s_hash = compute_ja3s(server_hello)
                    if ja3s_hash:
                        logger.debug(
                            "JA3S fingerprint: %s (server=%s)", ja3s_hash, src_ip
                        )

            # 인증서 체인 분석 (서버 -> 클라이언트 방향)
            if self._check_cert:
                cert_info = self._extract_cert_info(packet)
                if cert_info is not None:
                    cert_alert = self._analyze_certificate(
                        cert_info, src_ip, dst_ip
                    )
                    if cert_alert is not None:
                        return cert_alert

        # --- ClientHello: JA3 + SNI + ESNI/ECH 탐지 ---
        if not is_client_to_server:
            return None

        client_hello = self._get_client_hello(packet)
        if client_hello is None:
            return None

        # JA4를 한 번만 계산 (보강 및 차단 목록 검사에 모두 사용)
        ja4_hash: str | None = None
        if self._check_ja4:
            ja4_hash = compute_ja4(client_hello)
            if ja4_hash:
                logger.debug(
                    "JA4 fingerprint: %s (client=%s)", ja4_hash, src_ip
                )

        # JA3 해시 검사
        if self._check_ja3:
            ja3_hash = compute_ja3(client_hello)
            if ja3_hash and ja3_hash in self._blocked_ja3:
                if self.is_whitelisted(source_ip=src_ip):
                    return None
                malware_name = self._ja3_to_malware.get(ja3_hash, "Unknown")
                metadata: dict[str, Any] = {
                    "ja3_hash": ja3_hash,
                    "malware": malware_name,
                }
                if ja4_hash:
                    metadata["ja4_hash"] = ja4_hash
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Malicious TLS Fingerprint (JA3 Match)",
                    description=(
                        f"TLS ClientHello matches known malware JA3 fingerprint: "
                        f"{ja3_hash} (malware: {malware_name})"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.90,
                    metadata=metadata,
                )

        # JA4 차단 목록 검사
        if self._check_ja4 and ja4_hash and ja4_hash in self._blocked_ja4:
            if self.is_whitelisted(source_ip=src_ip):
                return None
            malware_name = self._ja4_to_malware.get(ja4_hash, "Unknown")
            return Alert(
                engine=self.name,
                severity=Severity.CRITICAL,
                title="Malicious TLS Fingerprint (JA4 Match)",
                description=(
                    f"TLS ClientHello matches known malware JA4 fingerprint: "
                    f"{ja4_hash} (malware: {malware_name})"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.92,
                metadata={
                    "ja4_hash": ja4_hash,
                    "malware": malware_name,
                },
            )

        # SNI 도메인 검사 + 인증서 불일치 탐지를 위한 SNI 캐싱
        if self._check_sni:
            sni = extract_sni(client_hello)
            if sni:
                # 인증서 CN/SAN 불일치 탐지를 위해 SNI 캐싱.
                # 키: (client_ip, server_ip) — 서버->클라이언트 인증서 응답에서
                # 예상 SNI를 조회할 수 있도록 함.
                self._cache_sni(src_ip, dst_ip, sni)

                if self.is_whitelisted(domain=sni):
                    return None
                # 전체 도메인 및 상위 도메인 검사
                parts = sni.lower().split(".")
                for i in range(len(parts)):
                    check_domain = ".".join(parts[i:])
                    if check_domain in self._blocked_domains:
                        feed_name = None
                        if self._feed_manager:
                            feed_name = self._feed_manager.get_feed_for_domain(
                                check_domain
                            )
                        return Alert(
                            engine=self.name,
                            severity=Severity.CRITICAL,
                            title="TLS Connection to Blocklisted Domain (SNI)",
                            description=(
                                f"TLS handshake to known malicious domain: {sni}"
                                + (f" (feed: {feed_name})" if feed_name else "")
                            ),
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            confidence=0.95,
                            metadata={
                                "sni": sni,
                                "matched_domain": check_domain,
                                "feed": feed_name,
                            },
                        )

        # --- ESNI/ECH 탐지 (최저 우선순위, 정보성) ---
        if self._detect_esni:
            esni_alert = self._check_esni_ech(client_hello, src_ip, dst_ip)
            if esni_alert is not None:
                return esni_alert

        return None

    def shutdown(self) -> None:
        """엔진 종료 시 모든 차단 목록과 캐시를 초기화한다."""
        self._blocked_ja3.clear()
        self._blocked_ja4.clear()
        self._ja3_to_malware.clear()
        self._ja4_to_malware.clear()
        self._blocked_domains.clear()
        self._sni_cache.clear()
        self._flow_stats.clear()

    # ------------------------------------------------------------------
    # 암호화 터널 탐지용 플로우 추적
    # ------------------------------------------------------------------

    def _track_flow(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int,
        pkt_size: int,
    ) -> None:
        """플로우의 패킷 크기를 기록하며 max_tracked_flows 제한을 적용한다.

        플로우 딕셔너리가 ``_max_tracked_flows``를 초과하면 가장 오래된
        마지막 관측 타임스탬프의 플로우를 제거한다.
        """
        key = (src_ip, dst_ip, dst_port)
        now = time.time()

        if key not in self._flow_stats:
            # 용량 초과 시 가장 오래된 플로우 제거
            if len(self._flow_stats) >= self._max_tracked_flows:
                oldest_key = min(
                    self._flow_stats,
                    key=lambda k: self._flow_stats[k][-1][0]
                    if self._flow_stats[k]
                    else float("inf"),
                )
                del self._flow_stats[oldest_key]
            self._flow_stats[key] = deque()

        self._flow_stats[key].append((now, pkt_size))

    def on_tick(self, timestamp: float) -> list[Alert]:
        """패킷 크기 균일성 기반의 터널 유사 플로우 주기적 검사.

        ``tunnel_min_packets`` 이상의 샘플이 있는 플로우에 대해 패킷 크기의
        변동계수(CV = 표준편차 / 평균)를 계산한다. CV가 ``tunnel_cv_threshold``
        미만이면 거의 동일한 패킷 크기를 나타내며, VPN/터널 캡슐화의
        특징이다.
        """
        if not self._detect_tunnels:
            return []

        alerts: list[Alert] = []

        keys_to_delete: list[tuple[str | None, str | None, int]] = []
        for flow_key, samples in self._flow_stats.items():
            if len(samples) < self._tunnel_min_packets:
                continue

            sizes = [s for _, s in samples]
            mean = sum(sizes) / len(sizes)
            if mean <= 0:
                continue

            variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
            stddev = math.sqrt(variance)
            cv = stddev / mean

            if cv < self._tunnel_cv_threshold:
                src_ip, dst_ip, dst_port = flow_key
                if self.is_whitelisted(source_ip=src_ip):
                    continue
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Suspected Encrypted Tunnel (Uniform Packet Sizes)",
                    description=(
                        f"Flow {src_ip} -> {dst_ip}:{dst_port} shows highly "
                        f"uniform packet sizes (CV={cv:.4f}, "
                        f"packets={len(samples)}), suggesting VPN/tunnel traffic"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.5,
                    metadata={
                        "cv": round(cv, 6),
                        "mean_pkt_size": round(mean, 1),
                        "packet_count": len(samples),
                        "dst_port": dst_port,
                    },
                ))
                # 반복 알림 방지를 위해 알림 후 플로우 초기화
                keys_to_delete.append(flow_key)

        for key in keys_to_delete:
            del self._flow_stats[key]

        return alerts

    # ------------------------------------------------------------------
    # ESNI / ECH 탐지
    # ------------------------------------------------------------------

    # ECH 및 레거시 ESNI 확장 타입 ID
    _EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
    _EXT_LEGACY_ESNI            = 0xFFCE

    def _check_esni_ech(
        self,
        client_hello: Any,
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """ClientHello 확장에서 ECH 또는 레거시 ESNI 사용을 검사한다.

        ECH (0xFE0D) 또는 ESNI (0xFFCE) 확장이 감지되면 INFO 수준 알림을
        반환한다. 이는 정보성 알림으로 — ECH는 서버 이름 가시성을 줄이지만
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

                if ext_val == self._EXT_ENCRYPTED_CLIENT_HELLO:
                    return Alert(
                        engine=self.name,
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

                if ext_val == self._EXT_LEGACY_ESNI:
                    return Alert(
                        engine=self.name,
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

    # ------------------------------------------------------------------
    # 인증서 불일치 탐지용 SNI 캐시
    # ------------------------------------------------------------------

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
        while len(self._sni_cache) > self._SNI_CACHE_MAX:
            self._sni_cache.popitem(last=False)

    # ------------------------------------------------------------------
    # 인증서 추출
    # ------------------------------------------------------------------

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

            # Scapy는 원시 인증서를 Cert()/X509Cert로 래핑 — 여러 접근 패턴 시도
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

    # ------------------------------------------------------------------
    # 인증서 분석
    # ------------------------------------------------------------------

    def _analyze_certificate(
        self,
        cert_info: dict[str, Any],
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """추출된 인증서의 이상 여부를 분석한다.

        검사 항목 (우선순위 순):
        1. SNI 불일치 — 인증서 CN/SAN이 이전 관측된 SNI와 불일치.
           (CRITICAL, 신뢰도 0.85)
        2. 만료된 인증서 — not_after가 과거. (WARNING, 0.7)
        3. 자체 서명 — 발급자와 주체가 동일. (WARNING, 0.6)
        4. 단기 유효 — 유효 기간 30일 미만. (INFO, 0.4)

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
                    engine=self.name,
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
                engine=self.name,
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
                engine=self.name,
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
                    engine=self.name,
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

    @staticmethod
    def _get_server_hello(packet: Packet):
        """패킷에서 TLS ServerHello 레이어 추출을 시도한다."""
        try:
            from scapy.layers.tls.handshake import TLSServerHello
            if packet.haslayer(TLSServerHello):
                return packet[TLSServerHello]
        except ImportError:
            pass
        return None

    @staticmethod
    def _get_client_hello(packet: Packet):
        """패킷에서 TLS ClientHello 레이어 추출을 시도한다."""
        try:
            from scapy.layers.tls.handshake import TLSClientHello
            if packet.haslayer(TLSClientHello):
                return packet[TLSClientHello]
        except ImportError:
            pass
        return None
