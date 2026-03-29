"""TLS 핑거프린트 탐지 엔진.

JA3/JA4 해시 매칭, SNI 차단 목록, 인증서 분석, ESNI/ECH 탐지,
TLS 터널 탐지를 위임 패턴으로 조합한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any

from scapy.all import TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.engines.tls.cert_checker import CertChecker
from netwatcher.detection.engines.tls.esni_checker import ESNIChecker
from netwatcher.detection.engines.tls.helpers import compute_ja3s, compute_ja4
from netwatcher.detection.engines.tls.ja3_checker import JA3Checker
from netwatcher.detection.engines.tls.ja4_checker import JA4Checker
from netwatcher.detection.engines.tls.sni_checker import SNIChecker
from netwatcher.detection.engines.tls.tunnel_detector import TunnelDetector
from netwatcher.detection.models import Alert
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.tls_fingerprint")


class TLSFingerprintEngine(DetectionEngine):
    """JA3 핑거프린팅 및 SNI 차단 목록을 통해 악성 TLS 클라이언트를 탐지한다.

    - JA3: TLS ClientHello 구조의 MD5 해시를 계산하여 SSLBL 피드의
      알려진 악성코드 핑거프린트와 매칭한다.
    - SNI: ClientHello에서 평문 서버 이름을 추출하여 도메인 차단 목록과
      대조한다.
    """

    name = "tls_fingerprint"
    requires_span = True
    description = "TLS 핸드셰이크의 JA3/JA4 핑거프린트를 분석합니다. 알려진 악성 클라이언트, 자체서명 인증서, 의심스러운 암호화 설정을 탐지합니다."
    description_key = "engines.tls_fingerprint.description"
    mitre_attack_ids = ['T1573']
    config_schema = {
        "check_ja3": {
            "type": bool, "default": True,
            "label": "JA3 핑거프린트 검사",
            "label_key": "engines.tls_fingerprint.check_ja3.label",
            "description": "TLS Client Hello의 JA3 핑거프린트를 수집/분석. "
                           "악성 도구(Cobalt Strike 등)의 알려진 JA3 해시와 매칭.",
            "description_key": "engines.tls_fingerprint.check_ja3.description",
        },
        "check_ja3s": {
            "type": bool, "default": True,
            "label": "JA3S 핑거프린트 검사",
            "label_key": "engines.tls_fingerprint.check_ja3s.label",
            "description": "TLS Server Hello의 JA3S 핑거프린트를 수집/분석. "
                           "C2 서버의 특징적 TLS 응답 패턴을 탐지.",
            "description_key": "engines.tls_fingerprint.check_ja3s.description",
        },
        "check_ja4": {
            "type": bool, "default": True,
            "label": "JA4 핑거프린트 검사",
            "label_key": "engines.tls_fingerprint.check_ja4.label",
            "description": "차세대 TLS 핑거프린트(JA4). JA3보다 정확한 클라이언트 식별 제공.",
            "description_key": "engines.tls_fingerprint.check_ja4.description",
        },
        "check_sni": {
            "type": bool, "default": True,
            "label": "SNI 검사",
            "label_key": "engines.tls_fingerprint.check_sni.label",
            "description": "TLS Server Name Indication 필드를 분석. "
                           "SNI 누락 또는 IP 직접 접속 시 알림(정상 HTTPS는 SNI 포함).",
            "description_key": "engines.tls_fingerprint.check_sni.description",
        },
        "check_cert": {
            "type": bool, "default": True,
            "label": "인증서 검사",
            "label_key": "engines.tls_fingerprint.check_cert.label",
            "description": "TLS 인증서의 유효기간, 자체서명 여부, Subject 이상 등을 분석.",
            "description_key": "engines.tls_fingerprint.check_cert.description",
        },
        "detect_tunnels": {
            "type": bool, "default": True,
            "label": "TLS 터널 탐지",
            "label_key": "engines.tls_fingerprint.detect_tunnels.label",
            "description": "TLS 트래픽 패턴으로 VPN/터널 사용을 탐지. "
                           "패킷 크기 분포의 변동계수(CV)가 낮으면 터널 의심.",
            "description_key": "engines.tls_fingerprint.detect_tunnels.description",
        },
        "tunnel_min_packets": {
            "type": int, "default": 30, "min": 10, "max": 500,
            "label": "터널 탐지 최소 패킷 수",
            "label_key": "engines.tls_fingerprint.tunnel_min_packets.label",
            "description": "터널 분석에 필요한 최소 패킷 수. 충분한 샘플이 있어야 정확한 판정 가능.",
            "description_key": "engines.tls_fingerprint.tunnel_min_packets.description",
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
        """엔진 설정을 초기화하고 각 검사기 인스턴스를 구성한다."""
        super().__init__(config)
        self._check_ja3  = config.get("check_ja3", True)
        self._check_ja3s = config.get("check_ja3s", True)
        self._check_ja4  = config.get("check_ja4", True)
        self._check_sni  = config.get("check_sni", True)
        self._check_cert = config.get("check_cert", True)

        # 터널 탐지 설정
        self._detect_tunnels = config.get("detect_tunnels", True)

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
        self._sni_cache: OrderedDict[tuple[str | None, str | None], str] = OrderedDict()

        # 검사기 인스턴스 생성 -- 엔진 참조를 전달하여 속성 변경에 자동 추적
        self._ja3_checker    = JA3Checker(self)
        self._ja4_checker    = JA4Checker(self)
        self._sni_checker    = SNIChecker(self, sni_cache=self._sni_cache)
        self._cert_checker   = CertChecker(
            engine_name=self.name, sni_cache=self._sni_cache,
        )
        self._esni_checker   = ESNIChecker(engine_name=self.name)
        self._tunnel_detector = TunnelDetector(
            engine=self,
            tunnel_min_packets=config.get("tunnel_min_packets", 30),
            tunnel_cv_threshold=config.get("tunnel_cv_threshold", 0.05),
            max_tracked_flows=config.get("max_tracked_flows", 5000),
        )

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
                self._tunnel_detector.track_flow(
                    src_ip, dst_ip, tcp.dport, len(packet)
                )
            elif is_server_to_client and tcp.sport in _TUNNEL_PORTS:
                self._tunnel_detector.track_flow(
                    src_ip, dst_ip, tcp.sport, len(packet)
                )

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

            if self._check_cert:
                cert_alert = self._cert_checker.check(packet, src_ip, dst_ip)
                if cert_alert is not None:
                    return cert_alert

        # --- ClientHello: JA3 + SNI + ESNI/ECH 탐지 ---
        if not is_client_to_server:
            return None

        client_hello = self._get_client_hello(packet)
        if client_hello is None:
            return None

        # JA4를 한 번만 계산
        ja4_hash: str | None = None
        if self._check_ja4:
            ja4_hash = compute_ja4(client_hello)
            if ja4_hash:
                logger.debug(
                    "JA4 fingerprint: %s (client=%s)", ja4_hash, src_ip
                )

        # JA3 해시 검사
        if self._check_ja3:
            alert = self._ja3_checker.check(
                client_hello, src_ip, dst_ip, ja4_hash
            )
            if alert is not None:
                return alert

        # JA4 차단 목록 검사
        if self._check_ja4:
            alert = self._ja4_checker.check(ja4_hash, src_ip, dst_ip)
            if alert is not None:
                return alert

        # SNI 도메인 검사
        if self._check_sni:
            alert = self._sni_checker.check(client_hello, src_ip, dst_ip)
            if alert is not None:
                return alert

        # --- ESNI/ECH 탐지 (최저 우선순위, 정보성) ---
        if self._detect_esni:
            alert = self._esni_checker.check(client_hello, src_ip, dst_ip)
            if alert is not None:
                return alert

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """터널 탐지를 위임한다."""
        if not self._detect_tunnels:
            return []
        return self._tunnel_detector.detect_tunnels(timestamp)

    def shutdown(self) -> None:
        """엔진 종료 시 모든 차단 목록과 캐시를 초기화한다."""
        self._blocked_ja3.clear()
        self._blocked_ja4.clear()
        self._ja3_to_malware.clear()
        self._ja4_to_malware.clear()
        self._blocked_domains.clear()
        self._sni_cache.clear()
        self._tunnel_detector.clear()

    # ------------------------------------------------------------------
    # 하위 호환성: 테스트 등에서 내부 속성/메서드에 직접 접근하는 경우를 지원
    # ------------------------------------------------------------------

    @property
    def _tunnel_min_packets(self):
        """터널 탐지기의 최소 패킷 수에 대한 위임 접근."""
        return self._tunnel_detector._tunnel_min_packets

    @property
    def _tunnel_cv_threshold(self):
        """터널 탐지기의 CV 임계값에 대한 위임 접근."""
        return self._tunnel_detector._tunnel_cv_threshold

    @property
    def _max_tracked_flows(self):
        """터널 탐지기의 최대 추적 플로우 수에 대한 위임 접근."""
        return self._tunnel_detector._max_tracked_flows

    @property
    def _flow_stats(self):
        """터널 탐지기의 플로우 통계에 대한 위임 접근."""
        return self._tunnel_detector._flow_stats

    @_flow_stats.setter
    def _flow_stats(self, value):
        self._tunnel_detector._flow_stats = value

    def _track_flow(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int,
        pkt_size: int,
    ) -> None:
        """터널 탐지기의 track_flow에 대한 위임."""
        self._tunnel_detector.track_flow(src_ip, dst_ip, dst_port, pkt_size)

    def _cache_sni(
        self, client_ip: str | None, server_ip: str | None, sni: str
    ) -> None:
        """SNI 검사기의 _cache_sni에 대한 위임."""
        self._sni_checker._cache_sni(client_ip, server_ip, sni)

    def _analyze_certificate(
        self,
        cert_info: dict[str, Any],
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """인증서 검사기의 _analyze_certificate에 대한 위임."""
        return self._cert_checker._analyze_certificate(cert_info, src_ip, dst_ip)

    @staticmethod
    def _extract_cert_info(packet: Packet) -> dict[str, Any] | None:
        """인증서 검사기의 _extract_cert_info에 대한 위임."""
        return CertChecker._extract_cert_info(packet)

    def _check_esni_ech(
        self,
        client_hello: Any,
        src_ip: str | None,
        dst_ip: str | None,
    ) -> Alert | None:
        """ESNI 검사기의 check에 대한 위임."""
        return self._esni_checker.check(client_hello, src_ip, dst_ip)

    # ECH 및 레거시 ESNI 확장 타입 ID (하위 호환성)
    _EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
    _EXT_LEGACY_ESNI            = 0xFFCE

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
