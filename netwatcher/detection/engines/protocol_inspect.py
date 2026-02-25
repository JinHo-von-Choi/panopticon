"""다중 프로토콜 검사: HTTP, SMTP, FTP, SSH.

애플리케이션 레이어 트래픽에서 의심스러운 패턴을 탐지한다.
스캐닝 도구, 민감 경로 접근, 오픈 릴레이 시도, 무차별 대입 공격
지표, 구버전 프로토콜 등을 포함한다.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Any

from scapy.all import TCP, Raw, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs, is_internal
from netwatcher.protocols.http import parse_http_request, parse_http_response
from netwatcher.protocols.smtp import parse_smtp_command, parse_smtp_response
from netwatcher.protocols.ftp import parse_ftp_command, parse_ftp_response
from netwatcher.protocols.ssh import parse_ssh_banner

logger = logging.getLogger("netwatcher.detection.engines.protocol_inspect")

# 기본 의심 User-Agent 부분문자열 (대소문자 무시 매칭)
_DEFAULT_SUSPICIOUS_UAS: list[str] = [
    "Nmap",
    "sqlmap",
    "Nikto",
    "DirBuster",
    "Hydra",
    "Masscan",
    "ZmEu",
    "w3af",
]

# 기본 민감 경로 (접두사 매칭, 대소문자 무시)
_DEFAULT_SENSITIVE_PATHS: list[str] = [
    "/admin",
    "/wp-login.php",
    "/.env",
    "/actuator",
    "/phpmyadmin",
    "/wp-config.php",
    "/.git",
    "/server-status",
]

# FTP 검사용 기본 민감 파일 패턴
_DEFAULT_SENSITIVE_FILES: list[str] = [
    ".env",
    ".htpasswd",
    "passwd",
    "shadow",
    "id_rsa",
    ".ssh",
]

# 검사할 HTTP 포트
_HTTP_PORTS = frozenset({80, 8080, 8000, 8443})

# 검사할 SMTP 포트
_SMTP_PORTS = frozenset({25, 587, 465})

# 검사할 FTP 포트
_FTP_PORTS = frozenset({20, 21})

# 구버전 서버 배너 (접두사 매칭, 대소문자 무시)
_OUTDATED_SERVERS: list[str] = [
    "apache/2.2.",
    "apache/2.0.",
    "iis/6.0",
    "iis/5.0",
    "iis/7.0",
    "nginx/0.",
    "nginx/1.0.",
    "nginx/1.2.",
]

# 스캐닝을 나타낼 수 있는 비표준 HTTP 메서드
_ABUSE_METHODS = frozenset({"TRACE", "CONNECT", "DEBUG", "TRACK", "PROPFIND"})

# 사용자 열거를 나타내는 SMTP 명령
_SMTP_ENUM_COMMANDS = frozenset({"VRFY", "EXPN"})

# 알려진 취약 SSH 버전 (소프트웨어 부분문자열, 대소문자 무시)
_VULNERABLE_SSH_SOFTWARE: list[str] = [
    "openssh_3.",
    "openssh_4.",
    "openssh_5.",
    "openssh_6.0",
    "openssh_6.1",
    "openssh_6.2",
    "dropbear_0.",
    "libssh-0.5",
    "libssh-0.6",
]


class ProtocolInspectEngine(DetectionEngine):
    """HTTP, SMTP, FTP, SSH 트래픽에서 의심스러운 패턴을 검사한다.

    HTTP 탐지:
    - 의심 User-Agent 문자열 (스캐닝 도구)
    - 민감/관리자 경로 접근
    - 비표준 HTTP 메서드 남용
    - 응답의 구버전 서버 배너

    SMTP 탐지:
    - VRFY/EXPN 명령 (사용자 열거)
    - 오픈 릴레이 시도 (내부 출발지에서 외부 도메인으로 RCPT TO)
    - AUTH 무차별 대입 (on_tick을 통한 임계값 기반)

    FTP 탐지:
    - 익명 로그인 시도
    - 민감 파일 접근 (.env, passwd 등의 RETR/STOR)
    - 로그인 실패 무차별 대입 (530 응답, on_tick을 통한 임계값 기반)

    SSH 탐지:
    - 구버전 SSH 프로토콜 (< 2.0)
    - 알려진 취약 SSH 소프트웨어 버전
    """

    name = "protocol_inspect"
    description = "프로토콜 심층 분석(DPI)을 수행합니다. FTP, SMTP, SSH 등 애플리케이션 프로토콜의 비정상 사용 패턴을 탐지합니다."
    config_schema = {
        "suspicious_user_agents": {
            "type": list, "default": _DEFAULT_SUSPICIOUS_UAS,
            "label": "의심 User-Agent 목록",
            "description": "HTTP User-Agent에 이 문자열이 포함되면 보안 도구 사용 의심 알림. "
                           "Nmap, sqlmap, Nikto 등 공격 도구의 기본 UA 패턴.",
        },
        "sensitive_paths": {
            "type": list, "default": _DEFAULT_SENSITIVE_PATHS,
            "label": "민감 경로 목록",
            "description": "이 경로에 대한 HTTP 요청 시 알림. "
                           "/admin, /.env, /wp-login.php 등 공격 대상이 되는 경로.",
        },
        "check_response": {
            "type": bool, "default": True,
            "label": "HTTP 응답 분석",
            "description": "HTTP 응답도 분석하여 에러 코드 패턴(다수 403/404) 탐지. "
                           "비활성화하면 요청만 분석.",
        },
        "max_tracked_responses": {
            "type": int, "default": 5000, "min": 100, "max": 100000,
            "label": "최대 추적 응답 수",
            "description": "메모리에 유지하는 HTTP 응답 추적 테이블 크기.",
        },
        "smtp_ports": {
            "type": list, "default": [25, 587, 465],
            "label": "SMTP 포트 목록",
            "description": "SMTP 프로토콜로 분석할 포트 번호 (쉼표 구분).",
        },
        "ftp_ports": {
            "type": list, "default": [20, 21],
            "label": "FTP 포트 목록",
            "description": "FTP 프로토콜로 분석할 포트 번호 (쉼표 구분).",
        },
        "ssh_port": {
            "type": int, "default": 22, "min": 1, "max": 65535,
            "label": "SSH 포트",
            "description": "SSH 프로토콜로 분석할 포트 번호.",
        },
        "sensitive_files": {
            "type": list, "default": _DEFAULT_SENSITIVE_FILES,
            "label": "민감 파일 목록",
            "description": "FTP에서 이 파일에 대한 접근 시 알림. "
                           ".env, passwd, id_rsa 등 민감 파일.",
        },
        "smtp_auth_threshold": {
            "type": int, "default": 5, "min": 2, "max": 100,
            "label": "SMTP 인증 실패 임계값",
            "description": "윈도우 내 SMTP 인증 실패 횟수가 이 값을 초과하면 무차별 대입 공격 의심.",
        },
        "smtp_auth_window": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "SMTP 인증 윈도우(초)",
            "description": "SMTP 인증 실패를 집계하는 시간 윈도우. 기본값 5분.",
        },
        "ftp_fail_threshold": {
            "type": int, "default": 5, "min": 2, "max": 100,
            "label": "FTP 실패 임계값",
            "description": "윈도우 내 FTP 로그인 실패 횟수가 이 값을 초과하면 무차별 대입 공격 의심.",
        },
        "ftp_fail_window": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "FTP 실패 윈도우(초)",
            "description": "FTP 로그인 실패를 집계하는 시간 윈도우. 기본값 5분.",
        },
        "max_tracked_sources": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 출발지 수",
            "description": "메모리에 유지하는 프로토콜 분석 출발지 추적 테이블 크기.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """프로토콜 심층 검사 엔진을 초기화한다. HTTP/SMTP/FTP/SSH 관련 설정을 적용한다."""
        super().__init__(config)
        # --- HTTP 설정 ---
        self._suspicious_uas: list[str] = [
            ua.lower()
            for ua in config.get("suspicious_user_agents", _DEFAULT_SUSPICIOUS_UAS)
        ]
        self._sensitive_paths: list[str] = [
            p.lower()
            for p in config.get("sensitive_paths", _DEFAULT_SENSITIVE_PATHS)
        ]
        self._response_check_enabled: bool = config.get("check_response", True)
        self._max_tracked: int = config.get("max_tracked_responses", 5000)

        # 이미 알림된 서버 배너용 LRU 캐시: (server_ip, banner) -> True
        self._alerted_banners: OrderedDict[tuple[str, str], bool] = OrderedDict()

        # --- SMTP 설정 ---
        smtp_port_list = config.get("smtp_ports", [25, 587, 465])
        self._smtp_ports: frozenset[int] = frozenset(smtp_port_list)

        # --- FTP 설정 ---
        ftp_port_list = config.get("ftp_ports", [20, 21])
        self._ftp_ports: frozenset[int] = frozenset(ftp_port_list)

        # --- SSH 설정 ---
        self._ssh_port: int = config.get("ssh_port", 22)

        # --- FTP 민감 파일 ---
        self._sensitive_files: list[str] = [
            f.lower()
            for f in config.get("sensitive_files", _DEFAULT_SENSITIVE_FILES)
        ]

        # --- 임계값 추적 ---
        self._max_tracked_sources: int = config.get("max_tracked_sources", 10000)
        self._smtp_auth_threshold: int = config.get("smtp_auth_threshold", 5)
        self._smtp_auth_window: int = config.get("smtp_auth_window", 300)
        self._ftp_fail_threshold: int = config.get("ftp_fail_threshold", 5)
        self._ftp_fail_window: int = config.get("ftp_fail_window", 300)

        # SMTP AUTH 시도: src_ip -> 타임스탬프 목록
        self._smtp_auth_attempts: OrderedDict[str, list[float]] = OrderedDict()
        # FTP 로그인 실패: src_ip -> 타임스탬프 목록
        self._ftp_fail_attempts: OrderedDict[str, list[float]] = OrderedDict()
        # SSH 배너 중복 제거: (ip, banner_str) -> True
        self._alerted_ssh_banners: OrderedDict[tuple[str, str], bool] = OrderedDict()

    # ------------------------------------------------------------------
    # HTTP: 요청 검사
    # ------------------------------------------------------------------

    def _inspect_request(
        self, parsed: dict, src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """파싱된 HTTP 요청에서 의심스러운 패턴을 검사한다."""
        method   = parsed.get("method", "")
        path     = parsed.get("path", "")
        ua       = parsed.get("user_agent") or ""
        path_low = path.lower()
        ua_low   = ua.lower()

        suspicious_ua  = False
        sensitive_path = False
        matched_ua:   str | None = None
        matched_path: str | None = None

        # 1. 의심 User-Agent
        for pattern in self._suspicious_uas:
            if pattern in ua_low:
                suspicious_ua = True
                matched_ua    = pattern
                break

        # 2. 민감 경로 접근
        for sp in self._sensitive_paths:
            if path_low.startswith(sp):
                sensitive_path = True
                matched_path   = sp
                break

        # 3. HTTP 메서드 남용
        method_abuse = method.upper() in _ABUSE_METHODS

        # 알림 생성: UA와 경로 모두 매칭 => CRITICAL
        if suspicious_ua and sensitive_path:
            return Alert(
                engine=self.name,
                severity=Severity.CRITICAL,
                title="Suspicious Scan: UA + Sensitive Path",
                description=(
                    f"Scanning tool UA ({matched_ua}) accessing sensitive path "
                    f"{path} from {src_ip} to {dst_ip}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.9,
                metadata={
                    "method": method,
                    "path": path,
                    "user_agent": ua,
                    "matched_ua": matched_ua,
                    "matched_path": matched_path,
                },
            )

        if suspicious_ua:
            return Alert(
                engine=self.name,
                severity=Severity.WARNING,
                title="Suspicious User-Agent Detected",
                description=(
                    f"Scanning tool User-Agent detected: {ua} "
                    f"from {src_ip} to {dst_ip}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.75,
                metadata={
                    "method": method,
                    "path": path,
                    "user_agent": ua,
                    "matched_ua": matched_ua,
                },
            )

        if sensitive_path:
            return Alert(
                engine=self.name,
                severity=Severity.WARNING,
                title="Sensitive Path Access",
                description=(
                    f"Access to sensitive path {path} from {src_ip} to {dst_ip}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.65,
                metadata={
                    "method": method,
                    "path": path,
                    "user_agent": ua,
                    "matched_path": matched_path,
                },
            )

        if method_abuse:
            return Alert(
                engine=self.name,
                severity=Severity.WARNING,
                title="HTTP Method Abuse",
                description=(
                    f"Non-standard HTTP method {method} from {src_ip} to {dst_ip}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.6,
                metadata={"method": method, "path": path},
            )

        return None

    # ------------------------------------------------------------------
    # HTTP: 응답 검사
    # ------------------------------------------------------------------

    def _inspect_response(
        self, parsed: dict, src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """HTTP 응답에서 구버전 서버 배너를 검사한다."""
        server = parsed.get("server") or ""
        if not server:
            return None

        server_low = server.lower()
        for pattern in _OUTDATED_SERVERS:
            if pattern in server_low:
                # 중복 제거: (server_ip, banner)당 한 번만 알림
                key = (src_ip or "", server)
                if key in self._alerted_banners:
                    return None

                # LRU 제거
                if len(self._alerted_banners) >= self._max_tracked:
                    self._alerted_banners.popitem(last=False)
                self._alerted_banners[key] = True

                return Alert(
                    engine=self.name,
                    severity=Severity.INFO,
                    title="Outdated Server Banner",
                    description=(
                        f"Server {src_ip} running outdated software: {server}"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.5,
                    metadata={
                        "server_banner": server,
                        "status_code": parsed.get("status_code"),
                    },
                )

        return None

    # ------------------------------------------------------------------
    # SMTP: 명령 검사
    # ------------------------------------------------------------------

    def _inspect_smtp(
        self, payload: bytes, tcp_sport: int, tcp_dport: int,
        src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """SMTP 트래픽에서 의심스러운 패턴을 검사한다."""
        # 클라이언트 명령 (목적지가 SMTP 포트)
        if tcp_dport in self._smtp_ports:
            parsed = parse_smtp_command(payload)
            if parsed:
                return self._inspect_smtp_command(parsed, src_ip, dst_ip)

        # 서버 응답 (출발지가 SMTP 포트)
        elif tcp_sport in self._smtp_ports:
            parsed = parse_smtp_response(payload)
            if parsed:
                return self._inspect_smtp_response(parsed, src_ip, dst_ip)

        return None

    def _inspect_smtp_command(
        self, parsed: dict, src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """파싱된 SMTP 명령을 검사한다."""
        command  = parsed.get("command", "")
        argument = parsed.get("argument", "")

        # 1. VRFY/EXPN - 사용자 열거 시도
        if command in _SMTP_ENUM_COMMANDS:
            return Alert(
                engine=self.name,
                severity=Severity.WARNING,
                title="SMTP User Enumeration Attempt",
                description=(
                    f"SMTP {command} command from {src_ip} to {dst_ip}: {argument}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.7,
                metadata={
                    "protocol": "smtp",
                    "command": command,
                    "argument": argument,
                },
            )

        # 2. 내부 출발지에서 외부 도메인으로 RCPT TO (오픈 릴레이 시도)
        if command == "RCPT TO" and src_ip and is_internal(src_ip):
            # <user@domain.com> 형식의 인수에서 도메인 추출
            domain = self._extract_email_domain(argument)
            if domain and not is_internal(domain):
                # 내부 출발지에서 외부 도메인 - 오픈 릴레이 가능성
                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="SMTP Open Relay Attempt",
                    description=(
                        f"Internal host {src_ip} attempting to relay mail to "
                        f"external domain {domain} via {dst_ip}"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.65,
                    metadata={
                        "protocol": "smtp",
                        "command": command,
                        "argument": argument,
                        "target_domain": domain,
                    },
                )

        # 3. AUTH 명령 - on_tick()에서 무차별 대입 탐지를 위해 추적
        if command == "AUTH" and src_ip:
            self._record_smtp_auth(src_ip)

        return None

    def _inspect_smtp_response(
        self, parsed: dict, src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """SMTP 서버 응답을 검사한다 (현재 응답에서 패킷별 알림 없음)."""
        # 향후 SMTP 응답에서 추가 패턴을 분석할 수 있음.
        return None

    @staticmethod
    def _extract_email_domain(argument: str) -> str | None:
        """<user@domain.com> 형식의 SMTP 인수에서 도메인을 추출한다."""
        at_pos = argument.find("@")
        if at_pos < 0:
            return None
        rest = argument[at_pos + 1:]
        # 후행 >와 공백 제거
        rest = rest.rstrip("> \t\r\n")
        return rest.lower() if rest else None

    def _record_smtp_auth(self, src_ip: str) -> None:
        """임계값 기반 탐지를 위해 SMTP AUTH 시도를 기록한다."""
        now = time.time()
        if src_ip not in self._smtp_auth_attempts:
            # LRU 제거
            if len(self._smtp_auth_attempts) >= self._max_tracked_sources:
                self._smtp_auth_attempts.popitem(last=False)
            self._smtp_auth_attempts[src_ip] = []
        self._smtp_auth_attempts[src_ip].append(now)

    # ------------------------------------------------------------------
    # FTP: 명령 및 응답 검사
    # ------------------------------------------------------------------

    def _inspect_ftp(
        self, payload: bytes, tcp_sport: int, tcp_dport: int,
        src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """FTP 트래픽에서 의심스러운 패턴을 검사한다."""
        # 클라이언트 명령 (목적지가 FTP 포트)
        if tcp_dport in self._ftp_ports:
            parsed = parse_ftp_command(payload)
            if parsed:
                return self._inspect_ftp_command(parsed, src_ip, dst_ip)

        # 서버 응답 (출발지가 FTP 포트)
        elif tcp_sport in self._ftp_ports:
            parsed = parse_ftp_response(payload)
            if parsed:
                return self._inspect_ftp_response(parsed, src_ip, dst_ip)

        return None

    def _inspect_ftp_command(
        self, parsed: dict, src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """파싱된 FTP 명령을 검사한다."""
        command  = parsed.get("command", "")
        argument = parsed.get("argument", "")

        # 1. 익명 로그인 시도
        if command == "USER" and argument.lower() == "anonymous":
            return Alert(
                engine=self.name,
                severity=Severity.INFO,
                title="FTP Anonymous Login",
                description=(
                    f"Anonymous FTP login attempt from {src_ip} to {dst_ip}"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=0.5,
                metadata={
                    "protocol": "ftp",
                    "command": command,
                    "argument": argument,
                },
            )

        # 2. RETR 또는 STOR을 통한 민감 파일 접근
        if command in ("RETR", "STOR"):
            arg_lower = argument.lower()
            for sensitive in self._sensitive_files:
                if sensitive in arg_lower:
                    return Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="FTP Sensitive File Access",
                        description=(
                            f"FTP {command} for sensitive file '{argument}' "
                            f"from {src_ip} to {dst_ip}"
                        ),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.75,
                        metadata={
                            "protocol": "ftp",
                            "command": command,
                            "filename": argument,
                            "matched_pattern": sensitive,
                        },
                    )

        return None

    def _inspect_ftp_response(
        self, parsed: dict, src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """FTP 서버 응답에서 로그인 실패를 검사한다."""
        code = parsed.get("code", 0)

        # 530 = 로그인 실패 - on_tick()에서 무차별 대입 탐지를 위해 추적
        if code == 530 and dst_ip:
            self._record_ftp_fail(dst_ip)

        return None

    def _record_ftp_fail(self, src_ip: str) -> None:
        """임계값 기반 탐지를 위해 FTP 로그인 실패를 기록한다."""
        now = time.time()
        if src_ip not in self._ftp_fail_attempts:
            if len(self._ftp_fail_attempts) >= self._max_tracked_sources:
                self._ftp_fail_attempts.popitem(last=False)
            self._ftp_fail_attempts[src_ip] = []
        self._ftp_fail_attempts[src_ip].append(now)

    # ------------------------------------------------------------------
    # SSH: 배너 검사
    # ------------------------------------------------------------------

    def _inspect_ssh(
        self, payload: bytes, tcp_sport: int, tcp_dport: int,
        src_ip: str | None, dst_ip: str | None,
    ) -> Alert | None:
        """SSH 트래픽에서 구버전 프로토콜/소프트웨어를 검사한다."""
        parsed = parse_ssh_banner(payload)
        if not parsed:
            return None

        protocol = parsed.get("protocol", "")
        software = parsed.get("software", "")
        banner_str = f"SSH-{protocol}-{software}"

        # 1. 구버전 SSH 프로토콜 (버전 < 2.0)
        try:
            proto_major = float(protocol.split(".")[0]) if protocol else 2.0
        except (ValueError, IndexError):
            proto_major = 2.0

        if proto_major < 2.0:
            # 중복 제거
            key = (src_ip or "", banner_str)
            if key not in self._alerted_ssh_banners:
                if len(self._alerted_ssh_banners) >= self._max_tracked:
                    self._alerted_ssh_banners.popitem(last=False)
                self._alerted_ssh_banners[key] = True

                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Outdated SSH Protocol",
                    description=(
                        f"SSH protocol version {protocol} detected from "
                        f"{src_ip or dst_ip} (software: {software})"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.8,
                    metadata={
                        "protocol": "ssh",
                        "ssh_version": protocol,
                        "software": software,
                        "banner": banner_str,
                    },
                )

        # 2. 알려진 취약 SSH 소프트웨어
        sw_lower = software.lower()
        for vuln_pattern in _VULNERABLE_SSH_SOFTWARE:
            if vuln_pattern in sw_lower:
                key = (src_ip or "", banner_str)
                if key not in self._alerted_ssh_banners:
                    if len(self._alerted_ssh_banners) >= self._max_tracked:
                        self._alerted_ssh_banners.popitem(last=False)
                    self._alerted_ssh_banners[key] = True

                    return Alert(
                        engine=self.name,
                        severity=Severity.INFO,
                        title="Outdated SSH Software",
                        description=(
                            f"Vulnerable SSH software {software} detected from "
                            f"{src_ip or dst_ip}"
                        ),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.6,
                        metadata={
                            "protocol": "ssh",
                            "ssh_version": protocol,
                            "software": software,
                            "banner": banner_str,
                            "matched_pattern": vuln_pattern,
                        },
                    )

        return None

    # ------------------------------------------------------------------
    # 메인 분석
    # ------------------------------------------------------------------

    def analyze(self, packet: Packet) -> Alert | None:
        """TCP 페이로드에서 HTTP/SMTP/FTP/SSH 프로토콜별 의심 패턴을 검사한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        tcp     = packet[TCP]
        payload = bytes(packet[Raw].load)

        src_ip, dst_ip = get_ip_addrs(packet)

        # 출발지 IP 화이트리스트 검사
        if src_ip and self.is_whitelisted(source_ip=src_ip):
            return None

        sport = tcp.sport
        dport = tcp.dport

        # --- HTTP 요청 (목적지가 HTTP 포트) ---
        if dport in _HTTP_PORTS:
            parsed = parse_http_request(payload)
            if parsed:
                return self._inspect_request(parsed, src_ip, dst_ip)

        # --- HTTP 응답 (출발지가 HTTP 포트, 상호 배타적) ---
        elif self._response_check_enabled and sport in _HTTP_PORTS:
            parsed = parse_http_response(payload)
            if parsed:
                return self._inspect_response(parsed, src_ip, dst_ip)

        # --- SMTP (목적지 또는 출발지가 SMTP 포트) ---
        elif dport in self._smtp_ports or sport in self._smtp_ports:
            return self._inspect_smtp(payload, sport, dport, src_ip, dst_ip)

        # --- FTP (목적지 또는 출발지가 FTP 포트) ---
        elif dport in self._ftp_ports or sport in self._ftp_ports:
            return self._inspect_ftp(payload, sport, dport, src_ip, dst_ip)

        # --- SSH (양쪽 포트 중 SSH 포트와 일치) ---
        elif dport == self._ssh_port or sport == self._ssh_port:
            return self._inspect_ssh(payload, sport, dport, src_ip, dst_ip)

        return None

    # ------------------------------------------------------------------
    # 주기적 틱: 임계값 기반 탐지
    # ------------------------------------------------------------------

    def on_tick(self, timestamp: float) -> list[Alert]:
        """임계값 기반 탐지를 위해 누적 데이터를 처리한다."""
        alerts: list[Alert] = []
        now = time.time()

        # SMTP AUTH 무차별 대입 검사
        smtp_cutoff = now - self._smtp_auth_window
        expired_smtp: list[str] = []
        for src_ip, timestamps in self._smtp_auth_attempts.items():
            # 만료된 항목 정리
            timestamps[:] = [t for t in timestamps if t > smtp_cutoff]
            if not timestamps:
                expired_smtp.append(src_ip)
                continue
            if len(timestamps) >= self._smtp_auth_threshold:
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="SMTP AUTH Brute Force",
                    description=(
                        f"SMTP AUTH brute force detected from {src_ip}: "
                        f"{len(timestamps)} attempts in {self._smtp_auth_window}s"
                    ),
                    source_ip=src_ip,
                    confidence=0.8,
                    metadata={
                        "protocol": "smtp",
                        "attempt_count": len(timestamps),
                        "window_seconds": self._smtp_auth_window,
                    },
                ))
                # 반복 알림 방지를 위해 알림 후 리셋
                timestamps.clear()

        for ip in expired_smtp:
            self._smtp_auth_attempts.pop(ip, None)

        # FTP 로그인 실패 무차별 대입 검사
        ftp_cutoff = now - self._ftp_fail_window
        expired_ftp: list[str] = []
        for src_ip, timestamps in self._ftp_fail_attempts.items():
            timestamps[:] = [t for t in timestamps if t > ftp_cutoff]
            if not timestamps:
                expired_ftp.append(src_ip)
                continue
            if len(timestamps) >= self._ftp_fail_threshold:
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="FTP Login Brute Force",
                    description=(
                        f"FTP login brute force detected from {src_ip}: "
                        f"{len(timestamps)} failed attempts in {self._ftp_fail_window}s"
                    ),
                    source_ip=src_ip,
                    confidence=0.8,
                    metadata={
                        "protocol": "ftp",
                        "attempt_count": len(timestamps),
                        "window_seconds": self._ftp_fail_window,
                    },
                ))
                timestamps.clear()

        for ip in expired_ftp:
            self._ftp_fail_attempts.pop(ip, None)

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._alerted_banners.clear()
        self._alerted_ssh_banners.clear()
        self._smtp_auth_attempts.clear()
        self._ftp_fail_attempts.clear()
