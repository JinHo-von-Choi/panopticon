"""지원 프로필(Support Profile) 계약 — 미지원 구성 조합의 조기 거부.

실행계획의 PR 01 요구를 구현한다. "비활성화는 결함 수정 완료가 아니다"는 원칙에
따라, 검증 통과 여부를 실제 enforcement·검증 게이트로 오인하지 못하게 하는 것이
이 모듈의 목적이다.

지원 프로필은 다음 두 가지를 함께 고정한다.

1. **프로필** (``support.profile``)
   - ``limited`` (기본값): 단일 센서·단일 워커·HA 꺼짐·AI 제안 전용.
     첫 제한 릴리스(PR 01~11)의 프로필.
   - ``full``: 배포 선택 폭을 넓히지만 상태·부작용 조합 검증이 아직 없다.
2. **구성 조합 검증**
   프로필과 무관하게 *구현되지 않았거나 검증되지 않은* 조합은 항상 거부한다.
   예를 들어 nftables 백엔드는 플레이스홀더만 존재하므로 어떤 프로필에서도
   enforcement로 인정하지 않는다.

거부 시 예외 대신 예외 목록을 먼저 계산할 수 있어, CLI·테스트·대시보드가
같은 판단을 재사용한다.

작성자: 최진호
작성일: 2026-10-05
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import Any, Iterable

logger = logging.getLogger("netwatcher.support")

# 지원 프로필 이름
PROFILE_LIMITED = "limited"
PROFILE_FULL = "full"
SUPPORTED_PROFILES = (PROFILE_LIMITED, PROFILE_FULL)

# PostgreSQL ssl_mode 허용 값 (Config가 그대로 DSN에 전달한다)
SUPPORTED_SSL_MODES = (
    "disable", "allow", "prefer", "require", "verify-ca", "verify-full",
)

# enforcement 백엔드 중 실제 구현·검증이 끝난 것
IMPLEMENTED_ENFORCEMENT_BACKENDS = ("iptables",)
# BlockManager가 생성자를 통과시킬 수 있지만 enforcement가 아니다
NON_ENFORCEMENT_BACKENDS = ("mock",)


@dataclass(frozen=True)
class Violation:
    """지원 계약 위반 1건."""

    code: str
    path: str
    message: str
    remediation: str = ""

    def as_dict(self) -> dict[str, str]:
        """API/로그 직렬화용 dict로 변환한다."""
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "remediation": self.remediation,
        }

    def __str__(self) -> str:
        base = f"[{self.code}] {self.path}: {self.message}"
        return f"{base} → {self.remediation}" if self.remediation else base


class UnsupportedConfigurationError(RuntimeError):
    """지원되지 않는 구성 조합으로 기동을 거부한다."""

    def __init__(self, violations: Iterable[Violation]) -> None:
        self.violations: list[Violation] = list(violations)
        detail = "\n".join(f"  - {v}" for v in self.violations)
        super().__init__(
            f"지원 프로필 검증 실패 ({len(self.violations)}건):\n{detail}"
        )


def _is_loopback_host(host: Any) -> bool:
    """바인드 주소가 루프백인지 판단한다. 값이 없으면 외부 노출로 간주한다."""
    if not isinstance(host, str) or not host.strip():
        return False
    value = host.strip()
    if value in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _as_bool(value: Any) -> bool:
    """YAML/env의 bool 표현을 견고하게 해석한다."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    return bool(value)


class SupportContract:
    """설정 객체에 대한 지원 프로필 검증기.

    Parameters
    ----------
    config:
        :class:`netwatcher.utils.config.Config` 인스턴스. ``raw`` dict를 사용한다.
    profile:
        프로필 이름. ``None``이면 ``support.profile`` → ``NETWATCHER_SUPPORT_PROFILE``
        → ``limited`` 순으로 결정한다.
    """

    def __init__(self, config: Any, profile: str | None = None) -> None:
        self._config = config
        self._raw: dict[str, Any] = getattr(config, "raw", {}) or {}
        self.profile = self._resolve_profile(profile)

    # ------------------------------------------------------------------
    # 프로필 결정
    # ------------------------------------------------------------------

    def _resolve_profile(self, profile: str | None) -> str:
        if profile:
            return str(profile)
        env_profile = os.environ.get("NETWATCHER_SUPPORT_PROFILE", "").strip()
        if env_profile:
            return env_profile
        section = self._raw.get("support")
        if isinstance(section, dict):
            declared = section.get("profile")
            if declared:
                return str(declared)
        return PROFILE_LIMITED

    # ------------------------------------------------------------------
    # 설정 접근 헬퍼
    # ------------------------------------------------------------------

    def get(self, dotted: str, default: Any = None) -> Any:
        """점 표기법으로 설정을 조회한다."""
        getter = getattr(self._config, "get", None)
        if callable(getter):
            value = getter(dotted, None)
            if value is not None:
                return value
        current: Any = self._raw
        for key in dotted.split("."):
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current

    def _flag(self, dotted: str) -> bool:
        return _as_bool(self.get(dotted, False))

    # ------------------------------------------------------------------
    # 검증
    # ------------------------------------------------------------------

    def violations(self) -> list[Violation]:
        """현재 설정의 위반 목록을 계산한다. 빈 목록이면 지원 조합이다."""
        found: list[Violation] = []
        found.extend(self._check_profile_name())
        found.extend(self._check_enforcement())
        found.extend(self._check_ai_apply_mode())
        found.extend(self._check_web_exposure())
        found.extend(self._check_auth())
        found.extend(self._check_database())
        found.extend(self._check_limited_profile())
        return found

    def enforce(self) -> None:
        """위반이 있으면 :class:`UnsupportedConfigurationError`를 던진다."""
        found = self.violations()
        if found:
            raise UnsupportedConfigurationError(found)
        logger.info(
            "지원 프로필 검증 통과 (profile=%s): 차단·승인 기능이 "
            "운영 검증을 통과했다는 의미는 아님",
            self.profile,
        )

    def describe(self) -> dict[str, Any]:
        """대시보드/상태 API가 소비하는 지원 계약 요약."""
        return {
            "profile": self.profile,
            "supported_profiles": list(SUPPORTED_PROFILES),
            "enforcement_backends": list(IMPLEMENTED_ENFORCEMENT_BACKENDS),
            "violations": [v.as_dict() for v in self.violations()],
        }

    # -- 개별 검사 -----------------------------------------------------

    def _check_profile_name(self) -> list[Violation]:
        if self.profile in SUPPORTED_PROFILES:
            return []
        return [Violation(
            code="SUP-000",
            path="support.profile",
            message=f"알 수 없는 지원 프로필 {self.profile!r}",
            remediation=f"지원 프로필 중 하나를 지정: {', '.join(SUPPORTED_PROFILES)}",
        )]

    def _check_enforcement(self) -> list[Violation]:
        """방화벽 enforcement 백엔드가 실제로 구현·검증되었는지 확인한다."""
        if not self._flag("response.enabled"):
            return []

        backend = str(self.get("response.backend", "iptables"))
        out: list[Violation] = []

        if backend in NON_ENFORCEMENT_BACKENDS:
            out.append(Violation(
                code="SUP-001",
                path="response.backend",
                message=f"backend={backend!r} 은 enforcement가 아니다",
                remediation="response.enabled=false 로 두거나 iptables backend 사용",
            ))
        elif backend not in IMPLEMENTED_ENFORCEMENT_BACKENDS:
            out.append(Violation(
                code="SUP-002",
                path="response.backend",
                message=(
                    f"backend={backend!r} 은 아직 구현되지 않았다 "
                    "(규칙의 적용·만료·복구 경로가 없음)"
                ),
                remediation="nftables는 PR 14의 TTL 게이트 통과 후에만 허용된다",
            ))

        duration = self.get("response.default_duration", 3600)
        try:
            duration_value = int(duration)
        except (TypeError, ValueError):
            out.append(Violation(
                code="SUP-003",
                path="response.default_duration",
                message=f"정수여야 하는 값이 들어왔다: {duration!r}",
                remediation="response.default_duration 을 정수로 지정",
            ))
        else:
            if duration_value <= 0:
                out.append(Violation(
                    code="SUP-004",
                    path="response.default_duration",
                    message="영구 차단은 지원 범위 밖이다",
                    remediation="양수 TTL(예: 300)을 지정",
                ))

        if self.get("response.chain_name", "NETWATCHER_BLOCK") == "INPUT":
            out.append(Violation(
                code="SUP-005",
                path="response.chain_name",
                message="INPUT 체인을 직접 사용하면 관측 범위 밖 트래픽까지 막는다",
                remediation="전용 체인 이름을 사용",
            ))
        return out

    def _check_ai_apply_mode(self) -> list[Violation]:
        """AI는 제안만 할 수 있다. 설정 쓰기 권한은 없어야 한다."""
        if not self._flag("ai_analyzer.enabled"):
            return []
        mode = str(self.get("ai_analyzer.apply_mode", "propose"))
        if mode == "propose":
            return []
        return [Violation(
            code="SUP-010",
            path="ai_analyzer.apply_mode",
            message=f"apply_mode={mode!r} 은 지원 범위 밖이다 (AI는 승인·scope·TTL을 결정하지 않는다)",
            remediation="ai_analyzer.apply_mode: propose (기본값) 유지",
        )]

    def _check_web_exposure(self) -> list[Violation]:
        """인증 없는 대시보드가 외부 인터페이스에 열리면 기동을 거부한다."""
        host = self.get("web.host", "0.0.0.0")
        if _is_loopback_host(host):
            return []
        if self._flag("auth.enabled"):
            return []

        out = [Violation(
            code="SUP-020",
            path="web.host",
            message=f"인증이 비활성화된 상태로 {host!r} 에 바인드된다",
            remediation=(
                "auth.enabled=true + NETWATCHER_LOGIN_PASSWORD 설정, "
                "또는 web.host 를 127.0.0.1 로 한정"
            ),
        )]

        origins = self.get("web.cors.allowed_origins", []) or []
        if isinstance(origins, (list, tuple)) and any(str(o) == "*" for o in origins):
            out.append(Violation(
                code="SUP-021",
                path="web.cors.allowed_origins",
                message="인증 없이 CORS 와일드카드가 허용된다",
                remediation="명시적 origin 목록으로 교체",
            ))
        return out

    def _check_auth(self) -> list[Violation]:
        """인증 설정 자체의 안전성."""
        if not self._flag("auth.enabled"):
            return []
        out: list[Violation] = []

        secret = os.environ.get("NETWATCHER_JWT_SECRET", "").strip()
        if not secret:
            secret = str(self.get("auth.jwt_secret", "") or "").strip()
        if not secret:
            out.append(Violation(
                code="SUP-030",
                path="auth.jwt_secret",
                message="JWT secret 이 없어 기동마다 자동 생성된다 (기존 토큰이 무효화됨)",
                remediation="NETWATCHER_JWT_SECRET 환경변수를 명시적으로 설정",
            ))

        try:
            hours = int(self.get("auth.token_expire_hours", 24))
        except (TypeError, ValueError):
            hours = 24
        if hours <= 0:
            out.append(Violation(
                code="SUP-031",
                path="auth.token_expire_hours",
                message="토큰 만료 시간이 0 이하다",
                remediation="양수 시간을 지정",
            ))

        if _as_bool(self.get("auth.multi_user", False)):
            out.append(Violation(
                code="SUP-032",
                path="auth.multi_user",
                message="multi_user 는 단일 사용자 JWT 만 검증된 상태다",
                remediation="multi_user=false 유지 (권한 분리 확장은 별도 지원)",
            ))
        return out

    def _check_database(self) -> list[Violation]:
        out: list[Violation] = []
        ssl_mode = str(self.get("postgresql.ssl_mode", "disable"))
        if ssl_mode not in SUPPORTED_SSL_MODES:
            out.append(Violation(
                code="SUP-040",
                path="postgresql.ssl_mode",
                message=f"지원하지 않는 ssl_mode: {ssl_mode!r}",
                remediation=f"허용 값: {', '.join(SUPPORTED_SSL_MODES)}",
            ))

        port = self.get("postgresql.port", 5432)
        try:
            port_value = int(port)
        except (TypeError, ValueError):
            out.append(Violation(
                code="SUP-041",
                path="postgresql.port",
                message=f"정수여야 하는 포트 값: {port!r}",
                remediation="숫자로 지정",
            ))
        else:
            if not 1 <= port_value <= 65535:
                out.append(Violation(
                    code="SUP-042",
                    path="postgresql.port",
                    message=f"포트 범위를 벗어났다: {port_value}",
                    remediation="1-65535 사이의 값 지정",
                ))
        return out

    def _check_limited_profile(self) -> list[Violation]:
        """제한 프로필에서 지원하지 않는 운영 모드를 거부한다."""
        if self.profile != PROFILE_LIMITED:
            return []
        out: list[Violation] = []

        workers = self.get("workers", 1)
        try:
            workers_value = int(workers)
        except (TypeError, ValueError):
            workers_value = 1
        if workers_value > 1:
            out.append(Violation(
                code="SUP-050",
                path="workers",
                message=f"workers={workers_value} 는 워커 정책 전파 게이트(G6) 통과 전이다",
                remediation="workers=1 로 두거나 support.profile 을 full 로 올린 뒤 검증",
            ))

        if self._flag("ha.enabled"):
            out.append(Violation(
                code="SUP-051",
                path="ha.enabled",
                message="HA fencing 게이트(G7) 통과 전이다",
                remediation="ha.enabled=false 유지",
            ))
        return out


def validate_support(config: Any, profile: str | None = None) -> list[Violation]:
    """편의 함수: 위반 목록만 반환한다."""
    return SupportContract(config, profile=profile).violations()


def enforce_support(config: Any, profile: str | None = None) -> SupportContract:
    """편의 함수: 위반이 있으면 예외, 없으면 계약 객체를 반환한다."""
    contract = SupportContract(config, profile=profile)
    contract.enforce()
    return contract
