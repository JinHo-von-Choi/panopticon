"""엔진 설정의 엄격 검증 계층 (PR 03).

기존 ``validate_config()`` 는 경고 문자열을 반환할 뿐 설정 적용을 막지 않는다.
그 결과 허용되지 않은 키, bool→int 강제 변환, NaN, 기본값 생략이 그대로 런타임에
들어갈 수 있었다. 이 모듈은 그 문제를 *거부 기반*으로 바꾼다.

검증 단계
    1. **스키마 선언 검사** — 선언 없는 설정 키는 무조건 오류
       (``config_schema`` 에 없는 파라미미터가 엔진에서 읽히면 조용히 무시된다)
    2. **타입 검사** — bool 은 int/float 로 강제 변환하지 않는다
    3. **유한성 검사** — NaN/Inf 거부
    4. **범위 검사** — 스키마의 min/max
    5. **누적 제한 검사** — 여러 항목이 합쳐 한계를 넘는 조합(예: cooldown=0 과
       window=0) 거부

``validate_engine_config()`` 는 예외가 아니라 구조화된 오류 목록을 반환한다.
API 계층은 이를 400 응답으로 매핑한다.

작성자: 최진호
작성일: 2026-10-05
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from netwatcher.detection.schema_utils import normalize_schema

# 엔진이 예약하는 키. config_schema 에 없어도 항상 허용한다.
RESERVED_KEYS = frozenset({"enabled", "tick_interval"})

# 누적 제한 규칙. 각 규칙은 관련 키들의 곱/합이 상한을 넘는지 검사한다.
# intent 는 사람이 읽는 제한의 목적을 남긴다.
CUMULATIVE_LIMITS: tuple[dict[str, Any], ...] = (
    {
        "keys": ("window_seconds", "cooldown_seconds"),
        "max_product": 86400 * 365,
        "intent": "윈도와 쿨다운의 곱이 1년치를 넘으면 탐지창이 사실상 무한대가 된다",
    },
    {
        "keys": ("max_tracked_hosts",),
        "max_value": 1_000_000,
        "intent": "추적 호스트 상한이 너무 커 메모리를 장악한다",
    },
)


@dataclass(frozen=True)
class ConfigViolation:
    """설정 검증 위반 1건."""

    key: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"key": self.key, "code": self.code, "message": self.message}

    def __str__(self) -> str:
        return f"[{self.code}] {self.key}: {self.message}"


class _TypeSpec:
    """정규화된 필드 정의의 타입 판정을 담당한다."""

    def __init__(self, field_type: Any) -> None:
        self.field_type = field_type

    def accepts(self, value: Any) -> bool:
        expected = self.field_type
        if expected is bool:
            return isinstance(value, bool)
        if expected is int:
            # bool 은 int 의 하위 타입이지만 설정에서 의미가 다르다 (True → 1).
            return isinstance(value, int) and not isinstance(value, bool)
        if expected is float:
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected is list:
            return isinstance(value, list)
        if expected is str:
            return isinstance(value, str)
        if expected is dict:
            return isinstance(value, dict)
        return isinstance(value, expected)

    def type_name(self) -> str:
        return getattr(self.field_type, "__name__", str(self.field_type))

    def coerce(self, value: Any) -> Any:
        """float 스키마에 int 가 온 경우에만 승격한다."""
        if self.field_type is float and isinstance(value, int) and not isinstance(value, bool):
            return float(value)
        return value


def validate_engine_config(
    schema: dict[str, Any] | None,
    config: dict[str, Any],
    *,
    strict_keys: bool = True,
    allow_partial: bool = False,
) -> list[ConfigViolation]:
    """엔진 설정 dict를 스키마에 대해 검증한다.

    Args:
        schema: 엔진의 ``config_schema``. None/빈 dict면 키 선언 검사를 건너뛴다.
        config: 검증할 설정 dict.
        strict_keys: 스키마에 없는 키를 오류로 처리할지 여부.
        allow_partial: True 면 스키마 필드 중 설정에 없는 것을 허용한다
            (부분 업데이트용). 스키마에 없는 키 검사는 항상 수행한다.

    Returns:
        위반 목록. 빈 목록이면 검증 통과.
    """
    violations: list[ConfigViolation] = []
    if not isinstance(config, dict):
        return [ConfigViolation(key="<root>", code="V-000", message="설정은 dict 여야 한다")]

    normalized = normalize_schema(schema) if schema else {}

    # 1) 스키마 선언 검사
    if strict_keys and normalized:
        allowed = set(normalized) | set(RESERVED_KEYS)
        for key in config:
            if key not in allowed:
                violations.append(ConfigViolation(
                    key=key,
                    code="V-001",
                    message="config_schema에 선언되지 않은 키 (엔진에서 읽히지 않는다)",
                ))

    # 2~4) 필드별 타입·유한성·범위 검사
    for key, field in normalized.items():
        if key not in config:
            if not allow_partial:
                violations.append(ConfigViolation(
                    key=key,
                    code="V-002",
                    message=f"필수 설정 누락 (기본값: {field['default']!r})",
                ))
            continue

        value = config[key]
        if value is None:
            violations.append(ConfigViolation(
                key=key, code="V-003", message="값이 null이다",
            ))
            continue

        spec = _TypeSpec(field["type"])
        if not spec.accepts(value):
            violations.append(ConfigViolation(
                key=key,
                code="V-010",
                message=f"expected {spec.type_name()}, got {type(value).__name__} (value={value!r})",
            ))
            continue

        coerced = spec.coerce(value)
        if isinstance(coerced, (int, float)) and not isinstance(coerced, bool):
            if not math.isfinite(coerced):
                violations.append(ConfigViolation(
                    key=key,
                    code="V-011",
                    message=f"값이 유한하지 않다 (NaN/Inf는 비교·직렬화가 깨진다): {value!r}",
                ))
                continue

            min_val = field.get("min")
            max_val = field.get("max")
            if min_val is not None and coerced < min_val:
                violations.append(ConfigViolation(
                    key=key, code="V-020", message=f"{coerced!r} 이(가) 최소값 {min_val} 미만",
                ))
            if max_val is not None and coerced > max_val:
                violations.append(ConfigViolation(
                    key=key, code="V-021", message=f"{coerced!r} 이(가) 최대값 {max_val} 초과",
                ))

            # 창·쿨다운 계열은 0 이거나 음수면 탐지가 성립하지 않는다.
            if key.endswith(("_seconds", "_window", "_interval")) and coerced <= 0:
                violations.append(ConfigViolation(
                    key=key, code="V-022", message="시간 기반 파라미터는 0보다 커야 한다",
                ))

    # 5) 누적 제한 검사
    violations.extend(_check_cumulative(config))

    return violations


def _check_cumulative(config: dict[str, Any]) -> list[ConfigViolation]:
    """키 조합이 Together 어긋나는 규칙을 검사한다."""
    out: list[ConfigViolation] = []
    for rule in CUMULATIVE_LIMITS:
        max_value = rule.get("max_value")
        if max_value is not None:
            for key in rule["keys"]:
                raw = config.get(key)
                if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                    continue
                if raw > max_value:
                    out.append(ConfigViolation(
                        key=key,
                        code="V-030",
                        message=f"{raw!r} 은(는) 상한 {max_value} 초과 — {rule['intent']}",
                    ))

        max_product = rule.get("max_product")
        if max_product is None:
            continue
        product = 1
        used: list[str] = []
        for key in rule["keys"]:
            raw = config.get(key)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                continue
            product *= abs(raw)
            used.append(key)
        if used and product > max_product:
            out.append(ConfigViolation(
                key="+".join(rule["keys"]),
                code="V-031",
                message=f"누적 값 {product!r} 이(가) 상한 {max_product} 초과 — {rule['intent']}",
            ))
    return out


def assert_valid_engine_config(
    schema: dict[str, Any] | None,
    config: dict[str, Any],
    *,
    engine_name: str = "",
    allow_partial: bool = False,
) -> None:
    """검증 실패 시 :class:`ValueError` 를 던지는 편의 함수."""
    violations = validate_engine_config(schema, config, allow_partial=allow_partial)
    if not violations:
        return
    prefix = f"{engine_name}: " if engine_name else ""
    detail = "; ".join(str(v) for v in violations)
    raise ValueError(f"{prefix}설정 검증 실패 ({len(violations)}건): {detail}")
