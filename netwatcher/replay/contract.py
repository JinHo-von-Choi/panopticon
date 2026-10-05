"""리플레이 분석 계약 (계획서 1장).

이 모듈이 정하는 것은 **무엇이 허용되고 무엇이 금지되는가** 다.

    "재실행은 운영 Dispatcher 를 호출하지 않는다.
     저장 바이트 → 파서 → 순수 분석 → 격리 결과 저장만 허용하며
     NIC 주입 · 외부 DNS/피드 조회 · 알림 · 방화벽 · 운영 DB 쓰기는 차단한다."

그래서 분석은 세 가지로만 이루어진다.

1. **저장된 입력**(trace) → 파싱된 특징값
2. **순수 분석** — 시간·피드·설정을 주입받아, 그 안에서만 판단
3. **격리 결과 저장** — `replay_results` 뿐

여기에 금지된 것이 들어오면 비교 결과는 신뢰할 수 없다. 경보가 나간 비교가
운영 경로와 같은 상태인지 말할 수 없기 때문이다. 그래서 외부 참조는
`AnalysisContract` 로만 주입하고, 그 밖의 경로는 코드에 존재하지 않게 한다
(`scripts/gates.py` G0-11 이 정적으로 확인한다).

또한 계획서는 오탐 감소를 성공으로 치지 않는다.

    "정상 여부는 담당자 확인이며 경보 감소가 오탐 감소는 아니다"

그러므로 결과는 "관측" 이다. 악성 여부를 확정하지 않는다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

# ------------------------------------------------------------------
# 비교 불가 사유 — 사유 없는 비교는 만들지 않는다
# ------------------------------------------------------------------

REASON_TRACE_INCOMPLETE = "trace_incomplete"
REASON_PAYLOAD_ENGINE = "payload_engine_no_source"
REASON_ENGINE_UNSUPPORTED = "engine_not_supported"
REASON_VERSION_MISMATCH = "version_scope_mismatch"
REASON_FEATURE_MISSING = "feature_not_recorded"
REASON_EXPIRED_EVIDENCE = "evidence_expired"
REASON_BUDGET_EXCEEDED = "budget_exceeded"

COMPARABLE_REASONS: tuple[str, ...] = (
    REASON_TRACE_INCOMPLETE,
    REASON_PAYLOAD_ENGINE,
    REASON_ENGINE_UNSUPPORTED,
    REASON_VERSION_MISMATCH,
    REASON_FEATURE_MISSING,
    REASON_EXPIRED_EVIDENCE,
    REASON_BUDGET_EXCEEDED,
)

# ------------------------------------------------------------------
# 분석 계약
# ------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisContract:
    """분석에 주입되는 모든 외부 입력.

    frozen 이라 분석 도중 값이 바뀌지 않는다. 바뀌면 같은 입력의 결과가
    달라지고, 그렇다면 그건 결함이 아니라 재현 실패다.
    """

    build_version: str = "unknown"
    config_version: str = "unknown"
    feed_version: str = "unknown"
    whitelist_version: str = "unknown"
    normalizer_version: str = "unknown"
    engine_params: dict[str, Any] = field(default_factory=dict)
    # 시간은 주입된다 — 분석 중 "지금" 을 읽으면 재현이 안 된다
    now: float = 0.0
    # 피드는 주입 스냅샷이다. 외부 조회는 금지된다
    feed_snapshot: dict[str, Any] = field(default_factory=dict)
    whitelist: tuple[str, ...] = ()

    def versions(self) -> dict[str, str]:
        return {
            "build": self.build_version,
            "config": self.config_version,
            "feed": self.feed_version,
            "whitelist": self.whitelist_version,
            "normalizer": self.normalizer_version,
        }

    def param(self, name: str, default: Any) -> Any:
        return self.engine_params.get(name, default)


# ------------------------------------------------------------------
# 관측 (악성 판정이 아니다)
# ------------------------------------------------------------------

# 관측 종류 — 엔진이 "무엇을 보았는가"
OBS_ADDRESS_BINDING = "address_binding_change"      # arp_spoof 계열 관측 의미
OBS_CONNECTION_DISTRIBUTION = "connection_attempt_distribution"  # port_scan 계열
OBS_TRANSFER_VOLUME = "transfer_volume_exceeded"    # data_exfil 계열

OBSERVATION_SEMANTICS: dict[str, str] = {
    "arp_spoof": OBS_ADDRESS_BINDING,
    "port_scan": OBS_CONNECTION_DISTRIBUTION,
    "data_exfil": OBS_TRANSFER_VOLUME,
}


@dataclass(frozen=True)
class Observation:
    """분석 결과 한 건.

    ``malicious`` 필드가 없다. 이 모듈은 악성 여부를 확정하지 않는다.
    계획서: "악성 여부를 확정하는 엔진으로 포장하지 않는다."
    """

    engine: str
    kind: str
    subject: str
    features: dict[str, Any] = field(default_factory=dict)
    observed_at: float = 0.0
    seq: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "kind": self.kind,
            "subject": self.subject,
            "features": dict(sorted(self.features.items())),
            "observed_at": self.observed_at,
            "seq": self.seq,
        }

    def key(self) -> str:
        """비교 단위. 임의 ID 는 넣지 않는다 — 실행마다 달라지므로."""
        return f"{self.engine}|{self.kind}|{self.subject}"


@dataclass
class ReplayResult:
    """한 버전 · 한 엔진의 실행 결과."""

    engine: str
    version: str
    observations: list[Observation] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        """결과 지문.

        계획서: "임의 ID 만 제외하고 경보 시점 · 순서는 유지한다."
        그러므로 시점과 순서는 해시에 포함하고, 실행마다 달라지는 ID 만
        제외한다.
        """
        return fingerprint_observations(self.observations)


def fingerprint_observations(observations: Sequence[Observation]) -> str:
    """관측 목록의 결정론적 지문.

    동일 입력 → 동일 지문 이어야 한다. 그래야 "같은 입력" 이라는 말이
    의미를 갖는다.
    """
    payload = [
        {
            "engine": o.engine,
            "kind": o.kind,
            "subject": o.subject,
            "observed_at": round(float(o.observed_at), 3),
            "seq": o.seq,
            "features": _canonical(o.features),
        }
        for o in observations
    ]
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> Any:
    """dict 키 정렬로 해시를 안정시킨다."""
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


# ------------------------------------------------------------------
# 분석기 계약
# ------------------------------------------------------------------

# 지원 엔진은 최초 3개로 제한한다 (계획서 1장).
# "각 후보는 G2·G3 를 통과한 것만 지원하고 나머지는 재현 미지원으로 남긴다"
SUPPORTED_ENGINES: tuple[str, ...] = ("arp_spoof", "port_scan", "data_exfil")

Analyzer = Callable[[Sequence[dict], AnalysisContract], list[Observation]]


def unsupported_reason(engine: str) -> str | None:
    """이 엔진을 재현할 수 없는 이유. 가능하면 None."""
    if engine not in SUPPORTED_ENGINES:
        return REASON_ENGINE_UNSUPPORTED
    return None


def iter_supported(engines: Iterable[str]) -> tuple[list[str], list[str]]:
    """지원/미지원 엔진을 나눈다. 미지원 사유는 숨기지 않는다."""
    supported: list[str] = []
    unsupported: list[str] = []
    for engine in engines:
        if unsupported_reason(engine) is None:
            supported.append(engine)
        else:
            unsupported.append(engine)
    return supported, unsupported
