"""분석 경험 라이브러리 — 사람이 확정한 판정을 다시 쓰는 원장.

경험 항목은 **실행 대비가 뒷받침할 때만** 만들어진다. 비교가 없거나 비교가
사람의 판정과 어긋나면 항목을 만들지 않는다 — 근거 없는 교훈은 다음 제안의
판정을 망친다.

교훈이 다시 쓰이는 곳은 새 제안 프롬프트다. 같은 신호의 과거 판정을
"PAST VERDICTS" 로 주입한다. 지난 판정만으로 새 판정을 대신하지 않는다 —
주입은 문맥일 뿐이다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
# 사람이 "정상" 이라고 확정한 판정.
NORMAL_DECISIONS = frozenset({"expected_backup", "approved_maintenance"})

# 엔진별 기본 도메인. 네트워크별 특성(프린터 스캔, NAS 백업 등)은 서명에
# 붙은 단어로 더 구체화한다.
ENGINE_DOMAINS = {
    "port_scan": "network_scan",
    "dns_anomaly": "dns",
    "arp_spoof": "layer2",
    "data_exfil": "exfiltration",
    "protocol_anomaly": "protocol",
    "http_suspicious": "http",
    "behavior_profile": "behavior",
    "traffic_anomaly": "traffic",
    "dhcp_spoof": "dhcp",
    "ransomware_lateral": "ransomware",
}

# 서명에 붙은 단어가 있으면 도메인을 더 좁힌다.
DOMAIN_TRAITS = (
    ("printer", "printer"),
    ("nas", "nas"),
    ("backup", "backup"),
    ("beacon", "beacon"),
    ("exfil", "exfiltration"),
    ("c2", "command_control"),
)

# 경험 항목의 기본 유효 기간. 같은 신호의 판정은 오래 갈수록 어긋난다.
DEFAULT_EXPIRY_DAYS = 180

# 주입할 과거 판정의 상한.
DEFAULT_LIMIT = 5


class ExperienceError(ValueError):
    """경험 항목을 만들 수 없는 상태."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def signature_of(event: Mapping[str, Any]) -> str:
    """사건의 신호를 식별하는 서명을 만든다.

    같은 엔진의 같은 규칙이면 같은 서명이다. 제목 문자열은 쓰지 않는다 —
    문구는 바뀌지만 신호는 같기 때문이다.
    """
    engine = str(event.get("engine") or "")
    metadata = event.get("metadata") or {}
    rule = str(
        event.get("title_key")
        or metadata.get("rule_id")
        or metadata.get("signature_id")
        or event.get("engine")
        or ""
    )
    return f"{engine}:{rule}"[:160]


def domain_of(engine: str, signature: str) -> str:
    """엔진과 서명에서 도메인을 유도한다."""
    base = ENGINE_DOMAINS.get(engine, "general")
    lowered = signature.lower()
    for keyword, trait in DOMAIN_TRAITS:
        if keyword in lowered:
            return f"{base}:{trait}"[:96]
    return base[:96]


def _probe_of(proposal: Mapping[str, Any]) -> Mapping[str, Any]:
    probe = proposal.get("probe")
    return probe if isinstance(probe, Mapping) else {}


def check_adoption(
    *,
    proposal: Mapping[str, Any],
    review: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """채택 조건을 검사한다. 통과하면 근거를 돌려준다.

    실패하면 이유가 붙은 ExperienceError 를 던진다.
    """
    probe = _probe_of(proposal)
    if probe.get("status") != "compared":
        raise ExperienceError(
            "실행 대비가 없다 — 대비가 뒷받침할 때만 교훈을 남긴다",
            "no_comparison",
        )
    if probe.get("comparable") is not True:
        raise ExperienceError(
            "실행 대비가 비교 가능하지 않다", "comparison_not_comparable",
        )

    counts = probe.get("counts") or {}
    removed = int(counts.get("removed") or 0)
    added = int(counts.get("added") or 0)
    changed = int(counts.get("changed") or 0)
    if removed + added + changed == 0:
        raise ExperienceError(
            "대비가 관측을 바꾸지 않았다 — 뒷받침할 차이가 없다",
            "no_observed_difference",
        )

    decision = str(review.get("decision") or "")
    if decision not in NORMAL_DECISIONS:
        raise ExperienceError(
            "사람의 판정이 정상 판정이 아니다", "review_not_normal",
        )

    engine = str(proposal.get("engine") or "")
    if str(event.get("engine") or "") != engine:
        raise ExperienceError(
            "제안과 판정의 대상 엔진이 다르다", "engine_mismatch",
        )

    if removed == 0 or added > 0:
        raise ExperienceError(
            "사람의 판정과 실행 대비의 방향이 다르다 — 후보 제안이 관측을 늘린다",
            "direction_mismatch",
        )

    return {
        "probe": probe,
        "counts": {"removed": removed, "added": added, "changed": changed},
        "decision": decision,
    }


def build_candidate(
    *,
    proposal: Mapping[str, Any],
    review: Mapping[str, Any],
    event: Mapping[str, Any],
    now: datetime | None = None,
    expiry_days: int = DEFAULT_EXPIRY_DAYS,
) -> dict[str, Any]:
    """채택 가능한 경험 항목을 만든다."""
    support = check_adoption(proposal=proposal, review=review, event=event)
    engine = str(proposal.get("engine") or "")
    signature = signature_of(event)
    domain = domain_of(engine, signature)

    note = str(review.get("note") or "").strip()
    params = proposal.get("params") or {}
    before = proposal.get("before") or {}
    changes = ", ".join(
        f"{key} {before.get(key)} → {value}" for key, value in sorted(params.items())
    )
    cue = f"{signature} · {review.get('actor') or 'unknown'} · {note}"[:1000]
    lesson = (
        f"정상 판정({support['decision']}) — {changes or '설정 변경'} 적용 후 "
        f"관측 {support['counts']['removed']}건이 사라졌다"
    )[:1000]
    evidence = {
        "probe": {
            "counts": support["counts"],
            "input_hash": support["probe"].get("input_hash", ""),
            "engine": support["probe"].get("engine", engine),
        },
        "review": {
            "event_id": review.get("event_id"),
            "decision": support["decision"],
            "note": note,
            "actor": str(review.get("actor") or "")[:255],
        },
        "proposal": {
            "id": proposal.get("id"),
            "params": dict(params),
            "before": dict(before),
        },
    }
    confidence = 0.5
    confidence += 0.2
    if support["decision"] == "expected_backup":
        confidence += 0.1
    confidence = min(confidence, 0.9)

    moment = now or datetime.now(timezone.utc)
    return {
        "engine": engine,
        "signature": signature,
        "domain": domain,
        "cue": cue,
        "lesson": lesson,
        "evidence": evidence,
        "confidence": confidence,
        "source_proposal_id": proposal.get("id"),
        "source_review_id": review.get("event_id"),
        "expires_at": (moment + timedelta(days=expiry_days)).isoformat(),
    }


def format_past_verdicts(rows: list[Mapping[str, Any]]) -> str:
    """과거 판정을 프롬프트에 넣을 문장으로 만든다."""
    if not rows:
        return ""
    lines = ["PAST VERDICTS (같은 신호의 과거 판정 — 참고일 뿐이다):"]
    for row in rows:
        confidence = row.get("confidence")
        if confidence is None:
            confidence_text = "-"
        else:
            try:
                confidence_text = f"{float(confidence):.2f}"
            except (TypeError, ValueError):
                confidence_text = "-"
        created = str(row.get("created_at") or "")[:10]
        lines.append(
            f"- [{created}] {row.get('domain')} · 신뢰도 {confidence_text} · "
            f"{row.get('lesson')}"
        )
    return "\n".join(lines)


class ExperienceService:
    """경험 라이브러리의 입구.

    제안·판정·사건을 읽어 채택 후보를 만들고, 사람이 승인하면 항목을 남긴다.
    """

    def __init__(
        self,
        *,
        proposal_repo: Any,
        event_repo: Any,
        experience_repo: Any,
        reviews: Any = None,
    ) -> None:
        self._proposals = proposal_repo
        self._events = event_repo
        self._experiences = experience_repo
        self._reviews = reviews

    async def candidate(
        self, proposal_id: int, review_id: int | None = None,
    ) -> dict[str, Any]:
        """채택 후보를 만든다. 만들 수 없으면 사유가 붙은 오류를 던진다."""
        proposal = await self._proposals.get_by_id(proposal_id)
        if proposal is None:
            raise ExperienceError("제안을 찾을 수 없다", "proposal_missing")
        if review_id is None:
            review_id = await self._experiences.latest_review_id_for_engine(
                str(proposal.get("engine") or ""),
            )
        if review_id is None:
            raise ExperienceError("같은 엔진의 판정이 없다", "review_missing")
        review = await self._reviews.raw(review_id) if self._reviews is not None else None
        if review is None:
            raise ExperienceError("판정을 찾을 수 없다", "review_missing")
        event = await self._events.get(review_id)
        if event is None:
            raise ExperienceError("판정 대상 사건을 찾을 수 없다", "event_missing")
        return build_candidate(proposal=proposal, review=review, event=event)

    async def adopt(
        self, proposal_id: int, review_id: int | None = None, actor: str = "system",
    ) -> dict[str, Any]:
        """사람의 승인을 받아 경험 항목을 남긴다."""
        candidate = await self.candidate(proposal_id, review_id)
        experience_id = await self._experiences.insert(candidate)
        return {"id": experience_id, "adopted_by": str(actor)[:100], **candidate}

    async def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return await self._experiences.list_recent(limit)

    async def matching(
        self, engine: str, signature: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        return await self._experiences.list_by_signature(engine, signature, limit)

    async def matching_many(
        self, signatures: list[tuple[str, str]], limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        return await self._experiences.list_by_signatures(signatures, limit)
