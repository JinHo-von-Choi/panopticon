"""탐지 결과 계약: 요약 → 근거 → 원자료 (PR 08, 게이트 G8).

계획서의 요구는 분명하다.

    "첫 탐지 결과는 감사가 가능해야 한다"
    "요약, 근거, 원자료 세 층이 모두 있어야 한다"

이전 상태는 이랬다. 어느 엔진도 계약을 검사받지 않았고, 알림은 세 층의 유무와
무관하게 그대로 저장되었다. 그래서 "포트가 스캔되었습니다" 같은 **검증 불가능한
주장**이 근거도 원자료도 없이 DB 에 쌓였다.

이 모듈은 계약을 *강제*하는 대신 * 드러낸다 *. 누락을 조용히 채우지 않고
``metadata["evidence"]`` 에 명시해, 운영자가 "근거 없는 탐지"를 걸러낼 수 있게
한다. 근거 없는 탐지를 정상처럼 저장하는 것이 계약 위반이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 계약의 세 층
LAYER_SUMMARY = "summary"   # 무엇이 일어났는가
LAYER_EVIDENCE = "evidence"  # 왜 그렇게 판단했는가
LAYER_RAW = "raw"           # 무엇을 관측했는가 (패킷)
EVIDENCE_LAYERS = (LAYER_SUMMARY, LAYER_EVIDENCE, LAYER_RAW)

STATUS_COMPLETE = "complete"
STATUS_INCOMPLETE = "incomplete"


@dataclass
class EvidenceReport:
    """알림이 계약 세 층을 충족하는지 판정한 결과."""

    layers: dict[str, bool] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing

    @property
    def status(self) -> str:
        return STATUS_COMPLETE if self.complete else STATUS_INCOMPLETE

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "layers": dict(self.layers),
            "missing": list(self.missing),
        }


def classify_alert(alert: Any) -> EvidenceReport:
    """알림이 세 층을 갖는지 판정한다.

    판정 기준
    - **요약**: 제목이 있고, 설명이 있거나 근거가 있으면 통과
    - **근거**: ``metadata`` 에 관측값이 있거나 ``reasoning`` 이 있어야 한다
    - **원자료**: ``packet_info`` 에 패킷 내용이 있어야 한다
    """
    title = (getattr(alert, "title", "") or "").strip()
    description = (getattr(alert, "description", "") or "").strip()
    metadata = getattr(alert, "metadata", None) or {}
    packet_info = getattr(alert, "packet_info", None) or {}
    reasoning = getattr(alert, "reasoning", None)

    has_summary = bool(title) and bool(description or metadata or reasoning)
    # confidence 만으로는 근거가 아니다 — 그 값은 파이프라인이 나중에 붙인다.
    evidence_keys = {k: v for k, v in metadata.items() if k != "confidence"}
    has_evidence = bool(evidence_keys) or bool((reasoning or "").strip())
    has_raw = bool(packet_info) and bool(
        packet_info.get("layers") or packet_info.get("length")
    )

    layers = {
        LAYER_SUMMARY: has_summary,
        LAYER_EVIDENCE: has_evidence,
        LAYER_RAW: has_raw,
    }
    return EvidenceReport(
        layers=layers,
        missing=[name for name in EVIDENCE_LAYERS if not layers[name]],
    )


def apply_evidence_contract(alert: Any) -> EvidenceReport:
    """계약을 판정하고 그 결과를 알림 metadata 에 기록한다.

    누락이 있어도 저장은 막지 않는다. 대신 ``metadata["evidence"]`` 로 남겨
    "근거 없는 탐지"를 나중에 찾아낼 수 있게 한다. 없는 근거를 지어내는 것은
    감사에 가장 위험하므로 절대 하지 않는다.
    """
    report = classify_alert(alert)
    metadata = getattr(alert, "metadata", None)
    if metadata is None:
        metadata = {}
        alert.metadata = metadata
    metadata["evidence"] = report.as_dict()
    return report


def describe_contract() -> dict[str, Any]:
    """대시보드/문서가 읽는 계약 명세."""
    return {
        "layers": list(EVIDENCE_LAYERS),
        "layer_meaning": {
            LAYER_SUMMARY: "무엇이 일어났는가 (제목 + 설명)",
            LAYER_EVIDENCE: "왜 그렇게 판단했는가 (관측값·판단 근거)",
            LAYER_RAW: "무엇을 관측했는가 (패킷 상세)",
        },
        "policy": (
            "누락이 있어도 저장은 하되 metadata.evidence 로 드러낸다. "
            "근거 없는 탐지를 정상처럼 취급하지 않는 것이 목적이다."
        ),
    }
