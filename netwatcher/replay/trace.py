"""Trace — 재현 가능한 입��� (계획서 1장).

    "Trace 에는 입력 종류 · 해시 · 순서 · tick 일정 · 워밍업 구간 또는
     호환 상태 snapshot 을 기록한다."
    "패킷별 영구 기록 대신 필요한 근거만 저장한다."
    "payload 엔진은 원본이 없으면 '재현 불가' 이며, 해시나 화면 요약으로
     원본을 대신하지 않는다."

그래서 trace 는 **원본 바이트가 아니라 특징값 레코드 목록** 이다. 그 레코드가
분석기에 필요한 필드만 담는다. 그리고 두 가지를 반드시 명시한다.

- ``complete``        입력이 잘렸는가
- ``payload_engines`` 원본이 없어 재현 불가한 엔진 목록

이 둘이 False/비어 있지 않으면 재실행은 "같은 입력" 이 아니다. 그 사실을
숨기지 않고 비교 불가 사유로 올린다.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Sequence

# 재현을 위해 기록해야 하는 필드. 이 밖의 값은 저장하지 않는다.
RECORDED_FIELDS = (
    "src_ip", "dst_ip", "src_mac", "dst_mac",
    "dst_port", "bytes", "ts", "ip_proto",
)

# payload 를 읽어야만 판단 가능한 엔진 — 원본이 없으면 재현 불가
PAYLOAD_ENGINES: tuple[str, ...] = (
    "http_suspicious", "dns_response", "protocol_inspect", "file_extraction",
)

INPUT_TYPE_FEATURES = "features"
INPUT_TYPE_PAYLOAD = "payload"


@dataclass
class Trace:
    """재현 단위 입력."""

    trace_id: str
    records: list[dict] = field(default_factory=list)
    input_type: str = INPUT_TYPE_FEATURES
    complete: bool = True
    payload_engines: tuple[str, ...] = ()
    tick_schedule: list[int] = field(default_factory=list)
    warmup: dict[str, Any] = field(default_factory=dict)
    compat_snapshot: dict[str, Any] = field(default_factory=dict)
    engines: tuple[str, ...] = ()

    @property
    def input_count(self) -> int:
        return len(self.records)

    @property
    def size_bytes(self) -> int:
        return len(json.dumps(self.records, sort_keys=True, ensure_ascii=False))

    def input_hash(self) -> str:
        """입력 해시 — 순서와 값이 모두 반영된다."""
        blob = json.dumps(
            self.records, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def order_key(self) -> str:
        """입력 순서 해시. 같은 값·다른 순서는 다른 입력이어야 한다."""
        keys = [
            f"{r.get('ts')}:{r.get('src_ip')}:{r.get('dst_ip')}:{r.get('dst_port')}"
            for r in self.records
        ]
        return hashlib.sha256("|".join(keys).encode("utf-8")).hexdigest()

    def as_row(self) -> dict[str, Any]:
        """DB 저장용."""
        return {
            "trace_id": self.trace_id,
            "input_type": self.input_type,
            "input_count": self.input_count,
            "input_hash": self.input_hash(),
            "order_key": self.order_key(),
            "tick_schedule": list(self.tick_schedule),
            "warmup": dict(self.warmup),
            "compat_snapshot": dict(self.compat_snapshot),
            "complete": self.complete,
            "payload_engines": list(self.payload_engines),
            "size_bytes": self.size_bytes,
        }


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


def build_trace(
    records: Sequence[dict],
    engines: Sequence[str],
    *,
    complete: bool = True,
    tick_seconds: int = 1,
    warmup_seconds: int = 0,
    compat_snapshot: dict[str, Any] | None = None,
) -> Trace:
    """기록으로부터 재현 입력을 만든다.

    Args:
        records: 특징값 레코드. ``RECORDED_FIELDS`` 만 남기고 버린다.
        engines: 이 trace 로 재현하려는 엔진 목록.
        complete: 입력이 잘리지 않았는지. False 면 비교 불가 사유가 된다.
        tick_seconds: 엔진 틱 주기. 틱 경계가 결과에 영향을 준다.
        warmup_seconds: 워밍업 구간. 0 이면 경계가 결과에 영향을 준다.
    """
    kept: list[dict] = []
    for rec in records:
        kept.append({f: rec[f] for f in RECORDED_FIELDS if f in rec})

    requested = list(engines)
    payload_needed = tuple(e for e in requested if e in PAYLOAD_ENGINES)

    span = 0
    if kept:
        span = int(max(r.get("ts") or 0 for r in kept) - min(r.get("ts") or 0 for r in kept))
    schedule = list(range(0, span + tick_seconds, tick_seconds)) if tick_seconds > 0 else []

    return Trace(
        trace_id=new_trace_id(),
        records=kept,
        input_type=INPUT_TYPE_FEATURES,
        complete=complete,
        payload_engines=payload_needed,
        tick_schedule=schedule,
        warmup={"seconds": warmup_seconds, "from": "trace_start"},
        compat_snapshot=dict(compat_snapshot or {}),
        engines=tuple(requested),
    )
