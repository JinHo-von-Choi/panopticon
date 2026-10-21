"""판정 계약 — 사건 판정과 작업 범위가 함께 쓰는 규칙.

여기에는 저장을 하지 않는다. 두 모듈이 서로를 부르지 않도록 계약만
모아 둔다.
"""

from __future__ import annotations

# 사람이 "정상" 이라고 확정한 판정.
NORMAL_DECISIONS = frozenset({"expected_backup", "approved_maintenance"})


class ReviewConflict(ValueError):
    """판정·작업 범위가 충돌했다."""


def event_scope(event):
    """사건에서 같은 대상을 가리키는 범위 값을 뽑는다."""
    external = (event.get("metadata") or {}).get("external_eve") or {}
    return {"source_ip": str(event.get("source_ip") or ""),
            "source_mac": str(event.get("source_mac") or "").lower(),
            "dest_ip": str(event.get("dest_ip") or ""),
            "dest_mac": str(event.get("dest_mac") or "").lower(),
            "flow_id": external.get("flow_id"),
            "observed_at": str(event.get("timestamp") or ""),
            "sensor_id": external.get("sensor_id"), "source_id": external.get("source_id"),
            "src_port": external.get("src_port"), "dest_port": external.get("dest_port"),
            "protocol": external.get("proto"),
            "signature_id": (external.get("details") or {}).get("signature_id")}
