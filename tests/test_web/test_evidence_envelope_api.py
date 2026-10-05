"""증거 봉투 API 테스트 (PR 09).

봉투는 **읽을 때 다시 판정**한다. 저장된 ``metadata["evidence"]`` 를 그대로
노출하면 계약이 도입되기 전에 저장된 행이 "검증 가능" 으로showing한다.
그래서 UI 가 보는 값은 언제나 실제 내용으로 재판정한 결과다.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.web.routes.events import _with_evidence, create_events_router


def _row(**overrides) -> dict:
    row = {
        "id": 1,
        "engine": "port_scan",
        "severity": "WARNING",
        "title": "Port scan detected",
        "description": "25 distinct ports",
        "metadata": {"count": 25, "confidence": 0.8},
        "packet_info": {"layers": ["IP", "TCP"], "length": 74},
        "timestamp": "2026-10-05T00:00:00Z",
    }
    row.update(overrides)
    return row


# ------------------------------------------------------------------
# 판정 결과 파생
# ------------------------------------------------------------------

def test_complete_alert_is_reported_complete():
    result = _with_evidence(_row())["evidence"]
    assert result["status"] == "complete"
    assert result["missing"] == []
    assert result["layers"] == {"summary": True, "evidence": True, "raw": True}


def test_confidence_is_not_counted_as_evidence():
    row = _row(metadata={"confidence": 0.9})
    result = _with_evidence(row)["evidence"]
    assert result["layers"]["evidence"] is False
    assert "evidence" in result["missing"]


def test_missing_raw_is_reported():
    row = _row(packet_info={})
    assert "raw" in _with_evidence(row)["evidence"]["missing"]


def test_stored_verdict_is_recomputed_not_trusted():
    """저장된 봉투가 'complete' 로 거짓말해도 재생성해야 한다.

    계약 이전 행은 evidence 키가 아예 없다. 그 키가 있다고 가정하면
    검증 불가능한 탐지가 검증 가능하다고 표시되는 역방향 오류가 생긴다.
    """
    # 저장값은 complete 라고 주장하지만, 실제 metadata 는 evidence 키뿐이다.
    # 그 키는 판정에서 제외되므로 근거가 없다 → complete 로 떠서는 안 된다.
    row = _row(
        metadata={"evidence": {"status": "complete", "layers": {}, "missing": []}},
    )
    result = _with_evidence(row)["evidence"]
    assert result["status"] == "incomplete", "저장된 판정을 그대로 신뢰했다"
    assert "evidence" in result["missing"]

    # 원자료가 없는 경우에도 저장값을 신뢰하지 않는다
    row2 = _row(
        metadata={"evidence": {"status": "complete", "layers": {}, "missing": []},
                  "count": 25, "confidence": 0.8},
        packet_info={},
    )
    result2 = _with_evidence(row2)["evidence"]
    assert "raw" in result2["missing"], "저장된 판정을 신뢰했다"


def test_evidence_key_is_ignored_when_recomputing():
    row = _row(metadata={"evidence": {"junk": True}})
    result = _with_evidence(row)["evidence"]
    # evidence 키 자체가 근거로 집계되지 않는다
    assert "evidence" in result["missing"]


def test_row_is_not_mutated():
    row = _row()
    snapshot = dict(row)
    _with_evidence(row)
    assert row == snapshot


def test_handles_missing_optional_fields():
    minimal = {"id": 2, "title": "t", "description": "d", "metadata": {"c": 1}}
    result = _with_evidence(minimal)["evidence"]
    assert result["layers"]["summary"] is True
    assert result["layers"]["raw"] is False


def test_handles_non_dict_metadata():
    row = _row(metadata=None, packet_info={"layers": ["IP"], "length": 1})
    result = _with_evidence(row)["evidence"]
    assert result["status"] == "incomplete"


# ------------------------------------------------------------------
# API 노출
# ------------------------------------------------------------------

def _client(rows=None, one=None) -> TestClient:
    repo = MagicMock()
    repo.list_recent = AsyncMock(return_value=rows or [])
    repo.count = AsyncMock(return_value=len(rows or []))
    repo.get_by_id = AsyncMock(return_value=one)

    dispatcher = MagicMock()
    app = FastAPI()
    app.include_router(create_events_router(repo, dispatcher), prefix="/api")
    return TestClient(app)


def test_list_endpoint_includes_evidence_envelope():
    client = _client(rows=[_row()])
    resp = client.get("/api/events")
    assert resp.status_code == 200
    ev = resp.json()["events"][0]
    assert "evidence" in ev
    assert ev["evidence"]["status"] == "complete"


def test_list_endpoint_flags_unverifiable_detections():
    client = _client(rows=[_row(metadata={"confidence": 0.9}, packet_info={})])
    ev = client.get("/api/events").json()["events"][0]
    assert ev["evidence"]["status"] == "incomplete"
    assert set(ev["evidence"]["missing"]) == {"evidence", "raw"}


def test_detail_endpoint_includes_evidence_envelope():
    client = _client(one=_row())
    resp = client.get("/api/events/1")
    assert resp.status_code == 200
    assert resp.json()["event"]["evidence"]["status"] == "complete"


def test_evidence_is_json_serializable():
    client = _client(rows=[_row()])
    # 직렬화 실패가 나면 500 이므로 200 이면 통과
    assert client.get("/api/events").status_code == 200
