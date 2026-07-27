"""인시던트 API 라우트 테스트.

조회가 인메모리 캐시가 아니라 영속 저장소를 우선하는지 검증한다.

작성자: 최진호
작성일: 2026-07-27
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from netwatcher.web.routes.incidents import create_incidents_router


def _row(incident_id: int = 7, resolved: bool = False) -> dict:
    return {
        "id": incident_id,
        "severity": "CRITICAL",
        "title": "Lateral movement burst",
        "description": "",
        "alert_ids": [1, 2, 3],
        "source_ips": ["192.168.1.10"],
        "engines": ["port_scan", "lateral_movement"],
        "kill_chain_stages": ["discovery", "lateral_movement"],
        "rule": "burst_same_src",
        "created_at": datetime(2026, 7, 27, 10, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 7, 27, 10, 5, tzinfo=timezone.utc),
        "resolved": resolved,
    }


def _client(correlator) -> TestClient:
    app = FastAPI()
    app.include_router(create_incidents_router(correlator), prefix="/api")
    return TestClient(app)


@pytest.fixture
def correlator_with_store():
    correlator = MagicMock()
    repo = MagicMock()
    repo.list_recent = AsyncMock(return_value=[_row()])
    repo.get_by_id = AsyncMock(return_value=_row())
    repo.resolve = AsyncMock(return_value=True)
    correlator.incident_repo = repo
    correlator.get_incidents.return_value = []
    correlator.get_incident.return_value = None
    correlator.resolve_incident.return_value = False
    return correlator, repo


@pytest.fixture
def correlator_without_store():
    correlator = MagicMock()
    correlator.incident_repo = None
    return correlator


def test_list_reads_from_store(correlator_with_store):
    """저장소가 있으면 캐시가 비어 있어도 목록을 반환한다."""
    correlator, repo = correlator_with_store
    resp = _client(correlator).get("/api/incidents")

    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "store"
    assert data["total"] == 1
    assert data["incidents"][0]["id"] == 7
    assert data["incidents"][0]["source_ips"] == ["192.168.1.10"]
    assert data["incidents"][0]["created_at"].startswith("2026-07-27T10:00")
    repo.list_recent.assert_awaited_once_with(limit=50, include_resolved=False)
    correlator.get_incidents.assert_not_called()


def test_list_passes_query_parameters(correlator_with_store):
    correlator, repo = correlator_with_store
    resp = _client(correlator).get("/api/incidents?limit=10&include_resolved=true")

    assert resp.status_code == 200
    repo.list_recent.assert_awaited_once_with(limit=10, include_resolved=True)


def test_list_falls_back_to_cache_without_store(correlator_without_store):
    correlator_without_store.get_incidents.return_value = [{"id": 1}]
    resp = _client(correlator_without_store).get("/api/incidents")

    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "cache"
    assert data["total"] == 1


def test_list_falls_back_when_store_errors(correlator_with_store):
    correlator, repo = correlator_with_store
    repo.list_recent.side_effect = RuntimeError("connection lost")
    correlator.get_incidents.return_value = [{"id": 99}]

    resp = _client(correlator).get("/api/incidents")

    assert resp.status_code == 200
    assert resp.json()["source"] == "cache"
    assert resp.json()["incidents"][0]["id"] == 99


def test_detail_reads_from_store(correlator_with_store):
    correlator, repo = correlator_with_store
    resp = _client(correlator).get("/api/incidents/7")

    assert resp.status_code == 200
    assert resp.json()["incident"]["id"] == 7
    repo.get_by_id.assert_awaited_once_with(7)


def test_detail_404_when_absent_everywhere(correlator_with_store):
    correlator, repo = correlator_with_store
    repo.get_by_id.return_value = None

    resp = _client(correlator).get("/api/incidents/404")

    assert resp.status_code == 404
    assert "error" in resp.json()


def test_resolve_persists_even_when_not_cached(correlator_with_store):
    """재시작으로 캐시에 없는 인시던트도 저장소를 통해 해결 처리된다."""
    correlator, repo = correlator_with_store
    correlator.resolve_incident.return_value = False

    resp = _client(correlator).post("/api/incidents/7/resolve")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    repo.resolve.assert_awaited_once_with(7)


def test_resolve_404_when_unknown(correlator_with_store):
    correlator, repo = correlator_with_store
    correlator.resolve_incident.return_value = False
    repo.resolve.return_value = False

    resp = _client(correlator).post("/api/incidents/12345/resolve")

    assert resp.status_code == 404
