"""통계 조회 실패를 고위험 사건 0건으로 표시하지 않는다."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.web.routes.stats import create_stats_router


def test_failed_incident_cache_returns_unavailable_instead_of_zero():
    def fail(**kwargs):
        raise OSError("injected incident cache failure")
    app = FastAPI()
    app.include_router(create_stats_router(
        SimpleNamespace(summary=AsyncMock(return_value={})),
        SimpleNamespace(count=AsyncMock(return_value=0)),
        correlator=SimpleNamespace(get_incidents=fail)))
    with TestClient(app) as client:
        response = client.get("/stats/summary")
    assert response.status_code == 503
    assert "high_risk_count" not in response.json()


def test_known_empty_incident_cache_still_reports_zero():
    app = FastAPI()
    app.include_router(create_stats_router(
        SimpleNamespace(summary=AsyncMock(return_value={})),
        SimpleNamespace(count=AsyncMock(return_value=0)),
        correlator=SimpleNamespace(get_incidents=lambda **kwargs: [])))
    with TestClient(app) as client:
        response = client.get("/stats/summary")
    assert response.status_code == 200
    assert response.json()["high_risk_count"] == 0
