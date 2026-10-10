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


def test_summary_reports_visible_hosts_from_visibility_state(monkeypatch):
    from netwatcher.services import visibility
    monkeypatch.setattr(visibility, "state", visibility._VisibilityState())
    visibility.state.update(7, 1000)
    app = FastAPI()
    app.include_router(create_stats_router(
        SimpleNamespace(summary=AsyncMock(return_value={})),
        SimpleNamespace(count=AsyncMock(return_value=0)),
        correlator=SimpleNamespace(get_incidents=lambda **kwargs: [])))
    with TestClient(app) as client:
        assert client.get("/stats/summary").json()["hosts_visible"] == 7


def test_traffic_reports_window_seconds_from_row_spacing():
    from datetime import datetime, timedelta, timezone
    start = datetime(2026, 10, 10, tzinfo=timezone.utc)
    rows = [{"timestamp": start + timedelta(minutes=5 * i), "total_packets": 300} for i in range(3)]
    app = FastAPI()
    app.include_router(create_stats_router(
        SimpleNamespace(recent=AsyncMock(return_value=rows)), SimpleNamespace()))
    with TestClient(app) as client:
        assert client.get("/stats/traffic?minutes=60").json()["window_seconds"] == 300
