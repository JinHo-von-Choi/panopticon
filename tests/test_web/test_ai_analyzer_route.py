"""GET /api/ai-analyzer/status 엔드포인트 단위 테스트."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import MagicMock


def _make_app(ai_analyzer) -> FastAPI:
    from netwatcher.web.routes.ai_analyzer import create_ai_analyzer_router
    app = FastAPI()
    app.include_router(create_ai_analyzer_router(ai_analyzer), prefix="/api")
    return app


class TestAiAnalyzerRoute:
    def test_status_returns_enabled_true(self):
        svc = MagicMock()
        svc._provider = "copilot"
        svc._interval_seconds = 900
        svc._lookback_minutes = 30
        svc._fp_threshold = 2
        svc._max_pct = 20
        svc._consecutive_fp = {"port_scan": 1}

        client = TestClient(_make_app(svc))
        resp = client.get("/api/ai-analyzer/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert data["provider"] == "copilot"
        assert data["interval_minutes"] == 15
        assert data["lookback_minutes"] == 30
        assert "consecutive_fp" in data

    def test_status_interval_minutes_computed_correctly(self):
        """interval_seconds=1800 이면 interval_minutes=30 이어야 한다."""
        svc = MagicMock()
        svc._provider = "claude"
        svc._interval_seconds = 1800
        svc._lookback_minutes = 60
        svc._fp_threshold = 3
        svc._max_pct = 30
        svc._consecutive_fp = {}

        client = TestClient(_make_app(svc))
        resp = client.get("/api/ai-analyzer/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interval_minutes"] == 30
        assert data["lookback_minutes"] == 60
