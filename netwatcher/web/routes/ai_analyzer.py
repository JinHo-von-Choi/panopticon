"""AI Analyzer 서비스 상태 조회 REST API.

작성자: 최진호
작성일: 2026-02-27
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter
from fastapi.responses import JSONResponse

if TYPE_CHECKING:
    from netwatcher.services.ai_analyzer import AIAnalyzerService

logger = logging.getLogger(__name__)


def create_ai_analyzer_router(ai_analyzer: "AIAnalyzerService") -> APIRouter:
    """AI Analyzer 상태 API 라우터 팩토리."""
    router = APIRouter(tags=["ai_analyzer"])

    @router.get("/ai-analyzer/status")
    async def get_status():
        """AI Analyzer 서비스 상태를 반환한다."""
        return JSONResponse({
            "enabled":          True,
            "provider":         ai_analyzer._provider,
            "interval_minutes": ai_analyzer._interval_seconds // 60,
            "lookback_minutes": ai_analyzer._lookback_minutes,
            "fp_threshold":     ai_analyzer._fp_threshold,
            "max_pct":          ai_analyzer._max_pct,
            "consecutive_fp":   dict(ai_analyzer._consecutive_fp),
        })

    return router
