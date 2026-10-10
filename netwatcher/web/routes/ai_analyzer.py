"""AI Analyzer 서비스 상태 조회 REST API.

작성자: 최진호
작성일: 2026-02-27
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException

from netwatcher.services.sensor_ai import status
from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.rbac import Role, require_role

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def create_ai_analyzer_router(ai_analyzer=None, *, sensor_control=None) -> APIRouter:
    """실제 AI 서비스의 상태를 조회한다."""
    router = APIRouter(tags=["ai_analyzer"])

    @router.get("/ai-analyzer/status")
    async def get_status(actor=Depends(require_role(Role.VIEWER))):
        try:
            # 분리 콘솔이 직접 분석을 돌리면 콘솔의 상태가 실제 상태다.
            if sensor_control is not None and ai_analyzer is None:
                async with asyncio.timeout(8):
                    return (await sensor_control.ai_status(actor))["ai"]
            return status(ai_analyzer)
        except SensorControlError as exc:
            raise HTTPException(exc.status, {"code": exc.code,
                "message": "AI 분석 상태를 확인할 수 없습니다."}) from None
        except (TimeoutError, ValueError, TypeError, AttributeError, OverflowError):
            raise HTTPException(503, {"code": "ai_state_unavailable",
                "message": "AI 분석 상태를 확인할 수 없습니다."}) from None

    return router
