"""엔진 설정 관리 REST API.

탐지 엔진의 설정 조회, 수정, 활성화/비활성화 토글을 제공한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger(__name__)


class ToggleRequest(BaseModel):
    """엔진 활성화/비활성화 토글 요청."""
    enabled: bool


def create_engines_router(
    registry: EngineRegistry,
    yaml_editor: YamlConfigEditor,
) -> APIRouter:
    """엔진 설정 API 라우터 팩토리.

    Args:
        registry: 엔진 레지스트리 (조회/리로드/활성화/비활성화).
        yaml_editor: YAML 설정 편집기 (영속화).

    Returns:
        설정된 APIRouter 인스턴스.
    """
    router = APIRouter(tags=["engines"])

    @router.get("/engines")
    async def list_engines():
        """모든 탐지 엔진 목록 반환."""
        engines = registry.get_all_engine_info()
        return {"engines": engines}

    @router.get("/engines/{name}")
    async def get_engine(name: str):
        """단일 탐지 엔진 상세 정보 반환."""
        info = registry.get_engine_info(name)
        if info is None:
            return JSONResponse(
                {"error": f"Engine not found: {name}"}, status_code=404,
            )
        return {"engine": info}

    @router.put("/engines/{name}/config")
    async def update_engine_config(name: str, body: dict[str, Any]):
        """엔진 설정 업데이트 (핫리로드 후 YAML 영속화)."""
        info = registry.get_engine_info(name)
        if info is None:
            return JSONResponse(
                {"error": f"Engine not found: {name}"}, status_code=404,
            )

        # null 값 필터링 (프론트엔드에서 빈 입력 시 null 전송)
        body = {k: v for k, v in body.items() if v is not None}

        # 기존 설정과 병합 후 핫리로드 (YAML 변경 전에 먼저 검증)
        existing = yaml_editor.get_engine_config(name) or {}
        merged = {**existing, **body}
        try:
            ok, err, warnings = registry.reload_engine(name, merged)
            if not ok:
                return JSONResponse(
                    {"error": f"Reload failed: {err}"}, status_code=500,
                )
        except Exception as exc:
            logger.exception("Reload failed for engine %s", name)
            return JSONResponse(
                {"error": f"Reload failed: {exc}"}, status_code=500,
            )

        # 핫리로드 성공 후에만 YAML 영속화
        try:
            yaml_editor.update_engine_config(name, body)
        except Exception as exc:
            logger.exception("YAML update failed for engine %s", name)
            warnings.append(f"설정이 적용되었으나 YAML 저장 실패: {exc}")

        result: dict[str, Any] = {
            "status": "ok",
            "engine": registry.get_engine_info(name),
        }
        if warnings:
            result["warnings"] = warnings
        return result

    @router.patch("/engines/{name}/toggle")
    async def toggle_engine(name: str, body: ToggleRequest):
        """엔진 활성화/비활성화 토글."""
        info = registry.get_engine_info(name)
        if info is None:
            return JSONResponse(
                {"error": f"Engine not found: {name}"}, status_code=404,
            )

        # YAML 영속화
        try:
            yaml_editor.update_engine_config(name, {"enabled": body.enabled})
        except Exception as exc:
            logger.exception("YAML update failed for engine %s", name)
            return JSONResponse(
                {"error": f"Failed to persist config: {exc}"}, status_code=500,
            )

        # 엔진 활성화/비활성화
        if body.enabled:
            config = yaml_editor.get_engine_config(name) or {}
            ok, err, warnings = registry.enable_engine(name, config)
        else:
            ok, err, warnings = registry.disable_engine(name)

        if not ok:
            return JSONResponse(
                {"error": f"Toggle failed: {err}"}, status_code=500,
            )

        result: dict[str, Any] = {
            "status": "ok", "name": name, "enabled": body.enabled,
        }
        if warnings:
            result["warnings"] = warnings
        return result

    return router
