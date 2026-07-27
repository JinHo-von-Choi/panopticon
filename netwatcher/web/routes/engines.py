"""탐지 엔진 관리 REST API (Standardized)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.utils.yaml_editor import YamlConfigEditor

class ToggleEngineRequest(BaseModel):
    enabled: bool

class UpdateConfigRequest(BaseModel):
    config: dict[str, Any]

def create_engines_router(registry: "EngineRegistry", yaml_editor: "YamlConfigEditor", flow_processor=None) -> APIRouter:
    router = APIRouter(prefix="/engines", tags=["engines"])

    @router.get("")
    async def list_engines():
        engines = registry.get_all_engine_info()
        return {"engines": engines}

    @router.patch("/{name}/toggle")
    async def toggle_engine(name: str, body: ToggleEngineRequest):
        try:
            yaml_editor.update_engine_config(name, {"enabled": body.enabled})
            if body.enabled:
                config = yaml_editor.get_engine_config(name) or {"enabled": True}
                ok, err, _ = registry.enable_engine(name, config)
            else:
                ok, err, _ = registry.disable_engine(name)
            if not ok:
                raise HTTPException(status_code=404, detail=err or "Engine not found")
            return {"status": "ok", "name": name, "enabled": body.enabled}
        except HTTPException:
            raise
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @router.get("/{name}")
    async def get_engine(name: str):
        info = registry.get_engine_info(name)
        if not info:
            return JSONResponse({"error": f"Engine '{name}' not found"}, status_code=404)
        return {"engine": info}

    @router.put("/{name}/config")
    async def update_config(name: str, body: dict[str, Any]):
        """설정을 검증 후 반영하고, 성공한 경우에만 YAML에 기록한다."""
        info = registry.get_engine_info(name)
        if not info:
            return JSONResponse({"error": f"Engine '{name}' not found"}, status_code=404)

        # 빈 입력 필드에서 온 null은 기존 값을 덮어쓰지 않도록 제거한다.
        updates = {k: v for k, v in body.items() if v is not None}
        updates = _filter_known_keys(name, updates)

        try:
            existing = yaml_editor.get_engine_config(name) or {}
            merged   = {**existing, **updates}
            ok, err, warnings = registry.reload_engine(name, merged)
            if not ok:
                return JSONResponse(
                    {"error": err or f"Failed to apply config for '{name}'"},
                    status_code=500,
                )
            yaml_editor.update_engine_config(name, updates)
        except KeyError as e:
            return JSONResponse({"error": str(e)}, status_code=404)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

        response: dict[str, Any] = {
            "status": "ok",
            "name":   name,
            "engine": registry.get_engine_info(name) or info,
        }
        if warnings:
            response["warnings"] = list(warnings)
        return response

    def _filter_known_keys(name: str, updates: dict[str, Any]) -> dict[str, Any]:
        """엔진 스키마에 선언된 키만 남긴다.

        스키마를 확인할 수 없거나 비어 있는 엔진은 필터링하지 않는다.
        """
        allowed = registry.get_config_keys(name) if hasattr(registry, "get_config_keys") else None
        if not isinstance(allowed, (set, frozenset, list, tuple)) or not allowed:
            return updates
        allowed = set(allowed) | {"enabled"}
        return {k: v for k, v in updates.items() if k in allowed}

    return router
