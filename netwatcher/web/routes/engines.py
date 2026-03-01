"""탐지 엔진 관리 REST API (Standardized)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from fastapi import APIRouter, HTTPException
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
            registry.toggle_engine(name, body.enabled)
            yaml_editor.update_engine_config(name, {"enabled": body.enabled})
            return {"status": "ok", "name": name, "enabled": body.enabled}
        except Exception as e: raise HTTPException(404, str(e))

    @router.put("/{name}/config")
    async def update_config(name: str, body: dict[str, Any]):
        try:
            registry.update_engine_config(name, body)
            yaml_editor.update_engine_config(name, body)
            return {"status": "ok", "name": name}
        except Exception as e: raise HTTPException(404, str(e))

    return router
