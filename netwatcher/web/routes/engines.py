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

    @router.put("/{name}/config")
    async def update_config(name: str, body: dict[str, Any]):
        try:
            yaml_editor.update_engine_config(name, body)
            config = yaml_editor.get_engine_config(name) or {}
            ok, err, _ = registry.reload_engine(name, config)
            if not ok:
                raise HTTPException(status_code=404, detail=err or "Engine not found")
            return {"status": "ok", "name": name}
        except HTTPException:
            raise
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return router
