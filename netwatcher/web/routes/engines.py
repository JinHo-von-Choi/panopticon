"""탐지 엔진 관리 REST API (Standardized)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from netwatcher.utils.yaml_editor import ConfigurationReadOnlyError
from pydantic import BaseModel

from netwatcher.detection.validation import validate_engine_config
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.change_audit import ChangeAudit, state_summary

if TYPE_CHECKING:
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger("netwatcher.web.engines")

class ToggleEngineRequest(BaseModel):
    enabled: bool

class UpdateConfigRequest(BaseModel):
    config: dict[str, Any]

def create_engines_router(registry: "EngineRegistry", yaml_editor: "YamlConfigEditor", flow_processor=None) -> APIRouter:
    router = APIRouter(prefix="/engines", tags=["engines"])
    changes = ChangeAudit()

    def snapshot(**args):
        return {"engine": args["name"],
                "configuration": state_summary(yaml_editor.get_engine_config(args["name"]))}

    @router.get("")
    async def list_engines():
        engines = registry.get_all_engine_info()
        return {"engines": engines}

    @router.patch("/{name}/toggle")
    @changes.guard(snapshot)
    async def toggle_engine(
        name: str,
        body: ToggleEngineRequest,
        request: Request,
        _auth: dict = Depends(require_role(Role.ADMIN)),
    ):
        try:
            yaml_editor.ensure_writable()
            previous = yaml_editor.get_engine_config(name) or {}
            yaml_editor.update_engine_config(name, {"enabled": body.enabled})
            if body.enabled:
                config = yaml_editor.get_engine_config(name) or {"enabled": True}
                ok, err, _ = registry.enable_engine(name, config)
            else:
                ok, err, _ = registry.disable_engine(name)
            if not ok:
                yaml_editor.update_engine_config(name, previous)
                raise HTTPException(status_code=404, detail=err or "Engine not found")
            return {"status": "ok", "name": name, "enabled": body.enabled}
        except ConfigurationReadOnlyError:
            raise HTTPException(status_code=503, detail="Configuration is read-only")
        except OSError:
            raise HTTPException(status_code=503, detail="Configuration could not be persisted")
        except HTTPException:
            raise
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception:
            logger.exception("Engine toggle failed (%s)", name)
            raise HTTPException(status_code=500, detail="Engine change failed")

    @router.get("/{name}")
    async def get_engine(name: str):
        info = registry.get_engine_info(name)
        if not info:
            return JSONResponse({"error": f"Engine '{name}' not found"}, status_code=404)
        return {"engine": info}

    @router.put("/{name}/config")
    @changes.guard(snapshot)
    async def update_config(
        name: str,
        body: dict[str, Any],
        request: Request,
        _auth: dict = Depends(require_role(Role.ADMIN)),
    ):
        """설정을 검증 후 반영하고, 성공한 경우에만 YAML에 기록한다.

        검증은 거부 기반이다(PR 03). 경고만 남기고 적용하던 이전 동작과 달리,
        스키마에 없는 키·타입 불일치·NaN·범위 초과·누적 제한 초과는 400으로
        거부하며 런타임과 YAML 어느 쪽에도 반영하지 않는다.
        """
        info = registry.get_engine_info(name)
        if not info:
            return JSONResponse({"error": f"Engine '{name}' not found"}, status_code=404)

        # 빈 입력 필드에서 온 null은 기존 값을 덮어쓰지 않도록 제거한다.
        updates = {k: v for k, v in body.items() if v is not None}

        schema = _engine_schema(name)
        if schema is not None:
            # 부분 업데이트이므로 allow_partial=True. 선언되지 않은 키는 여전히 거부된다.
            violations = validate_engine_config(schema, updates, allow_partial=True)
            if violations:
                return JSONResponse(
                    {
                        "error": f"설정 검증 실패 ({len(violations)}건)",
                        "violations": [v.as_dict() for v in violations],
                    },
                    status_code=400,
                )

        try:
            yaml_editor.ensure_writable()
            existing = yaml_editor.get_engine_config(name) or {}
            merged   = {**existing, **updates}

            # merged 전체를 대상으로 한 번 더 검증한다. 기존 YAML 값이 이미
            # 스키마를 어기고 있을 때 새 요청이 그걸 고쳐 쓰지 않도록 한다.
            if schema is not None:
                merged_violations = validate_engine_config(schema, merged)
                if merged_violations:
                    return JSONResponse(
                        {
                            "error": "병합 결과가 스키마를 만족하지 않는다",
                            "violations": [v.as_dict() for v in merged_violations],
                        },
                        status_code=400,
                    )

            ok, err, warnings = registry.reload_engine(name, merged)
            if not ok:
                return JSONResponse(
                    {"error": err or f"Failed to apply config for '{name}'"},
                    status_code=500,
                )
            try:
                yaml_editor.update_engine_config(name, updates)
            except Exception:
                restored, _, _ = registry.reload_engine(name, existing)
                if not restored:
                    return JSONResponse({"error": "Configuration rollback failed"}, status_code=503)
                raise
        except ConfigurationReadOnlyError:
            return JSONResponse({"error": "Configuration is read-only"}, status_code=503)
        except OSError:
            return JSONResponse({"error": "Configuration could not be persisted"}, status_code=503)
        except KeyError as e:
            return JSONResponse({"error": str(e)}, status_code=404)
        except Exception:
            logger.exception("Engine configuration update failed (%s)", name)
            return JSONResponse({"error": "Engine configuration update failed"}, status_code=500)

        response: dict[str, Any] = {
            "status": "ok",
            "name":   name,
            "engine": registry.get_engine_info(name) or info,
        }
        if warnings:
            response["warnings"] = list(warnings)
        return response

    def _engine_schema(name: str) -> dict[str, Any] | None:
        """엔진의 config_schema 를 반환한다.

        스키마를 dict로 받지 못하면 None 을 돌려준다. 스키마가 없는 엔진은
        검증 계층이 동작할 대상이 아니므로, 알 수 없는 키를 거부해야 하는 경우도
        만들어지지 않는다.
        """
        getter = getattr(registry, "get_engine_schema", None)
        if not callable(getter):
            return None
        try:
            schema = getter(name)
        except Exception:
            logger.warning("config_schema 조회 실패 (%s)", name, exc_info=True)
            return None
        if not isinstance(schema, dict) or not schema:
            return None
        return schema

    return router
