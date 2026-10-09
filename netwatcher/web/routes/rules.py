"""시그니처 규칙 관리 REST API."""

from __future__ import annotations

from typing import TYPE_CHECKING
import hashlib
import json
import re
import yaml

from fastapi import Depends, APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.change_audit import ChangeAudit
from pydantic import BaseModel, StrictBool

if TYPE_CHECKING:
    from netwatcher.detection.engines.signature import SignatureEngine


class RuleEnabled(BaseModel):
    enabled: StrictBool


def create_rules_router(signature_engine: SignatureEngine) -> APIRouter:
    """Rules API 라우터 팩토리."""
    router = APIRouter(tags=["rules"])
    changes = ChangeAudit()

    def snapshot(**args):
        if "rule_id" in args:
            rule = signature_engine.rules_by_id.get(args["rule_id"])
            return {"rule_id": args["rule_id"], "enabled": rule.enabled if rule else None}
        digest = hashlib.sha256()
        for rule in signature_engine.rules:
            digest.update(json.dumps(vars(rule), default=str, sort_keys=True).encode())
        return {"rule_count": len(signature_engine.rules), "rule_set_sha256": digest.hexdigest()}

    @router.get("/rules")
    async def list_rules():
        """로드된 모든 규칙 목록 반환."""
        rules = []
        for rule in signature_engine.rules:
            rules.append({
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.value,
                "protocol": rule.protocol,
                "src_ip": rule.src_ip,
                "dst_ip": rule.dst_ip,
                "src_port": rule.src_port,
                "dst_port": rule.dst_port,
                "flags": rule.flags,
                "content_nocase": rule.content_nocase,
                "has_content": len(rule.content) > 0,
                "has_regex": rule.regex is not None,
                "threshold": rule.threshold,
                "enabled": rule.enabled,
            })
        return {"rules": rules, "total": len(rules)}

    @router.get("/rules/{rule_id}")
    async def get_rule(rule_id: str):
        """특정 규칙 상세 정보 반환."""
        rules_map = signature_engine.rules_by_id
        rule = rules_map.get(rule_id)
        if not rule:
            return JSONResponse(
                {"error": f"Rule not found: {rule_id}"}, status_code=404,
            )
        return {
            "rule": {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.value,
                "protocol": rule.protocol,
                "src_ip": rule.src_ip,
                "dst_ip": rule.dst_ip,
                "src_port": rule.src_port,
                "dst_port": rule.dst_port,
                "flags": rule.flags,
                "content_nocase": rule.content_nocase,
                "has_content": len(rule.content) > 0,
                "content_count": len(rule.content),
                "has_regex": rule.regex is not None,
                "threshold": rule.threshold,
                "enabled": rule.enabled,
            }
        }

    @router.put("/rules/{rule_id}/toggle", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def toggle_rule(rule_id: str, request: Request, body: RuleEnabled | None = None):
        """규칙 활성화/비활성화 토글."""
        rules_map = signature_engine.rules_by_id
        rule = rules_map.get(rule_id)
        if not rule:
            return JSONResponse(
                {"error": f"Rule not found: {rule_id}"}, status_code=404,
            )
        rule.enabled = body.enabled if body is not None else not rule.enabled
        return {
            "status": "ok",
            "rule_id": rule.id,
            "enabled": rule.enabled,
        }

    @router.post("/rules/reload", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def reload_rules(request: Request):
        """규칙 디렉토리를 재스캔하여 규칙 다시 로드."""
        try:
            signature_engine.reload_rules()
        except (ValueError, TypeError, KeyError, OSError, AttributeError, yaml.YAMLError, re.error):
            raise HTTPException(400, "규칙 파일을 확인하세요. 기존 규칙은 유지합니다.") from None
        return {
            "status": "ok",
            "rules_loaded": len(signature_engine.rules),
        }

    return router
