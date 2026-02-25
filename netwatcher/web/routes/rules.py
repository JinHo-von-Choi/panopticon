"""시그니처 규칙 관리 REST API."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter
from fastapi.responses import JSONResponse

if TYPE_CHECKING:
    from netwatcher.detection.engines.signature import SignatureEngine


def create_rules_router(signature_engine: SignatureEngine) -> APIRouter:
    """Rules API 라우터 팩토리."""
    router = APIRouter(tags=["rules"])

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

    @router.put("/rules/{rule_id}/toggle")
    async def toggle_rule(rule_id: str):
        """규칙 활성화/비활성화 토글."""
        rules_map = signature_engine.rules_by_id
        rule = rules_map.get(rule_id)
        if not rule:
            return JSONResponse(
                {"error": f"Rule not found: {rule_id}"}, status_code=404,
            )
        rule.enabled = not rule.enabled
        return {
            "status": "ok",
            "rule_id": rule.id,
            "enabled": rule.enabled,
        }

    @router.post("/rules/reload")
    async def reload_rules():
        """규칙 디렉토리를 재스캔하여 규칙 다시 로드."""
        signature_engine.reload_rules()
        return {
            "status": "ok",
            "rules_loaded": len(signature_engine.rules),
        }

    return router
