"""미확정 변경을 추적할 관리자 전용 감사 조회."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from netwatcher.web.rbac import Role, require_role


def create_audit_router():
    router = APIRouter(prefix="/audit", tags=["audit"])

    @router.get("/changes/{request_id}", dependencies=[Depends(require_role(Role.ADMIN))])
    async def change_history(request: Request, request_id: Annotated[str, Path(
            pattern=r"^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$")]):
        audit = getattr(request.app.state, "audit_logger", None)
        if audit is None:
            raise HTTPException(503, "Audit storage is unavailable")
        try:
            async with asyncio.timeout(2):
                entries = await audit.change_history(request_id)
        except Exception:
            raise HTTPException(503, "Audit history could not be read") from None
        if not entries:
            raise HTTPException(404, "Change audit not found")
        result = next((entry for entry in reversed(entries)
                       if entry["action"] in {"sensor_change_applied", "sensor_change_archived"}), None)
        if result is None:
            result = next((entry for entry in reversed(entries)
                           if entry["action"] == "api_mutation"), None)
        outcome = ("applied" if result and result["action"] == "sensor_change_applied" else
                   result["details"].get("outcome", "unknown") if result else "unknown")
        if outcome not in ("applied", "completed", "failed"):
            outcome = "unknown"
        return {"request_id": request_id, "outcome": outcome, "entries": entries,
                "requires_reconciliation": outcome == "unknown"}

    return router
