"""업무 판정은 관리자 확인·필수 감사·버전 비교를 거친다."""
import asyncio
from typing import Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field, field_validator

from netwatcher.investigation.reviews import ReviewConflict
from netwatcher.web.change_audit import ChangeAudit, state_summary
from netwatcher.web.rbac import Role, require_role


class ReviewRequest(BaseModel):
    decision: Literal["expected_backup", "approved_maintenance", "investigate", "insufficient_evidence"]
    note: str = Field(min_length=3, max_length=512)
    expected_version: int = Field(ge=0, le=2**63 - 1)
    valid_hours: int = Field(default=24, ge=1, le=168)
    max_bytes: int | None = Field(default=None, ge=1, le=1024**4)

    @field_validator("note")
    @classmethod
    def meaningful_note(cls, value):
        if len(value.strip()) < 3 or "\x00" in value:
            raise ValueError("A review reason is required")
        return value.strip()


def create_business_reviews_router(reviews):
    router = APIRouter(prefix="/events", tags=["investigation"])
    changes = ChangeAudit()

    async def snapshot(event_id, **kwargs):
        if reviews is None:
            raise HTTPException(503, "Business review storage unavailable")
        return state_summary(await reviews.raw(event_id))

    @router.get("/{event_id}/business-review", dependencies=[Depends(require_role(Role.VIEWER))])
    async def get_review(event_id: int):
        if reviews is None:
            raise HTTPException(503, "Business review storage unavailable")
        try:
            async with asyncio.timeout(5):
                return await reviews.get(event_id)
        except ReviewConflict as error:
            raise HTTPException(404, str(error)) from None
        except (TimeoutError, asyncpg.PostgresError):
            raise HTTPException(503, "Business review storage unavailable") from None

    @router.get("/{event_id}/business-review/history", dependencies=[Depends(require_role(Role.VIEWER))])
    async def get_review_history(event_id: int, before_version: int | None = Query(default=None, ge=1, le=2**63-1)):
        if reviews is None:
            raise HTTPException(503, "Business review storage unavailable")
        try:
            async with asyncio.timeout(5):
                return await reviews.history(event_id, before_version)
        except ReviewConflict as error:
            raise HTTPException(404, str(error)) from None
        except (TimeoutError, asyncpg.PostgresError):
            raise HTTPException(503, "Business review storage unavailable") from None

    @router.put("/{event_id}/business-review")
    @changes.guard(snapshot)
    async def save_review(event_id: int, body: ReviewRequest, request: Request,
                          actor: dict = Depends(require_role(Role.ADMIN))):
        if reviews is None:
            raise HTTPException(503, "Business review storage unavailable")
        try:
            async with asyncio.timeout(5):
                return await reviews.save(event_id, body, str(actor.get("sub", "unknown")))
        except ReviewConflict as error:
            raise HTTPException(409, str(error)) from None
        except (TimeoutError, asyncpg.PostgresError):
            raise HTTPException(503, "Business review storage unavailable") from None

    return router
