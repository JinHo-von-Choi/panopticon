"""사건 담당자·인계 변경에 권한·필수 감사·버전 검사를 적용한다."""
import asyncio
from typing import Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from netwatcher.investigation.reviews import ReviewConflict
from netwatcher.web.change_audit import ChangeAudit, state_summary
from netwatcher.web.rbac import Role, require_role


class CaseRequest(BaseModel):
    owner: str = Field(default='', max_length=128)
    owner_id: UUID | None = None
    status: Literal['open', 'investigating', 'closed']
    note: str = Field(min_length=3, max_length=1024)
    expected_version: int = Field(ge=0, le=2**63 - 1)

    @field_validator('owner', 'note')
    @classmethod
    def clean_text(cls, value, info):
        value = value.strip()
        if any(ord(char) < 32 and char not in '\n\t' for char in value):
            raise ValueError('Control characters are not allowed')
        if info.field_name == 'owner' and any(char in value for char in '\n\t'):
            raise ValueError('Owner must be a single line')
        if info.field_name == 'note' and len(value) < 3:
            raise ValueError('A handover note is required')
        return value


def create_case_workflows_router(workflows):
    router = APIRouter(prefix='/events', tags=['investigation'])
    changes = ChangeAudit()

    async def snapshot(event_id, request=None, **kwargs):
        if workflows is None:
            raise HTTPException(503, 'Case storage unavailable')
        try:
            result = getattr(request.state, 'case_change_result', None) if request else None
            return state_summary(result if result is not None else await workflows.raw(event_id))
        except asyncpg.PostgresError:
            raise HTTPException(503, "Case storage unavailable") from None

    @router.get('/{event_id}/case', dependencies=[Depends(require_role(Role.VIEWER))])
    async def get_case(event_id: int, before_version: int | None = Query(default=None, ge=1, le=2**63-1)):
        if workflows is None:
            raise HTTPException(503, 'Case storage unavailable')
        try:
            async with asyncio.timeout(5):
                return await workflows.get(event_id, before_version)
        except ReviewConflict as error:
            raise HTTPException(404, str(error)) from None
        except (TimeoutError, asyncpg.PostgresError):
            raise HTTPException(503, 'Case storage unavailable') from None

    @router.put('/{event_id}/case')
    @changes.guard(snapshot)
    async def save_case(event_id: int, body: CaseRequest, request: Request,
                        actor: dict = Depends(require_role(Role.ADMIN))):
        if workflows is None:
            raise HTTPException(503, 'Case storage unavailable')
        try:
            async with asyncio.timeout(5):
                result = await workflows.save(event_id, body, str(actor.get('sub', 'unknown')),
                                              actor.get('uid'), actor.get('ver'))
                request.state.case_change_result = result['case'] | {'note': body.note}
                return result
        except ReviewConflict as error:
            raise HTTPException(409, str(error)) from None
        except (TimeoutError, asyncpg.PostgresError):
            raise HTTPException(503, 'Case storage unavailable') from None
    return router
