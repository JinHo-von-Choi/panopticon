"""반복 경보의 조회 권한과 실행 시간을 제한한다."""
import asyncio
from datetime import datetime, timedelta, timezone
from netwatcher.investigation.reviews import ReviewConflict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from netwatcher.web.rbac import Role, require_role


def create_event_groups_router(groups):
    router = APIRouter(prefix='/events', tags=['investigation'])


    @router.get('/groups', dependencies=[Depends(require_role(Role.VIEWER))])
    async def group_list(start: datetime | None = Query(None), end: datetime | None = Query(None),
                         offset: int = Query(0, ge=0, le=10000000), limit: int = Query(50, ge=1, le=100)):
        if groups is None:
            raise HTTPException(503, 'Group storage unavailable')
        end = end or datetime.now(timezone.utc)
        start = start or end-timedelta(hours=24)
        if any(value.tzinfo is None or value.utcoffset() is None for value in (start,end)):
            raise HTTPException(422, 'Group times require a timezone')
        start,end = start.astimezone(timezone.utc),end.astimezone(timezone.utc)
        if not timedelta(0) < end-start <= timedelta(days=7):
            raise HTTPException(422, 'Group period must be greater than zero and at most 7 days')
        try:
            async with asyncio.timeout(5):
                result = await groups.list(start,end,offset=offset,limit=limit)
        except ReviewConflict as error:
            raise HTTPException(413, str(error)) from None
        except (TimeoutError,asyncpg.PostgresError):
            raise HTTPException(503, 'Group storage unavailable') from None
        return JSONResponse(result,headers={'Cache-Control':'no-store'})

    @router.get('/{event_id}/group', dependencies=[Depends(require_role(Role.VIEWER))])
    async def event_group(event_id: int, offset: int = Query(0, ge=0, le=10000000),
                          limit: int = Query(50, ge=1, le=100)):
        if event_id < 1 or event_id > 2**63-1:
            raise HTTPException(422, 'Invalid event identifier')
        if groups is None:
            raise HTTPException(503, 'Group storage unavailable')
        try:
            async with asyncio.timeout(5):
                result = await groups.get(event_id, offset=offset, limit=limit)
        except (TimeoutError, asyncpg.PostgresError):
            raise HTTPException(503, 'Group storage unavailable') from None
        if result is None:
            raise HTTPException(404, 'Event not found')
        return JSONResponse(result, headers={'Cache-Control': 'no-store'})
    @router.get('/{event_id}/similar', dependencies=[Depends(require_role(Role.VIEWER))])
    async def previous_events(event_id: int, offset: int=Query(0,ge=0,le=10000000),
                               limit: int=Query(50,ge=1,le=100),days: int=Query(30,ge=1,le=90)):
        if event_id < 1 or event_id > 2**63-1:
            raise HTTPException(422,'Invalid event identifier')
        if groups is None:
            raise HTTPException(503,'Group storage unavailable')
        try:
            async with asyncio.timeout(5):
                result=await groups.get(event_id,offset=offset,limit=limit,previous=True,days=days)
        except (TimeoutError,asyncpg.PostgresError):
            raise HTTPException(503,'Group storage unavailable') from None
        if result is None:
            raise HTTPException(404,'Event not found')
        return JSONResponse(result,headers={'Cache-Control':'no-store'})
    return router
