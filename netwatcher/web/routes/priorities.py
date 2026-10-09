"""보존 사건의 처리 우선순위 조회 권한을 제한한다."""
import asyncio
from typing import Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from netwatcher.web.rbac import Role, require_role
from netwatcher.investigation.reviews import ReviewConflict


def create_priorities_router(priorities):
    router = APIRouter(prefix='/investigation', tags=['investigation'])

    @router.get('/priorities',dependencies=[Depends(require_role(Role.VIEWER))])
    async def get_priorities(category: Literal['unclosed','unassigned','unreviewed','expired','recheck']='unclosed',
                             offset: int=Query(0,ge=0,le=10000000),limit: int=Query(50,ge=1,le=100)):
        if priorities is None:
            raise HTTPException(503,'Priority storage unavailable')
        try:
            async with asyncio.timeout(5):
                result=await priorities.get(category,offset=offset,limit=limit)
        except ReviewConflict as error:
            raise HTTPException(413,str(error)) from None
        except (TimeoutError,asyncpg.PostgresError):
            raise HTTPException(503,'Priority storage unavailable') from None
        return JSONResponse(result,headers={'Cache-Control':'no-store'})
    return router
