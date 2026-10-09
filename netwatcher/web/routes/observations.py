"""보존 EVE 기록의 첫 관측을 조회한다."""
import asyncio
from typing import Literal

import asyncpg
from fastapi import APIRouter,Depends,HTTPException,Query
from fastapi.responses import JSONResponse
from netwatcher.web.rbac import Role,require_role
from netwatcher.investigation.reviews import ReviewConflict


def create_observations_router(observations):
    router=APIRouter(prefix='/investigation',tags=['investigation'])

    @router.get('/observations',dependencies=[Depends(require_role(Role.VIEWER))])
    async def get_observations(kind:Literal['addresses','peers']='addresses',hours:int=Query(24,ge=1,le=168),
                               offset:int=Query(0,ge=0,le=10000000),limit:int=Query(50,ge=1,le=100)):
        if observations is None:raise HTTPException(503,'Observation storage unavailable')
        try:
            async with asyncio.timeout(5):
                result=await observations.get(kind,hours=hours,offset=offset,limit=limit)
        except ReviewConflict as error:raise HTTPException(413,str(error)) from None
        except (TimeoutError,asyncpg.PostgresError):raise HTTPException(503,'Observation storage unavailable') from None
        return JSONResponse(result,headers={'Cache-Control':'no-store'})
    return router
