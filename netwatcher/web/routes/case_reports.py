"""기간 보고서의 조회 권한·시간 범위·출력 크기를 제한한다."""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, JSONResponse

from netwatcher.investigation.reports import report_csv
from netwatcher.investigation.reviews import ReviewConflict
from netwatcher.web.rbac import Role, require_role


def create_case_reports_router(reports):
    router = APIRouter(prefix='/reports',tags=['investigation'])

    @router.get('/weekly',dependencies=[Depends(require_role(Role.VIEWER))])
    async def weekly_report(start: datetime | None = Query(None), end: datetime | None = Query(None),
                            format: Literal['json','csv'] = 'json'):
        if reports is None:
            raise HTTPException(503,'Report storage unavailable')
        end = end or datetime.now(timezone.utc)
        start = start or end-timedelta(days=7)
        if any(value.tzinfo is None or value.utcoffset() is None for value in (start,end)):
            raise HTTPException(422,'Report times require a timezone')
        start,end = start.astimezone(timezone.utc),end.astimezone(timezone.utc)
        if not timedelta(0) < end-start <= timedelta(days=31):
            raise HTTPException(422,'Report period must be greater than zero and at most 31 days')
        try:
            async with asyncio.timeout(5):
                report = await reports.report(start,end)
        except ReviewConflict as error:
            raise HTTPException(413,str(error)) from None
        except (TimeoutError,asyncpg.PostgresError):
            raise HTTPException(503,'Report storage unavailable') from None
        if format == 'csv':
            filename = f'panopticon-report-{start:%Y%m%dT%H%M%SZ}-{end:%Y%m%dT%H%M%SZ}.csv'
            return Response(report_csv(report),media_type='text/csv; charset=utf-8',headers={
                'Content-Disposition':f'attachment; filename="{filename}"','Cache-Control':'no-store'})
        return JSONResponse(report,headers={'Cache-Control':'no-store'})
    return router
