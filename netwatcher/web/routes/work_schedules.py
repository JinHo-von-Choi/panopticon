"""수동·CSV 작업 일정 등록과 사건 연결의 권한 및 입력 검증."""
import asyncio
import csv
import io
import re
from datetime import datetime,timedelta,timezone
from typing import Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter,Depends,HTTPException,Query,Request
from pydantic import BaseModel,Field,IPvAnyAddress,field_validator,model_validator,ValidationError

from netwatcher.investigation.reviews import ReviewConflict
from netwatcher.web.change_audit import ChangeAudit,state_summary
from netwatcher.web.rbac import Role,require_role


class WorkRequest(BaseModel):
    title: str = Field(min_length=3,max_length=128)
    kind: Literal['backup','vulnerability_scan','deployment','maintenance']
    owner: str = Field(min_length=1,max_length=128)
    ticket: str = Field(min_length=1,max_length=128)
    note: str = Field(min_length=3,max_length=1024)
    source_ip: IPvAnyAddress
    source_mac: str | None = None
    dest_ip: IPvAnyAddress
    protocol: Literal['TCP','UDP']
    dest_port: int | None = Field(default=None,ge=1,le=65535)
    starts_at: datetime
    ends_at: datetime
    max_flow_bytes: int = Field(ge=1,le=1024**4)

    @field_validator('title','owner','ticket','note')
    @classmethod
    def text(cls,value,info):
        value=value.strip()
        minimum=3 if info.field_name in ('title','note') else 1
        if len(value)<minimum or any(ord(char)<32 and char not in '\n\t' for char in value):
            raise ValueError('Meaningful text required')
        if info.field_name!='note' and any(char in value for char in '\n\t'):
            raise ValueError('Single line required')
        return value

    @field_validator('source_mac')
    @classmethod
    def mac(cls,value):
        if value is not None:
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value):
                raise ValueError('Invalid MAC address')
            value=value.lower()
        return value

    @field_validator('dest_port','max_flow_bytes',mode='before')
    @classmethod
    def numeric(cls,value):
        if type(value) is bool:
            raise ValueError('Integer required')
        return value

    @field_validator('starts_at','ends_at',mode='before')
    @classmethod
    def iso_time(cls,value):
        if isinstance(value,datetime):return value
        if not isinstance(value,str) or 'T' not in value:
            raise ValueError('ISO 8601 timestamp required')
        return value

    @field_validator('starts_at','ends_at')
    @classmethod
    def aware_time(cls,value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('Timezone required')
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def period(self):
        if not timedelta(0)<self.ends_at-self.starts_at<=timedelta(days=31):
            raise ValueError('Work duration must be positive and at most 31 days')
        return self


class CsvRequest(BaseModel):
    csv: str = Field(min_length=1,max_length=131072)

    @field_validator('csv')
    @classmethod
    def byte_limit(cls,value):
        if len(value.encode('utf-8'))>131072:
            raise ValueError('CSV byte limit exceeded')
        return value


def parse_csv(body):
    reader=csv.DictReader(io.StringIO(body.csv.lstrip('\ufeff')),strict=True)
    fields=set(WorkRequest.model_fields)
    try: headers=reader.fieldnames
    except csv.Error:raise HTTPException(422,'csv_syntax') from None
    if headers is None or len(headers)!=len(set(headers)) or set(headers)!=fields:
        raise HTTPException(422,'csv_columns')
    records=[]
    try:
        for number,row in enumerate(reader,2):
            if len(records)>=100:
                raise HTTPException(422,'csv_row_limit')
            if None in row or any(value is None for value in row.values()):
                raise HTTPException(422,{'code':'csv_row_invalid','row':number})
            for key in ('source_mac','dest_port'):
                if not row[key].strip():row[key]=None
            try:records.append(WorkRequest.model_validate(row))
            except ValidationError:
                raise HTTPException(422,{'code':'csv_row_invalid','row':number}) from None
    except csv.Error:
        raise HTTPException(422,'csv_syntax') from None
    if not records:raise HTTPException(422,'csv_empty')
    return records


class RevokeRequest(BaseModel):
    expected_version:int=Field(ge=1,le=2**63-1)
    note:str=Field(min_length=3,max_length=512)

    @field_validator('note')
    @classmethod
    def text(cls,value):
        value=value.strip()
        if len(value)<3 or any(ord(char)<32 and char not in '\n\t' for char in value):
            raise ValueError('A revocation reason is required')
        return value


class WorkLinkRequest(BaseModel):
    schedule_id:UUID
    expected_version:int=Field(ge=0,le=2**63-1)


def create_work_schedules_router(schedules):
    router=APIRouter(tags=['investigation'])
    changes=ChangeAudit()

    async def snapshot(body=None,schedule_id=None,event_id=None,**kwargs):
        if schedules is None:raise HTTPException(503,'Work schedule storage unavailable')
        try:
            if event_id is not None:return state_summary(await schedules.for_event(event_id))
            if schedule_id is not None:return state_summary(await schedules.raw(schedule_id))
            records=parse_csv(body) if isinstance(body,CsvRequest) else [body]
            return state_summary(await schedules.batch_state(records))
        except asyncpg.PostgresError:
            raise HTTPException(503,'Work schedule storage unavailable') from None
        except ReviewConflict:
            raise HTTPException(404,'event_missing') from None

    async def execute(function,*args):
        if schedules is None:raise HTTPException(503,'Work schedule storage unavailable')
        try:
            async with asyncio.timeout(5):return await function(*args)
        except ReviewConflict as error:
            raise HTTPException(404 if str(error)=='event_missing' else 409,str(error)) from None
        except (TimeoutError,asyncpg.PostgresError):
            raise HTTPException(503,'Work schedule storage unavailable') from None

    @router.get('/work-schedules',dependencies=[Depends(require_role(Role.VIEWER))])
    async def list_schedules(limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0)):
        return await execute(schedules.list if schedules else None,limit,offset)

    @router.post('/work-schedules')
    @changes.guard(snapshot)
    async def create(body:WorkRequest,request:Request,actor:dict=Depends(require_role(Role.ADMIN))):
        return await execute(schedules.create if schedules else None,[body],str(actor.get('sub','unknown')))

    @router.post('/work-schedules/import')
    @changes.guard(snapshot)
    async def import_csv(body:CsvRequest,request:Request,actor:dict=Depends(require_role(Role.ADMIN))):
        records=parse_csv(body)
        return await execute(schedules.create if schedules else None,records,str(actor.get('sub','unknown')))

    @router.post('/work-schedules/{schedule_id}/revoke')
    @changes.guard(snapshot)
    async def revoke(schedule_id:UUID,body:RevokeRequest,request:Request,actor:dict=Depends(require_role(Role.ADMIN))):
        return await execute(schedules.revoke if schedules else None,schedule_id,body,str(actor.get('sub','unknown')))

    @router.get('/events/{event_id}/work-schedule',dependencies=[Depends(require_role(Role.VIEWER))])
    async def for_event(event_id:int,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0)):
        return await execute(schedules.for_event if schedules else None,event_id,limit,offset)

    @router.put('/events/{event_id}/work-schedule')
    @changes.guard(snapshot)
    async def link(event_id:int,body:WorkLinkRequest,request:Request,actor:dict=Depends(require_role(Role.ADMIN))):
        return await execute(schedules.link if schedules else None,event_id,body.schedule_id,body.expected_version,str(actor.get('sub','unknown')))
    return router
