"""관리 계정의 조회·생성·권한 변경·비밀번호 재설정 API."""

import asyncio
import hashlib
from typing import Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictInt, field_validator

from netwatcher.storage.user_accounts import AccountConflict, username
from netwatcher.storage.oidc_identities import OidcIdentities, issuer, subject
from netwatcher.web.change_audit import ChangeAudit
from netwatcher.web.rbac import Role, require_role


class AccountRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')


class CreateAccountRequest(AccountRequest):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr
    role: Literal['viewer', 'analyst', 'admin']

    @field_validator('username')
    @classmethod
    def normalized_username(cls, value):
        return username(value)


class UpdateAccountRequest(AccountRequest):
    expected_version: StrictInt = Field(ge=1, le=2**63-2)
    role: Literal['viewer', 'analyst', 'admin']
    enabled: StrictBool


class ResetPasswordRequest(AccountRequest):
    expected_version: StrictInt = Field(ge=1, le=2**63-2)
    password: SecretStr


class LinkIdentityRequest(AccountRequest):
    expected_version: StrictInt = Field(ge=1, le=2**63-2)
    issuer: str = Field(max_length=512)
    subject: str = Field(max_length=255)

    @field_validator('issuer')
    @classmethod
    def valid_issuer(cls, value):
        return issuer(value)

    @field_validator('subject')
    @classmethod
    def valid_subject(cls, value):
        return subject(value)


class UnlinkIdentityRequest(AccountRequest):
    expected_version: StrictInt = Field(ge=1, le=2**63-2)


def create_users_router(users):
    router = APIRouter(prefix='/users', tags=['users'])
    changes = ChangeAudit()
    identities = OidcIdentities(users.db) if users is not None else None

    async def execute(function, *args, **kwargs):
        if users is None:
            raise HTTPException(404, 'Managed accounts are disabled')
        try:
            async with asyncio.timeout(5):
                return await function(*args, **kwargs)
        except AccountConflict as error:
            raise HTTPException(404 if str(error) == 'account_missing' else 409, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        except (TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError):
            raise HTTPException(503, 'Account storage unavailable') from None

    async def snapshot(body=None, user_id=None, request=None, **kwargs):
        if users is None:
            raise HTTPException(404, 'Managed accounts are disabled')
        try:
            async with asyncio.timeout(1):
                # 변경 후 상태는 저장 함수가 반환한 버전이다. 뒤따른 다른 변경을 섞지 않는다.
                row = getattr(request.state, 'account_change_result', None) if request else None
                if row is None:
                    row = await users.get(user_id) if user_id is not None else await users.get_by_username(body.username)
        except (TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError):
            raise HTTPException(503, 'Account storage unavailable') from None
        if row is None:
            return None
        # 사용자 이름은 해시로 남기고 역할·활성 상태·버전은 변경 전후를 비교한다.
        return {'account_id': row['id'],
                'username_sha256': hashlib.sha256(row['username'].encode()).hexdigest(),
                'role': row['role'], 'enabled': row['enabled'], 'version': row['version']}

    async def identity_snapshot(user_id, request, **kwargs):
        saved = getattr(request.state, 'identity_change_result', None)
        if saved is None:
            current = await execute(identities.snapshot if identities else None, user_id)
            account, bindings = current['user'], current['identities']
            return {'account_id': account['id'], 'version': account['version'],
                    'identities': [binding_summary(item) for item in bindings]}
        return {'account_id': saved['user']['id'], 'version': saved['user']['version'],
                'changed_identity': binding_summary(saved['identity']),
                'operation': saved['operation']}

    def binding_summary(item):
        return {'id': item['id'],
                'issuer_sha256': hashlib.sha256(item['issuer'].encode()).hexdigest(),
                'subject_sha256': hashlib.sha256(item['subject'].encode()).hexdigest()}

    @router.get('/{user_id}/identities', dependencies=[Depends(require_role(Role.ADMIN))])
    async def list_identities(user_id: UUID):
        return await execute(identities.snapshot if identities else None, user_id)

    @router.post('/{user_id}/identities', status_code=201)
    @changes.guard(identity_snapshot)
    async def link_identity(user_id: UUID, body: LinkIdentityRequest, request: Request,
                            actor: dict = Depends(require_role(Role.ADMIN))):
        result = await execute(identities.link if identities else None, user_id,
            body.expected_version, body.issuer, body.subject, str(actor['sub']))
        request.state.identity_change_result = result | {'operation': 'link'}
        return result

    @router.delete('/{user_id}/identities/{identity_id}')
    @changes.guard(identity_snapshot)
    async def unlink_identity(user_id: UUID, identity_id: UUID, body: UnlinkIdentityRequest,
                              request: Request, actor: dict = Depends(require_role(Role.ADMIN))):
        result = await execute(identities.unlink if identities else None, user_id,
            body.expected_version, identity_id, str(actor['sub']))
        request.state.identity_change_result = result | {'operation': 'unlink'}
        return result

    @router.get('', dependencies=[Depends(require_role(Role.ADMIN))])
    async def list_accounts(limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0, le=1000)):
        return await execute(users.list if users else None, limit=limit, offset=offset)

    @router.get('/{user_id}', dependencies=[Depends(require_role(Role.ADMIN))])
    async def get_account(user_id: UUID):
        row = await execute(users.get if users else None, user_id)
        if row is None:
            raise HTTPException(404, 'account_missing')
        return {'user': row}

    @router.post('', status_code=201)
    @changes.guard(snapshot)
    async def create_account(body: CreateAccountRequest, request: Request,
                             actor: dict = Depends(require_role(Role.ADMIN))):
        row = await execute(users.create if users else None, body.username,
                            body.password.get_secret_value(), body.role, str(actor['sub']))
        request.state.account_change_result = row
        return {'user': row}

    @router.put('/{user_id}')
    @changes.guard(snapshot)
    async def update_account(user_id: UUID, body: UpdateAccountRequest, request: Request,
                             actor: dict = Depends(require_role(Role.ADMIN))):
        row = await execute(users.update if users else None, user_id, body.expected_version,
                            role=body.role, enabled=body.enabled, actor=str(actor['sub']))
        request.state.account_change_result = row
        return {'user': row}

    @router.post('/{user_id}/password')
    @changes.guard(snapshot)
    async def reset_password(user_id: UUID, body: ResetPasswordRequest, request: Request,
                             actor: dict = Depends(require_role(Role.ADMIN))):
        row = await execute(users.reset_password if users else None, user_id, body.expected_version,
                            body.password.get_secret_value(), str(actor['sub']))
        request.state.account_change_result = row
        return {'user': row}

    return router
