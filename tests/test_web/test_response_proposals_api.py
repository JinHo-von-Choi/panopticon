"""최소 대응 제안 API 테스트 (계획서 4장) — 실제 PostgreSQL.

고정하는 것

- POST 는 **제안만** 만든다 (`approved: false`)
- `/impact` 는 확정 범위와 미확인 범위를 **분리** 해 돌려준다
- 좁힐 수 없으면 409 — 넓은 IP 차단으로 대체하지 않는다
- 관측이 stale/unknown 이면 409
- AI 출처는 403
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from fastapi import FastAPI

from netwatcher.storage.repositories import ResponseProposalRepository
from netwatcher.web.auth import AuthManager
from netwatcher.web.rbac import Role
from netwatcher.web.routes.response_proposals import create_response_proposals_router

SECRET = "proposal-secret"


def _auth_manager() -> AuthManager:
    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = SECRET
    manager._expire_hours = 1
    return manager


def _h(role: Role) -> dict:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": "analyst", "role": role.value, "iat": now,
         "exp": now + timedelta(hours=1)},
        SECRET, algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _client(db) -> httpx.AsyncClient:
    app = FastAPI()
    app.state.auth_manager = _auth_manager()
    app.include_router(
        create_response_proposals_router(ResponseProposalRepository(db)), prefix="/api",
    )
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    )


def _body(**overrides) -> dict:
    body = {
        "source_ip": "8.8.8.8", "engine": "port_scan",
        "visibility_state": "observed",
        "evidence": {"summary": "25 ports scanned", "raw_layers": 3},
        "asset_id": "srv-1", "team": "infra", "criticality": "high",
        "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "scope_kind": "port", "ports": [22, 80], "service_aware": True,
        "peers": [
            {"asset_id": "db-1", "team": "data", "criticality": "critical", "confirmed": True},
            {"asset_id": "cache-1", "team": "data", "criticality": "low", "confirmed": False},
        ],
    }
    body.update(overrides)
    return body


# ------------------------------------------------------------------
# 생성 = 제안일 뿐
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_makes_proposal_not_action(db) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals", json=_body(), headers=_h(Role.ANALYST),
        )
        body = resp.json()

    assert resp.status_code == 201
    assert body["status"] == "proposed"
    assert body["approved"] is False
    assert "승인 없이는 어떤 조치도 실행되지 않는다" in body["notice"]


@pytest.mark.asyncio
async def test_impact_separates_confirmed_and_unconfirmed(db) -> None:
    async with _client(db) as client:
        created = (await client.post(
            "/api/response-proposals", json=_body(), headers=_h(Role.ANALYST),
        )).json()
        impact = (await client.get(
            created["impact_url"], headers=_h(Role.VIEWER),
        )).json()

    assert impact["observed_scope"]["asset_ids"] == ["db-1"]
    assert impact["unconfirmed_scope"]["asset_ids"] == ["cache-1"]
    assert impact["observed_scope"]["highest_criticality"] == "critical"
    assert "관측된 영향이 아니라" in impact["unconfirmed_scope"]["note"]
    assert "제안일 뿐 승인된 조치 아니다" in impact["guardrails"]["approval_required"]


# ------------------------------------------------------------------
# 좁히지 못하면 제안하지 않는다
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ip_only_scope_is_refused(db) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals",
            json=_body(scope_kind="ip", ports=[], service_aware=False),
            headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 409
    ctx = resp.json()["detail"]["context"]
    assert "backend_cannot_narrow_scope" in str(ctx)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["stale", "unknown"])
async def test_untrustworthy_observation_blocks_proposal(db, state) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals",
            json=_body(visibility_state=state), headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 409
    assert resp.json()["detail"]["context"]["visibility_state"] == state


@pytest.mark.asyncio
async def test_ai_cannot_create_proposal(db) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals",
            json=_body(created_by="ai"), headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_shared_ip_records_uncertainty(db) -> None:
    async with _client(db) as client:
        created = (await client.post(
            "/api/response-proposals", json=_body(shared=True),
            headers=_h(Role.ANALYST),
        )).json()
        impact = (await client.get(
            created["impact_url"], headers=_h(Role.VIEWER),
        )).json()

    assert "shared_ip_or_nat" in impact["uncertainty"]
    assert "shared_ip_or_nat" in impact["unconfirmed_scope"]["reasons"]


@pytest.mark.asyncio
async def test_stale_mapping_records_uncertainty(db) -> None:
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    async with _client(db) as client:
        created = (await client.post(
            "/api/response-proposals", json=_body(confirmed_at=old.isoformat()),
            headers=_h(Role.ANALYST),
        )).json()
        impact = (await client.get(
            created["impact_url"], headers=_h(Role.VIEWER),
        )).json()

    assert "asset_mapping_stale" in impact["uncertainty"]


@pytest.mark.asyncio
async def test_missing_mapping_refuses_proposal(db) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals", json=_body(asset_id=None),
            headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_ttl_bounded_by_schema(db) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals", json=_body(ttl_seconds=0),
            headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 422


# ------------------------------------------------------------------
# 권한
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_viewer_cannot_create(db) -> None:
    async with _client(db) as client:
        resp = await client.post(
            "/api/response-proposals", json=_body(), headers=_h(Role.VIEWER),
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_rejected(db) -> None:
    async with _client(db) as client:
        resp = await client.get("/api/response-proposals")
    assert resp.status_code == 401
