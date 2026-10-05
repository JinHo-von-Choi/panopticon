"""ResponseAction API 테스트 (계획서 2장, PR 13) — 실제 PostgreSQL.

고정하는 것

- approve 와 activate 가 **분리**되어 있다 (approve 는 OS 를 건드리지 않는다)
- 승인 후 값이 바뀌면 activate 가 **409** 다
- 거절된 요청이 적용 속도 제한을 소모하지 않는다
- 재시도가 **만료를 늘리지 않는다**
- shadow 실행기 결과가 **success 로 표시되지 않는다**
- admin 만 승인/적용할 수 있다

여기서 "적용됨" 을 기대하는 테스트가 하나도 없다는 것이 핵심이다. 검증된
만료 백엔드가 없으므로 OS 적용을 주장할 수 없다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from fastapi import FastAPI

from netwatcher.response.executor import ShadowExecutor
from netwatcher.response.lifecycle import LifecycleError
from netwatcher.storage.repositories import ResponseActionRepository
from netwatcher.web.auth import AuthManager
from netwatcher.web.rbac import Role
from netwatcher.web.routes.response import create_response_router

SECRET = "response-secret"


def _auth_manager() -> AuthManager:
    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = SECRET
    manager._expire_hours = 1
    return manager


def _h(role: Role) -> dict:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": "admin", "role": role.value, "iat": now,
         "exp": now + timedelta(hours=1)},
        SECRET, algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _app(db) -> FastAPI:
    app = FastAPI()
    app.state.auth_manager = _auth_manager()
    app.include_router(
        create_response_router(ResponseActionRepository(db), ShadowExecutor()),
        prefix="/api",
    )
    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    )


def _parse(value: str) -> datetime:
    """DB 직렬화와 API 응답의 표현 차이를 없앤 시각 파서."""
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _approve_body(**overrides) -> dict:
    body = {
        "target": "8.8.8.8", "direction": "input", "ttl_seconds": 300,
        "scope": {"asset": "srv-1"}, "base_version": "v1",
    }
    body.update(overrides)
    return body


async def _approve(client: httpx.AsyncClient, **overrides) -> dict:
    body = _approve_body(**overrides)
    # 매핑은 방금 확인된 것으로 본다 (기본값). 문자열로 직렬화해 보낸다
    body.setdefault("mapping_confirmed_at", datetime.now(timezone.utc).isoformat())
    resp = await client.post(
        "/api/change-proposals/1/approve", json=body, headers=_h(Role.ADMIN),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ------------------------------------------------------------------
# 승인 / 적용 분리
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_approve_does_not_touch_os(db) -> None:
    """승인은 결정 기록일 뿐이다. 실행기를 호출하지 않는다."""
    app = _app(db)
    async with _client(app) as client:
        body = await _approve(client)
        caps = (await client.get(
            "/api/response/capabilities", headers=_h(Role.VIEWER),
        )).json()

    assert body["state"] == "requested"
    assert body["approval"]["approved_hash"]
    assert "activate" in body["note"]

    # 배포가 OS 를 건드리지 않는다는 사실을 API 도 같은 방식으로 밝힌다
    assert caps["applies_to_os"] is False
    assert caps["auto_block_enabled"] is False
    assert caps["mode"] == "shadow"


@pytest.mark.asyncio
async def test_activate_records_intent_without_claiming_success(db) -> None:
    """shadow 적용은 'active' 가 아니다. 의도 기록일 뿐이다."""
    app = _app(db)
    async with _client(app) as client:
        approved = await _approve(client)
        resp = await client.post(
            f"/api/response-actions/{approved['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        body = resp.json()

    assert resp.status_code == 200, resp.text
    assert body["verified"] is False
    assert body["state"] != "active_verified"
    assert body["result"]["observed"] == "unknown"
    assert body["result"]["outcome"] == "unverified"
    assert body["expire_at"], "만료 시각은 승인된 TTL 로 정해진다"


@pytest.mark.asyncio
async def test_receipt_is_recorded(db) -> None:
    """영수증에 '확인하지 못했다' 가 남는다."""
    app = _app(db)
    async with _client(app) as client:
        approved = await _approve(client)
        await client.post(
            f"/api/response-actions/{approved['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        detail = (await client.get(
            f"/api/response-actions/{approved['action_id']}",
            headers=_h(Role.VIEWER),
        )).json()

    assert detail["receipts"]
    assert detail["receipts"][0]["outcome"] == "unverified"


# ------------------------------------------------------------------
# 409 — 승인 후 드리프트
# ------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("drift", [
    {"target": "1.1.1.1"},
    {"direction": "output"},
    {"ttl_seconds": 600},
    {"scope": {"asset": "srv-2"}},
    {"base_version": "v2"},
])
async def test_drift_after_approval_is_409(db, drift) -> None:
    """승인한 것과 다르면 적용하지 않는다."""
    app = _app(db)
    async with _client(app) as client:
        approved = await _approve(client)
        resp = await client.post(
            f"/api/response-actions/{approved['action_id']}/activate",
            json=_approve_body(**drift), headers=_h(Role.ADMIN),
        )
        assert resp.status_code == 409, resp.text
        assert resp.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_protected_target_cannot_be_approved(db) -> None:
    """보호 대상은 승인 단계에서 막는다."""
    app = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/change-proposals/1/approve",
            json=_approve_body(target="192.168.1.10"), headers=_h(Role.ADMIN),
        )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_permanent_ttl_rejected_by_schema(db) -> None:
    """영구 조치는 스키마 단계에서 불가능하다."""
    app = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/change-proposals/1/approve",
            json=_approve_body(ttl_seconds=0), headers=_h(Role.ADMIN),
        )
    assert resp.status_code == 422


# ------------------------------------------------------------------
# idempotency + 만료
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_retry_does_not_extend_expiry(db) -> None:
    """재시도가 만료를 늘리지 않는다."""
    app = _app(db)
    async with _client(app) as client:
        approved = await _approve(client)
        action_id = approved["action_id"]

        first = await client.post(
            f"/api/response-actions/{action_id}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        first_expire = first.json()["expire_at"]

        # 상태는 applying 이므로 재시도는 전이 거부로 막히고, 만료는 그대로다
        second = await client.post(
            f"/api/response-actions/{action_id}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert second.status_code == 409

        row = (await client.get(
            f"/api/response-actions/{action_id}", headers=_h(Role.VIEWER),
        )).json()["action"]
        # 문자열 표현이 아니라 시각 값으로 비교한다 (직렬화 형식 차이는 무관)
        assert _parse(row["expire_at"]) == _parse(first_expire), "재시도가 만료를 늘렸다"


@pytest.mark.asyncio
async def test_idempotency_key_reuse_across_actions_is_409(db) -> None:
    """같은 idempotency key 를 다른 조치에 쓰면 거부한다."""
    app = _app(db)
    async with _client(app) as client:
        first = await _approve(client)
        second = await _approve(client)

        headers = _h(Role.ADMIN)
        headers["Idempotency-Key"] = "same-key"

        await client.post(
            f"/api/response-actions/{first['action_id']}/activate",
            json=_approve_body(), headers=headers,
        )
        resp = await client.post(
            f"/api/response-actions/{second['action_id']}/activate",
            json=_approve_body(), headers=headers,
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["existing_action_id"] == first["action_id"]


# ------------------------------------------------------------------
# 권한
# ------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
async def test_only_admin_may_approve(db, role) -> None:
    app = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/change-proposals/1/approve", json=_approve_body(), headers=_h(role),
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_can_read_actions(db) -> None:
    app = _app(db)
    async with _client(app) as client:
        resp = await client.get("/api/response-actions", headers=_h(Role.VIEWER))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_unauthenticated_rejected(db) -> None:
    app = _app(db)
    async with _client(app) as client:
        resp = await client.get("/api/response/capabilities")
    assert resp.status_code == 401


# ------------------------------------------------------------------
# 실행 시점 매핑 신선도 (계획서 4장)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stale_mapping_blocks_activation(db) -> None:
    """오래된 매핑으로는 실행하지 않는다.

    제안 단계에서는 불확실성으로 남겨도 된다. **실행** 시점에는 막는다.
    """
    from datetime import timedelta

    app = _app(db)
    stale = datetime.now(timezone.utc) - timedelta(hours=1)
    async with _client(app) as client:
        approved = await _approve(
            client, mapping_confirmed_at=stale.isoformat())
        resp = await client.post(
            f"/api/response-actions/{approved['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["context"]["reason"] == "mapping_stale"


@pytest.mark.asyncio
async def test_missing_mapping_confirmation_blocks_activation(db) -> None:
    """매핑 확인 시각이 없으면 실행하지 않는다 — 추측으로 실행하지 않는다."""
    app = _app(db)
    async with _client(app) as client:
        approved = await _approve(client, mapping_confirmed_at=None)
        resp = await client.post(
            f"/api/response-actions/{approved['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["context"]["reason"] == "mapping_unconfirmed"


@pytest.mark.asyncio
async def test_fresh_mapping_allows_activation(db) -> None:
    app = _app(db)
    fresh = datetime.now(timezone.utc)
    async with _client(app) as client:
        approved = await _approve(
            client, mapping_confirmed_at=fresh.isoformat())
        resp = await client.post(
            f"/api/response-actions/{approved['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert resp.status_code == 200, resp.text
        # 그래도 적용 성공은 아니다 — shadow 다
        assert resp.json()["verified"] is False


# ------------------------------------------------------------------
# 429 — 적용 속도 제한 (계획서 2장 초기 제한: 분당 1개)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_second_activation_within_minute_is_rejected(db) -> None:
    """분당 1개를 넘으면 거절한다.

    429 는 OS 를 건드리기 전에 난다. 거절된 조치의 상태는 `requested`
    그대로여야 한다. 실패한 적용이 남으면 안 된다.
    """
    app = _app(db)
    fresh = datetime.now(timezone.utc)
    async with _client(app) as client:
        first = await _approve(client, mapping_confirmed_at=fresh.isoformat())
        ok = await client.post(
            f"/api/response-actions/{first['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert ok.status_code == 200, ok.text

        second = await _approve(client, mapping_confirmed_at=fresh.isoformat())
        limited = await client.post(
            f"/api/response-actions/{second['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert limited.status_code == 429, limited.text

        detail = (await client.get(
            f"/api/response-actions/{second['action_id']}",
            headers=_h(Role.VIEWER),
        )).json()

    # 거절은 실행이 아니다 — 기록이 남지 않는다
    assert detail["action"]["state"] == "requested"
    assert detail["receipts"] == []


@pytest.mark.asyncio
async def test_rate_limit_raises_http_429() -> None:
    """RateLimiter 자체가 계획서의 초기 제한값을 지키는지."""
    from netwatcher.response.lifecycle import RateLimiter

    limiter = RateLimiter()
    limiter.acquire(1)
    with pytest.raises(LifecycleError) as caught:
        limiter.acquire(2)
    assert caught.value.status_code == 429


@pytest.mark.asyncio
async def test_rejected_request_does_not_consume_rate_limit(db) -> None:
    """409 로 거절된 요청은 상한을 소모하지 않는다.

    매핑이 오래된 요청은 OS 를 건드리지 않았다. 그 요청이 상한을 먹으면
    실제로 적용할 수 있는 조치까지 429 로 막힌다. 거절과 실행을 구분해야
    상한이 안전장치로 남는다.
    """
    app = _app(db)
    stale = datetime.now(timezone.utc) - timedelta(hours=1)
    async with _client(app) as client:
        rejected = await _approve(client, mapping_confirmed_at=stale.isoformat())
        blocked = await client.post(
            f"/api/response-actions/{rejected['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
        assert blocked.status_code == 409

        fresh = datetime.now(timezone.utc)
        allowed = await _approve(client, mapping_confirmed_at=fresh.isoformat())
        resp = await client.post(
            f"/api/response-actions/{allowed['action_id']}/activate",
            json=_approve_body(), headers=_h(Role.ADMIN),
        )
    assert resp.status_code == 200, resp.text
