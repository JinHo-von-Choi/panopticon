"""리플레이 실행·비교 API 테스트 (계획서 1장, PR 12).

이 테스트는 **실제 PostgreSQL** 위에서 돈다. 격리 실행이 실제로 격리되어
있는지(운영 events 테이블에 아무것도 안 쓰였는지) DB 를 직접 확인해야 하기
때문이다.

고정하는 것

- 실행은 비동기다 (핸들러가 끝나기 전에 완료 상태를 내놓지 않는다)
- diff 는 완료된 실행에만 나온다
- 비교 불가 사유가 응답에 그대로 실린다
- 리플레이가 운영 events 테이블을 건드리지 않는다
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from fastapi import FastAPI

from netwatcher.replay.runs import ReplayRunService
from netwatcher.storage.repositories import ReplayRepository
from netwatcher.web.auth import AuthManager
from netwatcher.web.routes.replay import create_replay_router
from netwatcher.web.rbac import Role
from netwatcher.utils.config import Config

SECRET = "replay-secret"


def _auth_manager() -> AuthManager:
    manager = AuthManager(Config({
        "auth": {
            "enabled": True, "username": "admin", "password": "x",
            "jwt_secret": SECRET, "token_expire_hours": 1,
        },
    }))
    # AuthManager 는 NETWATCHER_JWT_SECRET 환경변수를 우선한다. 로컬 .env 에 따라
    # 테스트 결과가 달라지지 않도록 여기서 고정한다.
    manager._secret = SECRET
    manager._expire_hours = 1
    return manager


def _token(role: Role) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": "admin", "role": role.value, "iat": now, "exp": now + timedelta(hours=1)},
        SECRET, algorithm="HS256",
    )


def _h(role: Role) -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


def _app(db) -> tuple[FastAPI, ReplayRunService]:
    """실제 DB 를 쓰는 리플레이 앱.

    ``TestClient`` 는 쓰지 않는다. 앱을 **별도의 이벤트 루프**에서 실행하는데
    asyncpg 커넥션은 현재 루프에 묶여 있어
    ``ConnectionDoesNotExistError`` 로 죽는다. 같은 루프의
    ``httpx.ASGITransport`` 로 실제 HTTP 경로를 통과시킨다.
    """
    app = FastAPI()
    app.state.auth_manager = _auth_manager()
    service = ReplayRunService(ReplayRepository(db))
    app.include_router(create_replay_router(service), prefix="/api")
    return app, service


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    )


def _payload(**overrides) -> dict:
    payload = {
        "records": [
            {
                "src_ip": "10.0.0.9", "dst_ip": "10.0.0.2",
                "src_mac": "aa:bb:cc:00:00:01", "dst_mac": "aa:bb:cc:00:00:02",
                "dst_port": 1000 + i, "bytes": 120, "ts": 1.0 + i * 0.1,
                "ip_proto": "tcp",
            }
            for i in range(30)
        ],
        "engines": ["port_scan"],
        "baseline_params": {"threshold": 5},
        "candidate_params": {"threshold": 40},
        "baseline_version": "v1",
        "candidate_version": "v1",
        "config_version": "c1",
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------
# 실행 → diff
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_is_asynchronous_and_accepted(db) -> None:
    """POST 는 시작만 한다. 202 로 즉시 반환한다."""
    app, _service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(), headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "pending"
    assert body["input_count"] == 30
    assert body["trace_id"]


@pytest.mark.asyncio
async def test_diff_reports_removed_observation(db) -> None:
    """임계값을 올리면 관측이 사라진다 — 감소를 성공으로 해석하지 않는다."""
    app, service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(), headers=_h(Role.ANALYST),
        )
        run_id = resp.json()["run_id"]
        await service.wait(run_id, timeout=15.0)

        diff = (await client.get(
            f"/api/replay-runs/{run_id}/diff", headers=_h(Role.VIEWER),
        )).json()

    assert diff["status"] == "completed"
    assert diff["diff"]["counts"]["removed"] == 1
    assert "오탐 감소의 증거가 아니다" in diff["diff"]["interpretation"]["notice"]


@pytest.mark.asyncio
async def test_identical_versions_produce_identical_hash(db) -> None:
    """같은 버전·같은 설정 두 번 → 결과 해시 동일.

    후보 쪽 임계값까지 같아야 한다. 다르면 당연히 결과가 달라지는데,
    그건 "재현 실패" 가 아니라 "설정이 다름" 이다.
    """
    app, service = _app(db)
    same = _payload(candidate_params={"threshold": 5})
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=same, headers=_h(Role.ANALYST),
        )
        run_id = resp.json()["run_id"]
        await service.wait(run_id, timeout=15.0)
        body = (await client.get(
            f"/api/replay-runs/{run_id}/diff", headers=_h(Role.VIEWER),
        )).json()

    assert body["results_identical"] is True
    assert body["comparable"] is True


@pytest.mark.asyncio
async def test_unsupported_engine_reason_is_surfaced(db) -> None:
    """지원 밖 엔진은 실행 실패가 아니라 사유와 함께 끝난다."""
    app, service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(engines=["tls_fingerprint"]),
            headers=_h(Role.ANALYST),
        )
        run_id = resp.json()["run_id"]
        await service.wait(run_id, timeout=15.0)
        body = (await client.get(
            f"/api/replay-runs/{run_id}/diff", headers=_h(Role.VIEWER),
        )).json()

    assert body["comparable"] is False
    assert "engine_not_supported" in {r["code"] for r in body["non_comparable_reasons"]}


@pytest.mark.asyncio
async def test_incomplete_input_blocks_comparison(db) -> None:
    """입력이 잘렸으면 비교 불가로 남는다."""
    app, service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(complete=False),
            headers=_h(Role.ANALYST),
        )
        run_id = resp.json()["run_id"]
        await service.wait(run_id, timeout=15.0)
        body = (await client.get(
            f"/api/replay-runs/{run_id}/diff", headers=_h(Role.VIEWER),
        )).json()

    assert body["comparable"] is False
    assert "trace_incomplete" in {r["code"] for r in body["non_comparable_reasons"]}


@pytest.mark.asyncio
async def test_version_mismatch_blocks_comparison(db) -> None:
    """버전 지문이 다르면 비교 불가 — 차이의 출처를 특정할 수 없다."""
    app, service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(
                baseline_version="v1", candidate_version="v2",
            ),
            headers=_h(Role.ANALYST),
        )
        run_id = resp.json()["run_id"]
        await service.wait(run_id, timeout=15.0)
        body = (await client.get(
            f"/api/replay-runs/{run_id}/diff", headers=_h(Role.VIEWER),
        )).json()

    assert body["comparable"] is False
    assert "version_scope_mismatch" in {r["code"] for r in body["non_comparable_reasons"]}


@pytest.mark.asyncio
async def test_replay_does_not_write_operational_events_table(db) -> None:
    """격리를 DB 에서 직접 확인한다 — 운영 events 에 행이 없어야 한다."""
    app, service = _app(db)
    before = await db.pool.fetchval("SELECT COUNT(*) FROM events")

    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(), headers=_h(Role.ANALYST),
        )
        await service.wait(resp.json()["run_id"], timeout=15.0)

    after = await db.pool.fetchval("SELECT COUNT(*) FROM events")
    assert after == before, "리플레이가 운영 events 테이블을 건드렸다"

    # 격리 테이블에는 결과가 남아야 한다 — 격리 저장은 되지만 말만 하지 않도록
    stored = await db.pool.fetchval("SELECT COUNT(*) FROM replay_results")
    assert stored > 0


@pytest.mark.asyncio
async def test_trace_and_run_are_persisted(db) -> None:
    """재현에 필요한 trace(입력 해시·순서)와 실행 기록이 남는다."""
    app, service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(), headers=_h(Role.ANALYST),
        )
        run_id = resp.json()["run_id"]
        await service.wait(run_id, timeout=15.0)

    run = await db.pool.fetchrow("SELECT * FROM replay_runs WHERE id = $1", run_id)
    trace = await db.pool.fetchrow(
        "SELECT * FROM replay_traces WHERE trace_id = $1", run["trace_id"],
    )
    assert trace["input_hash"]
    assert trace["order_key"]
    assert trace["input_count"] == 30
    assert run["baseline_result_hash"]


# ------------------------------------------------------------------
# 권한 · 입력 검증
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_viewer_cannot_submit_run(db) -> None:
    """실행 요청은 analyst 이상. 조회는 viewer 로 충분하다."""
    app, _service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(), headers=_h(Role.VIEWER),
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_can_read_diff(db) -> None:
    """viewer 는 조회를 할 수 있다 (실행 요청은 analyst 이상)."""
    app, service = _app(db)
    async with _client(app) as client:
        created = await client.post(
            "/api/replay-runs", json=_payload(), headers=_h(Role.ANALYST),
        )
        run_id = created.json()["run_id"]
        await service.wait(run_id, timeout=15.0)
        resp = await client.get(
            f"/api/replay-runs/{run_id}/diff", headers=_h(Role.VIEWER),
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_empty_engines_rejected(db) -> None:
    app, _service = _app(db)
    async with _client(app) as client:
        resp = await client.post(
            "/api/replay-runs", json=_payload(engines=[]), headers=_h(Role.ANALYST),
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_missing_run_returns_404(db) -> None:
    app, _service = _app(db)
    async with _client(app) as client:
        resp = await client.get(
            "/api/replay-runs/999999/diff", headers=_h(Role.VIEWER),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(db) -> None:
    app, _service = _app(db)
    async with _client(app) as client:
        resp = await client.get("/api/replay-runs")
    assert resp.status_code == 401
