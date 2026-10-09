"""제안 승인 큐 API + 역할 분리 테스트 (PR 10).

계획서의 "읽기 / 제안 / 승인 3역할"을 HTTP 경계에서 고정한다.

| 동작 | viewer | analyst | admin |
|-|-|-|-|
| 목록 조회 | O | O | O |
| 제안 접수 | X | O | O |
| 승인 / 거절 | X | X | O |

승인은 곧 설정 쓰기다. 따라서 ADMIN 이 필요하고, 검증은 접수와 승인 두 번
모두 돈다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import jwt
import pytest
from tests.auth_helpers import configured_auth
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.detection.proposals import STATUS_PENDING, ProposalService
from netwatcher.web.routes.proposals import create_proposals_router
from netwatcher.web.rbac import Role

SCHEMA = {
    "enabled": (bool, True),
    "threshold": {"type": int, "default": 50, "min": 1, "max": 1000},
}
CURRENT = {"enabled": True, "threshold": 50}
SECRET = "test-secret"


class FakeRepo:
    def __init__(self) -> None:
        self.rows: dict[int, dict] = {}
        self._next = 1

    async def insert(self, engine, params, reason="", source="human", before=None):
        pid = self._next
        self._next += 1
        self.rows[pid] = {
            "id": pid, "engine": engine, "params": dict(params),
            "reason": reason, "source": source, "before": dict(before or {}),
            "status": STATUS_PENDING, "applied": None, "apply_error": None,
        }
        return pid

    async def get_by_id(self, pid):
        return self.rows.get(pid)

    async def list_pending(self, limit=50):
        return [r for r in self.rows.values() if r["status"] == STATUS_PENDING][:limit]

    async def list_recent(self, limit=50, status=None):
        items = list(self.rows.values())
        if status:
            items = [r for r in items if r["status"] == status]
        return items[:limit]

    async def count_pending(self):
        return sum(1 for r in self.rows.values() if r["status"] == STATUS_PENDING)

    async def decide(self, pid, status, decided_by, note=""):
        row = self.rows.get(pid)
        if row is None or row["status"] != STATUS_PENDING:
            return False
        row.update(status=status, decided_by=decided_by, decision_note=note)
        return True

    async def mark_applied(self, pid, applied, error=None):
        row = self.rows[pid]
        row.update(applied=applied, apply_error=error,
                   status="approved" if applied else "failed")


def _client(repo=None, reload_result=(True, None, [])) -> tuple[TestClient, MagicMock, FakeRepo]:
    repo = repo or FakeRepo()
    registry = MagicMock()
    registry.get_engine_schema.return_value = SCHEMA
    registry.reload_engine.return_value = reload_result
    editor = MagicMock()
    editor.get_engine_config.return_value = dict(CURRENT)
    editor.update_engine_config.return_value = None

    svc = ProposalService(registry=registry, yaml_editor=editor, proposal_repo=repo)
    svc._registry = registry
    svc._editor = editor

    app = FastAPI()
    app.include_router(create_proposals_router(svc), prefix="/api")

    # 인증을 켠 상태로 역할 검증을 실제로 건다
    manager = configured_auth(SECRET)
    app.state.auth_manager = manager

    return TestClient(app), editor, repo


def _token(role: Role) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": "u", "role": role.value, "iat": now, "exp": now + timedelta(hours=1)},
        SECRET, algorithm="HS256",
    )


def _h(role: Role) -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


def test_submit_does_not_hide_config_read_failure():
    client, editor, repo = _client()
    editor.get_engine_config.side_effect = OSError("private configuration path")
    response = client.post("/api/proposals", headers=_h(Role.ANALYST),
                           json={"engine": "port_scan", "params": {"threshold": 80}})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "현재 설정을 조회할 수 없습니다"
    assert "private configuration path" not in response.text
    assert repo.rows == {}


def test_apply_error_response_and_queue_do_not_expose_internal_exception():
    client, editor, repo = _client()
    response = client.post("/api/proposals", headers=_h(Role.ANALYST),
                           json={"engine": "port_scan", "params": {"threshold": 80}})
    assert response.status_code == 201
    pid = response.json()["id"]
    editor.update_engine_config.side_effect = OSError("private configuration path")
    response = client.post(f"/api/proposals/{pid}/approve", headers=_h(Role.ADMIN), json={})
    assert response.status_code == 200
    assert response.json()["applied"] is False
    assert response.json()["status"] == "failed"
    assert "private configuration path" not in response.text
    response = client.get("/api/proposals", headers=_h(Role.VIEWER))
    assert response.status_code == 200
    assert "private configuration path" not in response.text
    assert repo.rows[pid]["apply_error"] == "설정 제안 반영에 실패했습니다. 현재 설정을 확인하세요"


# ------------------------------------------------------------------
# 역할 분리
# ------------------------------------------------------------------

@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST, Role.ADMIN])
def test_all_roles_can_list(role):
    client, _, _ = _client()
    resp = client.get("/api/proposals", headers=_h(role))
    assert resp.status_code == 200
    assert "proposals" in resp.json()


def test_viewer_cannot_submit_proposal():
    client, editor, repo = _client()
    resp = client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(Role.VIEWER),
    )
    assert resp.status_code == 403
    assert repo.rows == {}
    editor.update_engine_config.assert_not_called()


@pytest.mark.parametrize("role", [Role.ANALYST, Role.ADMIN])
def test_analyst_and_admin_can_submit(role):
    client, _, repo = _client()
    resp = client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(role),
    )
    assert resp.status_code == 201
    assert len(repo.rows) == 1
    # 제안만으로는 아무것도 바뀌지 않는다
    repo.rows[1]["status"] == STATUS_PENDING


@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
def test_non_admin_cannot_approve(role):
    client, editor, repo = _client()
    client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(Role.ANALYST),
    )
    resp = client.post(
        "/api/proposals/1/approve",
        json={"decided_by": "someone"},
        headers=_h(role),
    )
    assert resp.status_code == 403
    editor.update_engine_config.assert_not_called()
    assert repo.rows[1]["status"] == STATUS_PENDING


def test_admin_can_approve():
    client, editor, repo = _client()
    client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(Role.ADMIN),
    )
    resp = client.post(
        "/api/proposals/1/approve",
        json={"decided_by": "admin", "note": "확인함"},
        headers=_h(Role.ADMIN),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["applied"] is True
    editor.update_engine_config.assert_called_once()


def test_admin_can_reject():
    client, editor, repo = _client()
    client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(Role.ADMIN),
    )
    resp = client.post(
        "/api/proposals/1/reject",
        json={"decided_by": "admin"},
        headers=_h(Role.ADMIN),
    )
    assert resp.json()["status"] == "rejected"
    editor.update_engine_config.assert_not_called()


# ------------------------------------------------------------------
# 검증이 HTTP 경계에서도 작동하는지
# ------------------------------------------------------------------

def test_schema_violation_returns_400_with_violations():
    client, editor, repo = _client()
    resp = client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": True}},
        headers=_h(Role.ANALYST),
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["violations"]
    assert repo.rows == {}
    editor.update_engine_config.assert_not_called()


def test_apply_failure_is_reported_truthfully():
    client, editor, repo = _client(reload_result=(False, "engine rejected", []))
    client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(Role.ADMIN),
    )
    resp = client.post(
        "/api/proposals/1/approve",
        json={"decided_by": "admin"},
        headers=_h(Role.ADMIN),
    )
    body = resp.json()
    assert body["applied"] is False
    assert body["status"] == "failed"
    assert body["error"]
    editor.update_engine_config.assert_not_called()


def test_pending_count_exposed():
    client, _, _ = _client()
    client.post(
        "/api/proposals",
        json={"engine": "port_scan", "params": {"threshold": 80}},
        headers=_h(Role.ADMIN),
    )
    body = client.get("/api/proposals", headers=_h(Role.VIEWER)).json()
    assert body["pending"] == 1


def test_missing_token_rejected():
    client, _, _ = _client()
    assert client.get("/api/proposals").status_code == 401
