"""분석 경험 라이브러리 API 테스트.

사람이 확정한 판정과 실행 대비가 일치할 때만 항목이 생긴다. 비교가 없으면
거부된다 — 근거 없는 교훈이 다음 판정을 망치게 두지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.auth_helpers import configured_auth

from netwatcher.detection.experience import ExperienceService
from netwatcher.web.rbac import Role
from netwatcher.web.routes.experiences import create_experiences_router

SECRET = "test-secret"

PROBE_COMPARED = {
    "status": "compared", "comparable": True, "input_hash": "a" * 64,
    "counts": {"added": 0, "removed": 2, "changed": 0, "unchanged": 1},
}
PROPOSAL = {
    "id": 7, "engine": "port_scan", "params": {"threshold": 80},
    "before": {"threshold": 50}, "probe": PROBE_COMPARED,
}
REVIEW = {
    "event_id": 11, "decision": "expected_backup", "note": "프린터 스캔",
    "actor": "analyst",
}
EVENT = {"id": 11, "engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title"}


class FakeProposalRepo:
    def __init__(self, row):
        self._row = row

    async def get_by_id(self, proposal_id):
        return self._row if self._row and self._row["id"] == proposal_id else None


class FakeEventRepo:
    def __init__(self, row):
        self._row = row

    async def get(self, event_id):
        return self._row if self._row and self._row["id"] == event_id else None


class FakeExperienceRepo:
    def __init__(self, review_id=11):
        self.rows = []
        self._review_id = review_id

    async def insert(self, experience):
        self.rows.append(experience)
        return len(self.rows)

    async def latest_review_id_for_engine(self, engine):
        return self._review_id

    async def list_recent(self, limit=50):
        return self.rows[:limit]

    async def list_by_signature(self, engine, signature, limit=5):
        return [
            row for row in self.rows
            if row["engine"] == engine and row["signature"] == signature
        ][:limit]

    async def list_by_signatures(self, signatures, limit_per_signature=5):
        wanted = set(signatures)
        return [row for row in self.rows if (row["engine"], row["signature"]) in wanted]


class FakeReviews:
    def __init__(self, review):
        self._review = review

    async def raw(self, event_id):
        return self._review if self._review and self._review["event_id"] == event_id else None


def _client(proposal=PROPOSAL, review=REVIEW, event=EVENT, review_id=11):
    experiences = FakeExperienceRepo(review_id)
    service = ExperienceService(
        proposal_repo=FakeProposalRepo(proposal),
        event_repo=FakeEventRepo(event),
        experience_repo=experiences,
        reviews=FakeReviews(review),
    )
    app = FastAPI()
    app.include_router(create_experiences_router(service), prefix="/api")
    app.state.auth_manager = configured_auth(SECRET)
    return TestClient(app), experiences


def _token(role: Role) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": "u", "role": role.value, "iat": now, "exp": now + timedelta(hours=1)},
        SECRET, algorithm="HS256",
    )


def _h(role: Role) -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


def test_candidate_is_shown_before_adoption():
    client, _repo = _client()
    response = client.get("/api/experiences/candidate?proposal_id=7", headers=_h(Role.ANALYST))
    assert response.status_code == 200
    candidate = response.json()["candidate"]
    assert candidate["source_proposal_id"] == 7
    assert candidate["evidence"] != {}


def test_candidate_without_comparison_is_refused():
    client, _repo = _client(proposal={**PROPOSAL, "probe": {"status": "skipped"}})
    response = client.get("/api/experiences/candidate?proposal_id=7", headers=_h(Role.ANALYST))
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "no_comparison"


def test_viewer_cannot_see_candidates():
    client, _repo = _client()
    response = client.get("/api/experiences/candidate?proposal_id=7", headers=_h(Role.VIEWER))
    assert response.status_code == 403


def test_analyst_adopts_the_experience():
    client, experiences = _client()
    response = client.post("/api/experiences", headers=_h(Role.ANALYST),
                           json={"proposal_id": 7, "review_id": 11})
    assert response.status_code == 201
    assert response.json()["experience"]["id"] == 1
    assert len(experiences.rows) == 1


def test_adoption_without_comparison_is_refused():
    client, experiences = _client(proposal={**PROPOSAL, "probe": {"status": "skipped"}})
    response = client.post("/api/experiences", headers=_h(Role.ANALYST),
                           json={"proposal_id": 7, "review_id": 11})
    assert response.status_code == 400
    assert experiences.rows == []


def test_viewer_cannot_adopt():
    client, experiences = _client()
    response = client.post("/api/experiences", headers=_h(Role.VIEWER),
                           json={"proposal_id": 7, "review_id": 11})
    assert response.status_code == 403
    assert experiences.rows == []


def test_adopted_experience_is_listed():
    client, _repo = _client()
    client.post("/api/experiences", headers=_h(Role.ANALYST),
                json={"proposal_id": 7, "review_id": 11})
    response = client.get("/api/experiences", headers=_h(Role.VIEWER))
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_adoption_is_recorded_in_the_ledger():
    """경험 반영이 원장에 남는다."""
    client, _repo = _client()
    recorded = []

    class FakeAudit:
        async def log(self, user, action, resource, details=None, ip="", tenant_id=None):
            recorded.append({"action": action, "resource": resource, "details": details})
            return True

    client.app.state.audit_logger = FakeAudit()
    response = client.post("/api/experiences", headers=_h(Role.ANALYST),
                           json={"proposal_id": 7, "review_id": 11})
    assert response.status_code == 201
    ledger = [entry for entry in recorded if entry["action"] == "analysis_experience_adopted"]
    assert len(ledger) == 1
    assert ledger[0]["details"]["source_proposal_id"] == 7
    assert ledger[0]["details"]["lesson"]
