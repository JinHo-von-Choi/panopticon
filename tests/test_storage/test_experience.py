"""분석 경험 라이브러리 저장 테스트.

경험 항목은 증거가 비어 있으면 존재할 수 없고, 근거가 된 제안·판정이
실제로 존재해야 한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from netwatcher.storage.repositories import ConfigProposalRepository, ExperienceRepository


async def _proposal(db) -> int:
    repo = ConfigProposalRepository(db)
    return await repo.insert(
        engine="port_scan", params={"threshold": 80}, reason="오탐",
        probe={"status": "compared", "comparable": True,
               "counts": {"added": 0, "removed": 2, "changed": 0, "unchanged": 1}},
    )


def _experience(proposal_id: int, **overrides) -> dict:
    experience = {
        "engine": "port_scan",
        "signature": "port_scan:engines.port_scan.alerts.scan.title",
        "domain": "network_scan:printer",
        "cue": "매일 09:00 프린터 스캔",
        "lesson": "정상 판정 — 임계값 50 → 80",
        "evidence": {"probe": {"counts": {"removed": 2}}},
        "confidence": 0.8,
        "source_proposal_id": proposal_id,
        "source_review_id": None,
        "expires_at": None,
    }
    experience.update(overrides)
    return experience


@pytest.mark.asyncio
async def test_experience_is_stored_and_read(db):
    repo = ExperienceRepository(db)
    proposal_id = await _proposal(db)
    experience_id = await repo.insert(_experience(proposal_id))

    row = await repo.get(experience_id)
    assert row["engine"] == "port_scan"
    assert row["domain"] == "network_scan:printer"
    assert row["evidence"]["probe"]["counts"]["removed"] == 2


@pytest.mark.asyncio
async def test_empty_evidence_is_refused(db):
    repo = ExperienceRepository(db)
    proposal_id = await _proposal(db)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await repo.insert(_experience(proposal_id, evidence={}))


@pytest.mark.asyncio
async def test_missing_proposal_reference_is_refused(db):
    repo = ExperienceRepository(db)
    with pytest.raises(asyncpg.exceptions.ForeignKeyViolationError):
        await repo.insert(_experience(999999))


@pytest.mark.asyncio
async def test_expired_experience_is_not_returned(db):
    repo = ExperienceRepository(db)
    proposal_id = await _proposal(db)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    await repo.insert(_experience(
        proposal_id, signature="port_scan:expired",
        expires_at=(past + timedelta(hours=1)).isoformat(),
    ))
    await repo.insert(_experience(proposal_id, signature="port_scan:live"))

    expired = await repo.list_by_signature("port_scan", "port_scan:expired")
    live = await repo.list_by_signature("port_scan", "port_scan:live")
    assert expired == []
    assert len(live) == 1


@pytest.mark.asyncio
async def test_experiences_are_found_by_signature_pairs(db):
    repo = ExperienceRepository(db)
    proposal_id = await _proposal(db)
    await repo.insert(_experience(proposal_id, signature="port_scan:a"))
    await repo.insert(_experience(proposal_id, signature="port_scan:b"))

    rows = await repo.list_by_signatures([("port_scan", "port_scan:a")])
    assert [row["signature"] for row in rows] == ["port_scan:a"]

    empty = await repo.list_by_signatures([])
    assert empty == []


@pytest.mark.asyncio
async def test_deleting_the_source_proposal_invalidates_the_experience(db):
    """출처 제안이 사라지면 경험도 사라진다 — 근거 없는 교훈을 남기지 않는다."""
    repo = ExperienceRepository(db)
    proposal_id = await _proposal(db)
    experience_id = await repo.insert(_experience(proposal_id))
    assert await repo.get(experience_id) is not None

    async with db.pool.acquire() as conn:
        await conn.execute("DELETE FROM config_proposals WHERE id = $1", proposal_id)

    assert await repo.get(experience_id) is None
