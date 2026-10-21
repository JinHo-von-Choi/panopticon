"""제안 대비 결과 저장 테스트.

승인 큐에 들어가는 제안은 대비 또는 명시적 사유를 갖는다. 그 계약이
DB 에서 지켜지는지 확인한다.
"""

from __future__ import annotations

import asyncpg
import pytest

from netwatcher.storage.repositories import ConfigProposalRepository

RECORDS = [
    {"src_ip": "10.0.0.5", "dst_port": 22, "ts": 1000.0},
    {"src_ip": "10.0.0.5", "dst_port": 23, "ts": 1001.0},
    {"src_ip": "10.0.0.5", "dst_port": 24, "ts": 1002.0},
]


@pytest.mark.asyncio
async def test_proposal_without_input_keeps_explicit_reason(db):
    repo = ConfigProposalRepository(db)
    proposal_id = await repo.insert(
        engine="port_scan", params={"threshold": 2}, reason="오탐",
    )
    row = await repo.get_by_id(proposal_id)
    assert row["probe"]["status"] == "skipped"
    assert row["probe"]["reasons"][0]["code"] == "trace_unavailable"


@pytest.mark.asyncio
async def test_probe_result_is_stored(db):
    repo = ConfigProposalRepository(db)
    proposal_id = await repo.insert(
        engine="port_scan", params={"threshold": 2}, reason="오탐",
        probe={"status": "compared", "counts": {"added": 1}},
    )
    row = await repo.get_by_id(proposal_id)
    assert row["probe"]["status"] == "compared"
    assert row["probe"]["counts"]["added"] == 1


@pytest.mark.asyncio
async def test_attach_probe_updates_pending_proposal(db):
    repo = ConfigProposalRepository(db)
    proposal_id = await repo.insert(
        engine="port_scan", params={"threshold": 2}, reason="오탐",
    )
    assert await repo.attach_probe(proposal_id, {"status": "compared"}) is True
    row = await repo.get_by_id(proposal_id)
    assert row["probe"]["status"] == "compared"


@pytest.mark.asyncio
async def test_probe_without_status_is_refused_by_the_database(db):
    """사유 없는 미실행은 남지 않는다 — DB 가 막는다."""
    repo = ConfigProposalRepository(db)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await repo.insert(
            engine="port_scan", params={"threshold": 2}, reason="오탐",
            probe={"counts": {"added": 0}},
        )
