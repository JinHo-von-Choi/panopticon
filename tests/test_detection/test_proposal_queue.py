"""설정 제안 승인 큐 테스트 (PR 10).

이 테스트는 "승인"이 실제로 어떤 의미인지 고정한다.

- **제안은 큐에 들어가지 않는다** — 스키마를 어기면
- **승인만이 쓴다** — 거절은 아무것도 바꾸지 않는다
- **승인해도 검증은 다시 돈다** — 접수 후 다른 사람이 설정을 바꿨을 수 있다
- **반영 실패를 성공으로 위장하지 않는다** — status=failed 와 사유를 남긴다
- **역할** — 제안은 analyst, 승인은 admin
- **되돌릴 근거** — 승인 시점의 이전 설정을 남긴다
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from netwatcher.detection.proposals import (
    SOURCE_AI,
    STATUS_APPROVED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_REJECTED,
    ProposalError,
    ProposalService,
)

SCHEMA = {
    "enabled": (bool, True),
    "threshold": {"type": int, "default": 50, "min": 1, "max": 1000},
    "window_seconds": {"type": int, "default": 60, "min": 1, "max": 3600},
}

CURRENT = {"enabled": True, "threshold": 50, "window_seconds": 60}


class FakeRepo:
    """DB 동작을 흉내 낸 저장소."""

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
        row["applied"] = applied
        row["apply_error"] = error
        row["status"] = STATUS_APPROVED if applied else STATUS_FAILED


def _service(repo=None, reload_result=(True, None, [])):
    registry = MagicMock()
    registry.get_engine_schema.return_value = SCHEMA
    registry.reload_engine.return_value = reload_result

    editor = MagicMock()
    editor.get_engine_config.return_value = dict(CURRENT)
    editor.update_engine_config.return_value = None

    svc = ProposalService(registry=registry, yaml_editor=editor, proposal_repo=repo)
    svc._registry = registry
    svc._editor = editor
    return svc


# ------------------------------------------------------------------
# 1. 제안 접수
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_proposal_is_accepted():
    repo = FakeRepo()
    svc = _service(repo)
    pid = await svc.submit("port_scan", {"threshold": 80}, reason="오탐")
    assert pid == 1
    assert repo.rows[1]["status"] == STATUS_PENDING
    assert repo.rows[1]["source"] == "human"


@pytest.mark.asyncio
async def test_proposal_records_current_config_for_rollback():
    repo = FakeRepo()
    svc = _service(repo)
    await svc.submit("port_scan", {"threshold": 80})
    # 되돌리기 근거가 없으면 승인 후 원복할 수 없다
    assert repo.rows[1]["before"]["threshold"] == 50


@pytest.mark.asyncio
async def test_ai_source_is_recorded():
    repo = FakeRepo()
    svc = _service(repo)
    await svc.submit("port_scan", {"threshold": 80}, source=SOURCE_AI)
    assert repo.rows[1]["source"] == "ai"


@pytest.mark.asyncio
async def test_schema_violation_is_rejected_at_submit():
    repo = FakeRepo()
    svc = _service(repo)

    with pytest.raises(ProposalError) as exc:
        await svc.submit("port_scan", {"threshold": True})

    assert exc.value.violations
    assert repo.rows == {}, "스키마를 어기는 제안이 큐에 들어갔다"


@pytest.mark.asyncio
async def test_undeclared_key_is_rejected_at_submit():
    repo = FakeRepo()
    svc = _service(repo)
    with pytest.raises(ProposalError):
        await svc.submit("port_scan", {"nonexistent": 1})
    assert repo.rows == {}


@pytest.mark.asyncio
async def test_out_of_range_is_rejected_at_submit():
    repo = FakeRepo()
    svc = _service(repo)
    with pytest.raises(ProposalError):
        await svc.submit("port_scan", {"threshold": 99999})
    assert repo.rows == {}


@pytest.mark.asyncio
async def test_unknown_engine_is_rejected():
    repo = FakeRepo()
    svc = _service(repo)
    svc._registry.get_engine_schema.return_value = None
    with pytest.raises(ProposalError):
        await svc.submit("nope", {"threshold": 10})


@pytest.mark.asyncio
async def test_empty_params_rejected():
    repo = FakeRepo()
    svc = _service(repo)
    with pytest.raises(ProposalError):
        await svc.submit("port_scan", {})


# ------------------------------------------------------------------
# 2. 거절은 아무것도 바꾸지 않는다
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reject_applies_nothing():
    repo = FakeRepo()
    svc = _service(repo)
    pid = await svc.submit("port_scan", {"threshold": 80})

    decision = await svc.decide(pid, approved=False, decided_by="admin")

    assert decision.approved is False
    assert decision.applied is False
    assert decision.status == STATUS_REJECTED
    svc._registry.reload_engine.assert_not_called()
    svc._editor.update_engine_config.assert_not_called()
    assert repo.rows[pid]["status"] == STATUS_REJECTED


# ------------------------------------------------------------------
# 3. 승인은 검증된 경로로만 쓴다
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_approve_applies_through_validated_path():
    repo = FakeRepo()
    svc = _service(repo)
    pid = await svc.submit("port_scan", {"threshold": 80})

    decision = await svc.decide(pid, approved=True, decided_by="admin")

    assert decision.approved is True
    assert decision.applied is True
    assert decision.status == STATUS_APPROVED
    assert repo.rows[pid]["status"] == STATUS_APPROVED
    assert repo.rows[pid]["applied"] is True
    assert repo.rows[pid]["decided_by"] == "admin"

    # reload 이 먼저, YAML 기록은 그 다음 (대시보드 쓰기와 동일 순서)
    assert svc._registry.reload_engine.called
    merged = svc._registry.reload_engine.call_args[0][1]
    assert merged["threshold"] == 80
    assert merged["window_seconds"] == 60
    svc._editor.update_engine_config.assert_called_once_with(
        "port_scan", {"threshold": 80},
    )


@pytest.mark.asyncio
async def test_reload_failure_skips_yaml_write():
    repo = FakeRepo()
    svc = _service(repo, reload_result=(False, "boom", []))
    pid = await svc.submit("port_scan", {"threshold": 80})

    decision = await svc.decide(pid, approved=True, decided_by="admin")

    assert decision.approved is True
    assert decision.applied is False
    assert decision.error
    # 실패를 성공으로 위장하지 않는다
    assert repo.rows[pid]["status"] == STATUS_FAILED
    assert svc._registry.reload_engine.call_args.args == ("port_scan", CURRENT)
    assert repo.rows[pid]["apply_error"]
    svc._editor.update_engine_config.assert_not_called()


@pytest.mark.asyncio
async def test_yaml_write_failure_is_recorded_not_hidden():
    repo = FakeRepo()
    svc = _service(repo)
    svc._editor.update_engine_config.side_effect = OSError("disk full")
    pid = await svc.submit("port_scan", {"threshold": 80})

    decision = await svc.decide(pid, approved=True, decided_by="admin")

    assert decision.applied is False
    assert repo.rows[pid]["status"] == STATUS_FAILED


# ------------------------------------------------------------------
# 4. 승인 시점 재검증
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proposal_itself_is_revalidated_at_approval_time():
    """승인하려는 변경 자체가 스키마를 어기면 막는다."""
    repo = FakeRepo()
    svc = _service(repo)
    pid = await svc.submit("port_scan", {"threshold": 80})

    # 접수와 승인 사이에 제안을 변조했다 (큐 직접 조작에 해당)
    repo.rows[pid]["params"] = {"undeclared_key": 1}

    with pytest.raises(ProposalError):
        await svc.decide(pid, approved=True, decided_by="admin")

    svc._registry.reload_engine.assert_not_called()
    svc._editor.update_engine_config.assert_not_called()
    assert repo.rows[pid]["status"] == STATUS_REJECTED


@pytest.mark.asyncio
async def test_preexisting_drift_warns_but_does_not_block():
    """기존 설정의 방치된 키가 모든 승인을 막아서는 안 된다.

    실제로 이 버그가 있었다: config/default.yaml 에 스키마에 없는 키가 남아
    있으면 어떤 제안도 승인되지 않았다. 제안자는 자기 제안을 고칠 수 없었고,
    큐가 영구히 막혔다.
    """
    repo = FakeRepo()
    svc = _service(repo)
    pid = await svc.submit("port_scan", {"threshold": 80})

    # 접수 시점에 이미 있던 기존 설정 문제
    repo.rows[pid]["before"]["legacy_undeclared_key"] = 1
    repo.rows[pid]["before"].pop("window_seconds", None)  # 스키마 필드 누락

    decision = await svc.decide(pid, approved=True, decided_by="admin")

    assert decision.approved is True
    assert decision.applied is True
    # 막지는 않되 반드시 드러낸다
    assert decision.warnings, "기존 설정 문제가 경고로 드러나지 않았다"
    svc._editor.update_engine_config.assert_called_once()


# ------------------------------------------------------------------
# 5. 결정은 한 번만
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cannot_decide_twice():
    repo = FakeRepo()
    svc = _service(repo)
    pid = await svc.submit("port_scan", {"threshold": 80})
    await svc.decide(pid, approved=True, decided_by="admin")

    with pytest.raises(ProposalError):
        await svc.decide(pid, approved=True, decided_by="admin2")


@pytest.mark.asyncio
async def test_unknown_proposal_rejected():
    repo = FakeRepo()
    svc = _service(repo)
    with pytest.raises(ProposalError):
        await svc.decide(999, approved=True, decided_by="admin")


# ------------------------------------------------------------------
# 6. 조회
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pending_count_and_listing():
    repo = FakeRepo()
    svc = _service(repo)
    await svc.submit("port_scan", {"threshold": 80})
    await svc.submit("port_scan", {"threshold": 90})

    assert await svc.pending_count() == 2
    assert len(await svc.pending()) == 2

    pid = (await svc.pending())[0]["id"]
    await svc.decide(pid, approved=False, decided_by="admin")
    assert await svc.pending_count() == 1
