"""인시던트 식별자 계약 (PR 05).

설계 원칙: **인시던트 식별자는 DB 가 부여한다.**

인메모리 카운터로 id 를 만들면 다음 일이 실제로 일어난다.

1. 프로세스가 재시작되면 카운터가 다시 1부터 시작한다
2. 대시보드(저장소 조회)가 보여주는 id 와 상관분석기의 인메모리 id 가 어긋난다
3. ``UPDATE incidents SET ... WHERE id = $1`` 이 과거 인시던트를 덮어쓴다
4. ``POST /api/incidents/{id}/resolve`` 가 엉뚱한 인시던트를 해결 처리한다

이 테스트는 그 경로가 열리지 않는지 고정한다.
"""

from __future__ import annotations

import asyncio

import pytest

from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.models import Alert, Severity


class FakeIncidentRepo:
    """실제 DB 와 동일하게 id 를 부여하는 저장소 대역."""

    def __init__(self, first_id: int = 1000) -> None:
        self._next = first_id
        self.inserted: list[dict] = []
        self.updates: list[tuple[int, dict]] = []
        self.resolved: list[int] = []

    async def insert(self, **fields) -> int:
        row_id = self._next
        self._next += 1
        self.inserted.append({**fields, "_id": row_id})
        return row_id

    async def update(self, incident_id: int, **fields) -> None:
        self.updates.append((incident_id, dict(fields)))

    async def resolve(self, incident_id: int) -> bool:
        self.resolved.append(incident_id)
        return True


def _alert(engine: str, source: str = "10.0.0.5") -> Alert:
    return Alert(
        engine=engine,
        severity=Severity.WARNING,
        title=f"{engine} alert",
        description="d",
        source_ip=source,
    )


def _correlator(repo=None) -> AlertCorrelator:
    c = AlertCorrelator(time_window=300, burst_threshold=3, burst_window=60)
    if repo is not None:
        c.set_incident_repo(repo)
    return c


def _correlate(c: AlertCorrelator) -> "object":
    """두 엔진 알림으로 인시던트를 만든다."""
    c.process_alert(_alert("port_scan"), event_id=1)
    return c.process_alert(_alert("lateral_movement"), event_id=2)


# ------------------------------------------------------------------
# 핵심 계약
# ------------------------------------------------------------------

def test_new_incident_has_no_id_until_persisted():
    """생성 시점에는 id 가 없다 — DB 가 줄 때까지 None."""
    c = _correlator(FakeIncidentRepo())
    incident = _correlate(c)
    assert incident is not None
    assert incident.id is None
    assert incident.to_dict()["persisted"] is False


def test_persist_assigns_database_id():
    repo = FakeIncidentRepo(first_id=4242)
    c = _correlator(repo)
    incident = _correlate(c)

    asyncio.run(c.persist(incident))

    assert incident.id == 4242
    assert incident.to_dict()["persisted"] is True


def test_async_process_alert_returns_persisted_incident():
    """디스패처가 쓰는 경로: 반환 시점에 이미 id 를 갖고 있어야 한다."""
    repo = FakeIncidentRepo(first_id=77)
    c = _correlator(repo)

    async def run() -> object:
        return await c.async_process_alert(_alert("port_scan"), event_id=1) or \
            await c.async_process_alert(_alert("lateral_movement"), event_id=2)

    # 첫 알림은 단일 이벤트라 인시던트를 만들지 않을 수 있다 → 두 번 호출
    first = asyncio.run(c.async_process_alert(_alert("port_scan"), event_id=1))
    if first is None:
        incident = asyncio.run(c.async_process_alert(_alert("lateral_movement"), event_id=2))
    else:
        incident = first

    assert incident is not None
    assert incident.id == 77
    assert incident.to_dict()["persisted"] is True


def test_persist_is_idempotent():
    """두 번 호출해도 행이 두 개 생기지 않는다."""
    repo = FakeIncidentRepo()
    c = _correlator(repo)
    incident = _correlate(c)

    async def run():
        await c.persist(incident)
        first_id = incident.id
        await c.persist(incident)
        return first_id

    first_id = asyncio.run(run())
    assert incident.id == first_id
    assert len(repo.inserted) == 1


def test_update_targets_database_id():
    """업데이트는 인메모리 카운터가 아니라 DB id 로 전송된다."""
    repo = FakeIncidentRepo(first_id=555)
    c = _correlator(repo)
    incident = _correlate(c)
    asyncio.run(c.persist(incident))

    # 추가 알림 → 기존 인시던트 갱신 경로
    c.process_alert(_alert("icmp_anomaly"), event_id=3)
    asyncio.run(c.persist(incident))

    assert repo.updates, "갱신이 발생해야 한다"
    for target_id, _fields in repo.updates:
        assert target_id == 555


def test_resolve_targets_database_id():
    repo = FakeIncidentRepo(first_id=888)
    c = _correlator(repo)
    incident = _correlate(c)

    async def run() -> bool:
        await c.persist(incident)
        # resolve_incident 는 DB 반영을 fire-and-forget 으로 예약하므로
        # 실행 중인 이벤트 루프가 있어야 한다 (라우트는 별도로 await 한다).
        ok = c.resolve_incident(888)
        await asyncio.sleep(0)
        return ok

    assert asyncio.run(run()) is True
    assert repo.resolved == [888]


# ------------------------------------------------------------------
# 재시작 후 충돌 방지
# ------------------------------------------------------------------

def test_no_in_memory_counter_survives_restart():
    """재시작 후에도 id 는 DB 에서 나온다 — 카운터가 새 id 를 만들지 않는다."""
    repo_a = FakeIncidentRepo(first_id=1)
    first = _correlator(repo_a)
    inc_a = _correlate(first)
    asyncio.run(first.persist(inc_a))
    assert inc_a.id == 1

    # "재시작": 새 상관분석기 + 같은 DB (시퀀스는 계속 증가)
    repo_b = FakeIncidentRepo(first_id=2)   # DB 가 이미 1 을 사용했다
    second = _correlator(repo_b)
    inc_b = _correlate(second)
    asyncio.run(second.persist(inc_b))

    assert inc_b.id == 2, "새 인시던트가 1 번을 다시 쓰면 안 된다"
    assert inc_b.id != inc_a.id


def test_unpersisted_incident_is_not_addressable():
    """미영속 인시던트는 id 로 조회/해제되지 않는다."""
    c = _correlator()
    incident = _correlate(c)
    assert incident.id is None
    assert c.get_incident(None) is None
    assert c.resolve_incident(None) is False


def test_resolve_unknown_id_returns_false():
    c = _correlator(FakeIncidentRepo())
    incident = _correlate(c)
    asyncio.run(c.persist(incident))
    assert c.resolve_incident(999_999) is False


# ------------------------------------------------------------------
# 저장소 장애
# ------------------------------------------------------------------

def test_insert_failure_leaves_id_none_and_does_not_raise():
    """삽입이 실패해도 예외가 전파되지 않고, id 는 없는 채로 남는다."""
    class BrokenRepo:
        async def insert(self, **fields):
            raise RuntimeError("db down")

    c = _correlator(BrokenRepo())
    incident = _correlate(c)
    asyncio.run(c.persist(incident))
    assert incident.id is None


def test_no_repo_keeps_incident_usable():
    """저장소가 없는 구성에서도 상관분석 자체는 동작한다."""
    c = _correlator()
    incident = _correlate(c)
    assert incident is not None
    assert len(c.get_incidents()) >= 1


# ------------------------------------------------------------------
# 직렬화 형태
# ------------------------------------------------------------------

def test_to_dict_exposes_persisted_flag():
    c = _correlator(FakeIncidentRepo())
    incident = _correlate(c)
    payload = incident.to_dict()
    assert payload["persisted"] is False
    assert payload["id"] is None

    asyncio.run(c.persist(incident))
    payload = incident.to_dict()
    assert payload["persisted"] is True
    assert payload["id"] == 1000


def test_correlator_has_no_next_id_counter():
    """인메모리 id 카운터가 코드에 남아 있지 않아야 한다."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "netwatcher" / "detection" / "correlator.py"
    text = src.read_text(encoding="utf-8")
    assert "_next_id" not in text
