"""노예(canary) 검증 — 실경로 종단간 테스트.

이전까지의 검증은 모두 컴포넌트 단위였다. 모킹된 저장소, 직접 만든 패킷,
라우터를 거치지 않은 호출. 계획서의 수락 순서는
**게이트 → 노예 → 운영** 인데, 노예 단계가 비어 있었다.

이 테스트는 모킹을 쓰지 않는다.

- **실제 PostgreSQL** (테스트 스키마)
- **실제 엔진** (EngineRegistry 가 발견한 것)
- **실제 AlertDispatcher** (큐 + 소비 루프)
- **실제 HTTP 라우터** (TestClient, JWT 역할 검증 포함)
- **실제 EventRepository / ConfigProposalRepository**

검증하는 두 가지

1. **첫 탐지 결과가 감사 가능하다** — 포트 스캔을 실제로 흘려 알림이 DB 에
   저장되고, 그 행이 증거 봉투 세 층을 갖는지 확인한다 (계획서 G8)
2. **승인 루프가 실경로에서 동작한다** — AI 제안이 큐에 들어가고, 사람이
   승인하면 YAML 과 런타임에 반영되는지 확인한다
3. **관측 범위가 실제로 채워진다** — 계측 지점(key)이 존재하는 것과 실제
   계수값이 생기는 것은 다르다. 실경로에서 숫자가 생기는지 확인한다

이 경로가 깨지면 대시보드가 보여주는 것은 거짓말이 된다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from scapy.all import IP, TCP, Ether

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.evidence import LAYER_EVIDENCE, LAYER_RAW
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.proposals import (
    SOURCE_AI,
    STATUS_APPROVED,
    ProposalService,
)
from netwatcher.detection.registry import EngineRegistry
from netwatcher.observability.observation import ObservationService
from netwatcher.storage.repositories import ConfigProposalRepository, EventRepository
from netwatcher.utils.packet_info import extract_packet_info
from netwatcher.web.auth import AuthManager
from netwatcher.web.routes.events import _with_evidence
from netwatcher.web.routes.proposals import create_proposals_router
from netwatcher.web.rbac import Role

import httpx
from fastapi import FastAPI

SECRET = "canary-secret"


# ------------------------------------------------------------------
# 1. 첫 탐지 결과가 감사 가능해야 한다 (G8)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_real_detection_reaches_db_with_evidence(config, event_repo, db):
    """실제 엔진 + 실제 디스패처로 포트 스캔을 탐지하고 DB 행을 확인한다."""
    registry = EngineRegistry(config)
    registry.discover_and_register()
    assert registry.get_all_engine_info(), "엔진이 하나도 등록되지 않았다"

    dispatcher = AlertDispatcher(
        config=config, event_repo=event_repo, correlator=None,
    )
    await dispatcher.start()
    try:
        # 실제 탐지 조건을 만족시키는 SYN 버스트
        scanned = 0
        for port in range(1, 61):
            pkt = Ether() / IP(src="8.8.8.8", dst="10.0.0.2") / TCP(
                sport=54321, dport=port, flags="S",
            )
            for alert in registry.process_packet(pkt):
                # 파이프라인이 하는 일을 그대로 수행한다
                alert.packet_info = extract_packet_info(pkt)
                alert.metadata["confidence"] = alert.confidence
                dispatcher.enqueue(alert)
                scanned += 1
            if scanned:
                break

        # 엔진 tick 으로 시간창 기반 엔진(port_scan 등)을 확정한다
        for _ in range(3):
            for alert in registry.tick():
                alert.packet_info = alert.packet_info or {}
                dispatcher.enqueue(alert)
                scanned += 1

        assert scanned, "실제 탐지가 하나도 발생하지 않았다 — 테스트 전제 자체가 깨졌다"

        # 종료 시 배 emptiness (PR 06) — 경로 전체를 통과시킨다
        await dispatcher.stop(drain_timeout=5.0)
    finally:
        await dispatcher.stop(drain_timeout=1.0)

    rows = await event_repo.list_recent(limit=20)
    assert rows, "탐지 결과가 DB 에 저장되지 않았다"

    row = rows[0]
    # 저장된 행에서 봉투를 재판정한다 (PR 09)
    evidence = _with_evidence(row)["evidence"]

    assert evidence["layers"]["summary"] is True
    assert evidence["layers"]["evidence"] is True, (
        f"근거 층이 비었다: {evidence}"
    )
    assert evidence["layers"]["raw"] is True, (
        f"원자료 층이 비었다: {evidence}"
    )
    assert evidence["status"] == "complete", evidence
    assert LAYER_EVIDENCE not in evidence["missing"]
    assert LAYER_RAW not in evidence["missing"]

    # 감사 가능한 탐지에는 식별자와 시각이 있어야 한다
    assert row["id"] is not None
    assert row["timestamp"] is not None
    assert row["engine"]


@pytest.mark.asyncio
async def test_detection_survives_dispatcher_shutdown(config, event_repo):
    """종료 경로에서 탐지 결과가 사라지지 않아야 한다 (PR 06)."""
    dispatcher = AlertDispatcher(
        config=config, event_repo=event_repo, correlator=None,
    )
    await dispatcher.start()
    for i in range(10):
        dispatcher.enqueue(Alert(
            engine="port_scan", severity=Severity.WARNING,
            title=f"synthetic-{i}", description="d", source_ip="10.0.0.1",
            metadata={"count": i}, packet_info={"layers": ["IP"], "length": 74},
        ))
    await dispatcher.stop(drain_timeout=5.0)

    rows = await event_repo.list_recent(limit=20)
    titles = {r["title"] for r in rows}
    assert sum(1 for t in titles if t.startswith("synthetic-")) == 10, (
        f"종료 시 큐의 알림이 유실됐다: {sorted(titles)}"
    )


# ------------------------------------------------------------------
# 2. 승인 루프가 실경로에서 동작한다 (PR 10)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proposal_reaches_db_and_is_approved(config, db, event_repo):
    """실제 config_proposals 테이블과 실제 HTTP 라우터를 거친 승인 흐름."""
    from netwatcher.utils.yaml_editor import YamlConfigEditor

    repo = ConfigProposalRepository(db)
    registry = EngineRegistry(config)
    registry.discover_and_register()

    import tempfile
    from pathlib import Path
    # 실제 YAML 편집기를 임시 설정 파일에 붙인다
    tmp = Path(tempfile.mkdtemp())
    yaml_path = tmp / "config.yaml"
    yaml_path.write_text(
        "netwatcher:\n"
        "  engines:\n"
        "    port_scan:\n"
        "      enabled: true\n"
        "      window_seconds: 60\n"
        "      threshold: 50\n"
        "      cooldown_seconds: 300\n",
        encoding="utf-8",
    )
    editor = YamlConfigEditor(str(yaml_path))

    service = ProposalService(
        registry=registry, yaml_editor=editor, proposal_repo=repo,
    )

    # 2-1. AI 제안이 실제 테이블에 들어간다
    proposal_id = await service.submit(
        engine="port_scan",
        params={"threshold": 80},
        reason="연속 오탐 — 노예 검증",
        source=SOURCE_AI,
    )
    stored = await repo.get_by_id(proposal_id)
    assert stored is not None, "제안이 DB 에 저장되지 않았다"
    assert stored["status"] == "pending"
    assert stored["source"] == "ai"
    assert stored["params"]["threshold"] == 80
    # 되돌리기 근거가 실제로 기록돼야 한다
    assert stored["before"] is not None
    assert stored["before"]["threshold"] == 50

    # 2-2. 제안만으로는 아무것도 바뀌지 않는다
    assert editor.get_engine_config("port_scan")["threshold"] == 50, (
        "제안만으로 설정이 변경됐다 — 승인이 유일한 쓰기 경로여야 한다"
    )

    # 2-3. HTTP 경계를 통해 승인한다 (역할 검증 포함)
    #
    # TestClient 를 쓰면 안 된다. TestClient 은 앱을 별도의 이벤트 루프에서
    # 실행하는데 asyncpg 커넥션은 루프에 묶여 있어
    # "another operation is in progress" 로 실패한다. 같은 루프의
    # ASGITransport 로 실제 HTTP 경로를 통과시킨다.
    app = FastAPI()
    app.include_router(create_proposals_router(service), prefix="/api")
    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = SECRET
    manager._expire_hours = 1
    app.state.auth_manager = manager

    now = datetime.now(timezone.utc)

    def _tok(role: Role) -> str:
        return jwt.encode(
            {"sub": "canary", "role": role.value, "iat": now,
             "exp": now + timedelta(hours=1)},
            SECRET, algorithm="HS256",
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # analyst 는 승인할 수 없다
        forbidden = await client.post(
            f"/api/proposals/{proposal_id}/approve",
            json={"decided_by": "analyst"},
            headers={"Authorization": f"Bearer {_tok(Role.ANALYST)}"},
        )
        assert forbidden.status_code == 403
        assert editor.get_engine_config("port_scan")["threshold"] == 50

        # admin 은 승인할 수 있고 실제로 반영된다
        approved = await client.post(
            f"/api/proposals/{proposal_id}/approve",
            json={"decided_by": "admin", "note": "노예 검증 승인"},
            headers={"Authorization": f"Bearer {_tok(Role.ADMIN)}"},
        )
        assert approved.status_code == 200, approved.text
        body = approved.json()

    assert body["status"] == STATUS_APPROVED
    assert body["applied"] is True, body

    # 2-4. 설정이 실제로 반영되고 감사 흔적이 남는다
    assert editor.get_engine_config("port_scan")["threshold"] == 80
    after = await repo.get_by_id(proposal_id)
    assert after["status"] == "approved"
    assert after["applied"] is True
    assert after["decided_by"] == "admin"
    assert after["decided_at"] is not None

    # 2-5. YAML 파일에도 남는다 (재시작 후에도 유지)
    assert "threshold: 80" in yaml_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_invalid_proposal_never_reaches_db(config, db):
    """스키마를 어기는 제안은 실제 테이블에 들어가지 않는다."""
    from netwatcher.utils.yaml_editor import YamlConfigEditor
    import tempfile
    from pathlib import Path
    from netwatcher.detection.proposals import ProposalError

    repo = ConfigProposalRepository(db)
    registry = EngineRegistry(config)
    registry.discover_and_register()

    tmp = Path(tempfile.mkdtemp())
    yaml_path = tmp / "config.yaml"
    yaml_path.write_text(
        "netwatcher:\n  engines:\n    port_scan:\n      enabled: true\n",
        encoding="utf-8",
    )
    editor = YamlConfigEditor(str(yaml_path))
    service = ProposalService(
        registry=registry, yaml_editor=editor, proposal_repo=repo,
    )

    before = await repo.count_pending()

    with pytest.raises(ProposalError):
        await service.submit("port_scan", {"undeclared_key": 1})
    with pytest.raises(ProposalError):
        await service.submit("port_scan", {"threshold": True})

    assert await repo.count_pending() == before, \
        "스키마를 어기는 제안이 큐에 들어갔다"


# ------------------------------------------------------------------
# 3. 관측 범위가 실경로에서 채워지는가 (G2)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_observation_records_real_pipeline(config, event_repo):
    """실제 경로를 통과한 탐지가 관측 창에 **숫자로** 남는지 확인한다.

    배선만 있고 값이 0 이면 "관측됨" 이라는 판정은 아무것도 보지 않은 통과다.
    그래서 이 테스트는 키의 존재가 아니라 실제 계수값을 본다.
    """
    observation = ObservationService(sensor_id="canary")
    observation.mark_heartbeat()

    registry = EngineRegistry(config)
    registry.discover_and_register()

    dispatcher = AlertDispatcher(
        config=config, event_repo=event_repo, correlator=None,
        observation=observation,
    )
    await dispatcher.start()
    try:
        for port in range(1, 61):
            pkt = Ether() / IP(src="8.8.8.8", dst="10.0.0.2") / TCP(
                sport=54321, dport=port, flags="S",
            )
            for alert in registry.process_packet(pkt):
                alert.packet_info = extract_packet_info(pkt)
                alert.metadata["confidence"] = alert.confidence
                dispatcher.enqueue(alert)
        for alert in registry.tick():
            alert.packet_info = alert.packet_info or {}
            dispatcher.enqueue(alert)

        await dispatcher.stop(drain_timeout=5.0)
    finally:
        await dispatcher.stop(drain_timeout=1.0)

    snap = observation.snapshot()

    # 실제 경로의 계측값이 채워져야 한다
    assert snap["stages"]["result_queue"]["received"] > 0, (
        "알림이 큐를 지났는데 result_queue 가 0 이다 — 계측 지점이 없다"
    )
    assert snap["stages"]["db"]["accepted"] > 0, (
        "DB 저장이 성공했는데 db 단계 계측이 없다"
    )
    assert snap["last_durable_event_at"] is not None, (
        "영속 이벤트가 기록되었는데 관측 창에 남지 않았다"
    )
    assert snap["state"] == "observed", snap["reasons"]
    assert snap["reasons"], "근거 없는 상태"

    # 커널 drop 은 앱 손실률에 섞이지 않는다
    for name, entry in snap["loss"]["per_stage"].items():
        assert "app_loss_ratio" in entry
        if entry["kernel_dropped"] > 0:
            assert "kernel_loss_note" in entry, f"{name}: 합산 방지가 없다"

    # 링크 손실은 숫자를 만들지 않는다
    assert snap["loss"]["link_loss"]["value"] is None
    assert snap["loss"]["link_loss"]["status"] == "unknown"


# ------------------------------------------------------------------
# 4. 조치 생애주기 — 실경로에서 "적용됨" 을 주장하지 않는가 (G7)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_response_lifecycle_never_claims_enforcement(config, db):
    """승인→적용 경로가 실제로 돌아가면서도 '적용됐다' 고 말하지 않는다.

    계획서: "검증된 만료 백엔드·권한 분리·적용 경로 증명이 하나라도 없으면
    shadow/제안만 출시한다." 그래서 이 테스트의 기대값은 **성공이 아니다.**

    이 배포에 OS 를 건드리는 백엔드가 없다는 것을 실경로에서 확인한다.
    """
    from netwatcher.response.executor import ShadowExecutor, executor_capabilities
    from netwatcher.storage.repositories import ResponseActionRepository
    from netwatcher.web.routes.response import create_response_router

    app = FastAPI()
    service = ShadowExecutor()
    app.include_router(
        create_response_router(ResponseActionRepository(db), service),
        prefix="/api",
    )
    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = SECRET
    manager._expire_hours = 1
    app.state.auth_manager = manager

    now = datetime.now(timezone.utc)

    def _tok(role: Role) -> str:
        return jwt.encode(
            {"sub": "canary", "role": role.value, "iat": now,
             "exp": now + timedelta(hours=1)},
            SECRET, algorithm="HS256",
        )

    # 매핑 확인 시각이 없으면 실행 단계가 거부해야 한다 (계획서 4장)
    unmapped = {
        "target": "8.8.8.8", "direction": "input", "ttl_seconds": 300,
        "scope": {"asset": "srv-1"}, "base_version": "v1",
    }
    body = {**unmapped, "mapping_confirmed_at": now.isoformat()}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        caps = (await client.get(
            "/api/response/capabilities",
            headers={"Authorization": f"Bearer {_tok(Role.VIEWER)}"},
        )).json()
        assert caps["applies_to_os"] is False, "OS 를 건드리지 않는다고 선언해야 한다"
        assert caps["auto_block_enabled"] is False
        assert caps["kernel_expiry_verified"] is False

        # 매핑 미확인 → 실행 거부 (제안은 되지만 실행은 안 된다)
        unmapped_action = (await client.post(
            "/api/change-proposals/1/approve", json=unmapped,
            headers={"Authorization": f"Bearer {_tok(Role.ADMIN)}"},
        )).json()
        blocked = await client.post(
            f"/api/response-actions/{unmapped_action['action_id']}/activate",
            json=unmapped, headers={"Authorization": f"Bearer {_tok(Role.ADMIN)}"},
        )
        assert blocked.status_code == 409, "캐시된 매핑으로 실행을 허용했다"

        approved = (await client.post(
            "/api/change-proposals/1/approve", json=body,
            headers={"Authorization": f"Bearer {_tok(Role.ADMIN)}"},
        )).json()
        action_id = approved["action_id"]

        activated = await client.post(
            f"/api/response-actions/{action_id}/activate", json=body,
            headers={"Authorization": f"Bearer {_tok(Role.ADMIN)}"},
        )
        result = activated.json()
        assert result["verified"] is False, "shadow 적용을 확인됨으로 표시했다"
        assert result["state"] != "active_verified"

        # 승인과 적용이 분리되어 있다 — 승인만으로는 아무 변화가 없다
        stale = await client.post(
            f"/api/response-actions/{action_id}/activate",
            json={**body, "scope": {"asset": "srv-2"}},
            headers={"Authorization": f"Bearer {_tok(Role.ADMIN)}"},
        )
        assert stale.status_code == 409

    # OS 를 건드리지 않았음이 의도 기록으로 남는다
    assert service.intents and service.intents[0].target == "8.8.8.8"
