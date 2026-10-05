"""관측 범위 API 테스트 (PR 11 / 계획서 3장).

이 API 가 대시보드에 주는 값은 "관측 범위" 다. 다음을 고정한다.

- 상태는 언제나 이유를 동반한다 (판정 없는 상태를 노출하지 않는다)
- 조회 실패를 "관측 이상 없음" 으로 바꾸지 않는다
- 링크 손실은 측정 불가라는 사실이 응답에 남는다
- 읽기 전용이다 — 승인 권한 없이도, 그리고 그것만으로 상태가 바뀌지 않는다
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.observability.observation import (
    DROP_SOURCE_APP,
    DROP_SOURCE_KERNEL,
    KIND_DROPPED,
    KIND_RECEIVED,
    STAGE_CAPTURE,
    STAGE_INPUT_QUEUE,
    STATE_OBSERVED,
    STATE_STALE,
    ObservationService,
)
from netwatcher.web.routes.observation import create_observation_router


def _app(observation: ObservationService) -> FastAPI:
    app = FastAPI()
    app.include_router(create_observation_router(observation), prefix="/api")
    return app


def _client(observation: ObservationService) -> TestClient:
    return TestClient(_app(observation))


# ------------------------------------------------------------------
# 기본 계약
# ------------------------------------------------------------------

def test_state_always_has_reasons():
    """판정 없이 상태만 내놓지 않는다."""
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()

    body = _client(obs).get("/api/observation").json()

    assert body["state"] in {"observed", "partial", "stale", "unknown"}
    assert body["reasons"], "이유 없는 상태를 노출했다"


def test_fresh_sensor_reports_observed():
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()
    obs.record(STAGE_CAPTURE, KIND_RECEIVED, 100)

    body = _client(obs).get("/api/observation").json()

    assert body["state"] == STATE_OBSERVED
    assert body["sensor_id"] == "s"
    assert body["observed_traffic"] == 100
    assert body["no_traffic_observed"] is False


def test_dead_heartbeat_reports_stale():
    """센서가 살아 있는지 확인되지 않으면 stale — 경보 부재의 근거로 못 쓴다."""
    obs = ObservationService(sensor_id="s", heartbeat_seconds=10.0)
    obs._window.last_heartbeat_at = time.time() - 60

    body = _client(obs).get("/api/observation").json()

    assert body["state"] == STATE_STALE
    assert "확인되지 않는다" in body["interpretation"]["message"]


def test_zero_traffic_is_not_declared_outage():
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()

    body = _client(obs).get("/api/observation").json()

    assert body["no_traffic_observed"] is True
    assert body["state"] == STATE_OBSERVED
    assert any("장애를 선언하지 않는다" in c for c in body["interpretation"]["cautions"])


# ------------------------------------------------------------------
# 손실 표시
# ------------------------------------------------------------------

def test_loss_does_not_merge_kernel_and_app_drops():
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()
    obs.record(STAGE_CAPTURE, KIND_RECEIVED, 1000)
    obs.record(STAGE_CAPTURE, KIND_DROPPED, 400, drop_source=DROP_SOURCE_KERNEL)
    obs.record(STAGE_CAPTURE, KIND_DROPPED, 10, drop_source=DROP_SOURCE_APP)

    entry = _client(obs).get("/api/observation").json()["loss"]["per_stage"][STAGE_CAPTURE]

    assert entry["kernel_dropped"] == 400
    assert entry["app_dropped"] == 10
    assert entry["app_loss_ratio"] == pytest.approx(0.01)


def test_link_loss_remains_unknown_in_response():
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()

    body = _client(obs).get("/api/observation").json()

    assert body["loss"]["link_loss"]["value"] is None
    assert body["loss"]["link_loss"]["status"] == "unknown"
    assert any("링크" in c or "NIC" in c for c in body["interpretation"]["cautions"])


def test_unsupported_measurements_are_listed():
    obs = ObservationService(sensor_id="s")
    body = _client(obs).get("/api/observation").json()

    assert "nic_drop" in body["unsupported_measurements"]


def test_queue_saturation_downgrades_to_partial():
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()
    obs.record(STAGE_INPUT_QUEUE, KIND_RECEIVED, 200)
    obs.record(STAGE_INPUT_QUEUE, KIND_DROPPED, 50, drop_source=DROP_SOURCE_APP)

    body = _client(obs).get("/api/observation").json()

    assert body["state"] == "partial"
    assert "온전하지 않다" in body["interpretation"]["message"]


# ------------------------------------------------------------------
# 읽기 전용 / 결측 표시
# ------------------------------------------------------------------

def test_reading_does_not_change_state():
    """관측 상태를 조회하는 행위가 상태를 바꾸면 안 된다."""
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()
    obs.record(STAGE_CAPTURE, KIND_RECEIVED, 10)

    client = _client(obs)
    first = client.get("/api/observation").json()
    second = client.get("/api/observation").json()

    assert first["stages"] == second["stages"]
    assert first["state"] == second["state"]


def test_kernel_probe_is_reported_even_when_unavailable():
    """커널 drop 측정기가 없을 때도 조용히 사라지지 않고 사유를 말한다."""
    obs = ObservationService(sensor_id="s")
    app = FastAPI()
    app.include_router(create_observation_router(obs, kernel_probe=None), prefix="/api")

    body = TestClient(app).get("/api/observation").json()

    assert body["kernel_drop_source"]["available"] is False
    assert "연결되지" in body["kernel_drop_source"]["reason"]


def test_state_without_judgement_falls_back_to_unknown():
    """근거가 사라진 상태(빈 reasons)는 unknown 으로 낮춘다.

    서비스 계약을 우회한 값이 들어와도 "관측됨" 으로 표시되지 않는다.
    """
    obs = ObservationService(sensor_id="s")
    obs.mark_heartbeat()
    # 계약을 깨고 직접 빈 상태를 만든다
    obs.snapshot = lambda *a, **k: {  # type: ignore[method-assign]
        "sensor_id": "s", "state": "observed", "reasons": [], "stages": {},
        "loss": {}, "observed_traffic": 5, "no_traffic_observed": False,
        "unsupported_measurements": [],
    }

    body = _client(obs).get("/api/observation").json()

    assert body["state"] == "unknown"
    assert body["reasons"]
