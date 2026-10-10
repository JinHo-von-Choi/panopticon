"""분리 콘솔 AI 분석: 지정 분석가 계정으로만 센서에 제안하고, 판정 경보는 사건으로 남긴다."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from netwatcher.services.console_ai import ConsoleAIAnalyzer
from netwatcher.services.sensor_control import SensorControlError

STATE = {"engine": {"name": "port_scan", "enabled": True, "config": {"threshold": 20},
                    "schema": [{"key": "threshold", "type": "int", "default": 15}]},
         "base_version": "a" * 64}


def decision(verdict, engine="port_scan", adjustments=None):
    return json.dumps({"version": 1, "verdict": verdict, "engine": engine, "reason": "r",
                       "reasoning": [], "adjustments": adjustments or {}, "evidence_event_ids": [1]})


def analyzer(account=None, read=None):
    config = MagicMock()
    config.section.return_value = {"enabled": True, "provider": "anthropic", "model": "m",
                                   "endpoint": "http://127.0.0.1:9", "api_key_env": "TEST_AI_KEY",
                                   "service_account": "ai-bot", "consecutive_fp_threshold": 1,
                                   "max_threshold_increase_pct": 20}
    config.get.return_value = "en"
    events = MagicMock()
    events.insert = AsyncMock()
    control = MagicMock()
    control.read = AsyncMock(return_value=STATE) if read is None else read
    control.proposals = AsyncMock(return_value={"proposal": {"id": 7}})
    accounts = MagicMock()
    accounts.get_by_username = AsyncMock(return_value=account if account is not None else
                                         {"id": "11111111-1111-1111-1111-111111111111", "username": "ai-bot",
                                          "role": "analyst", "enabled": True, "version": 3})
    svc = ConsoleAIAnalyzer(config, events, control, accounts)
    svc._fetch_recent_events = AsyncMock(return_value=[{"id": 1, "engine": "port_scan", "severity": "WARNING",
                                                        "title": "t", "source_ip": "1.1.1.1", "timestamp": "x"}])
    return svc, events, control


async def run(svc, text):
    svc._backend.complete = AsyncMock(return_value=text)
    svc._last_prompt_sha = None
    await svc._run_once()
    for task in list(svc._proposal_tasks):
        await task


@pytest.mark.asyncio
async def test_false_positive_becomes_capped_proposal_from_service_account():
    svc, events, control = analyzer()
    await run(svc, decision("FALSE_POSITIVE", adjustments={"threshold": 100}))
    args, kwargs = control.proposals.await_args
    assert args[0] == "proposal.submit"
    assert args[1]["uid"] == "11111111-1111-1111-1111-111111111111" and args[1]["ver"] == 3
    assert kwargs["base_version"] == "a" * 64
    assert kwargs["updates"]["params"] == {"threshold": 24}      # 현재 20의 20% 상한, 정수
    assert kwargs["updates"]["reason"].startswith("[AI anthropic]")


@pytest.mark.asyncio
async def test_confirmed_threat_is_written_as_event():
    svc, events, control = analyzer()
    await run(svc, decision("CONFIRMED_THREAT"))
    assert events.insert.await_args.kwargs["engine"] == "ai_analyzer"
    assert events.insert.await_args.kwargs["severity"] == "CRITICAL"
    control.proposals.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("account", [
    {"id": "1", "username": "ai-bot", "role": "viewer", "enabled": True, "version": 1},
    {"id": "1", "username": "ai-bot", "role": "analyst", "enabled": False, "version": 1},
])
async def test_unusable_account_stops_before_any_sensor_call(account):
    svc, events, control = analyzer(account=account)
    await run(svc, decision("FALSE_POSITIVE", adjustments={"threshold": 30}))
    control.read.assert_not_awaited()
    control.proposals.assert_not_awaited()
    assert svc._health["last_failure"] == "service_account"


@pytest.mark.asyncio
async def test_unknown_engine_records_verdict_without_proposal():
    svc, events, control = analyzer(read=AsyncMock(side_effect=SensorControlError("engine_not_found", 404)))
    await run(svc, decision("FALSE_POSITIVE", engine="made_up", adjustments={"threshold": 30}))
    control.proposals.assert_not_awaited()
    assert events.insert.await_count >= 1


def test_service_account_is_required():
    config = MagicMock()
    config.section.return_value = {"enabled": True, "provider": "claude"}
    with pytest.raises(ValueError):
        ConsoleAIAnalyzer(config, MagicMock(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_status_route_reports_console_analyzer_not_sensor():
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from netwatcher.web.routes.ai_analyzer import create_ai_analyzer_router
    svc, _, _ = analyzer()
    sensor = MagicMock()
    sensor.ai_status = AsyncMock(side_effect=AssertionError("sensor must not be asked"))
    app = FastAPI()
    app.include_router(create_ai_analyzer_router(svc, sensor_control=sensor), prefix="/api")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = (await client.get("/api/ai-analyzer/status")).json()
    assert body["provider"] == "anthropic" and body["credential"] in {"configured", "missing"}
