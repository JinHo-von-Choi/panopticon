"""AI 공급자: 모의 HTTP 서버로 실패 종류와 결과 계약을 확인한다."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp import web

from netwatcher.ai.providers import HttpProvider, ProviderError, build_provider, parse_decision
from netwatcher.services.ai_analyzer import AIAnalyzerService

DECISION = {"version": 1, "verdict": "FALSE_POSITIVE", "engine": "port_scan", "reason": "printer sweep",
            "reasoning": ["same printer every hour"], "adjustments": {"threshold": 30},
            "evidence_event_ids": [11, 999]}


@pytest_asyncio.fixture
async def server():
    state = {"mode": "ok", "requests": []}

    async def handle(request):
        state["requests"].append({"path": request.path, "headers": dict(request.headers), "body": await request.json()})
        mode = state["mode"]
        if mode == "slow":
            await asyncio.sleep(2)
        if mode in ("401", "429", "500"):
            return web.json_response({"error": mode}, status=int(mode))
        if mode == "not_json":
            return web.Response(text="<html>")
        text = json.dumps(DECISION) if mode == "ok" else "I think it is fine."
        if request.path.endswith("/v1/messages"):
            return web.json_response({"content": [{"type": "text", "text": text}]})
        return web.json_response({"choices": [{"message": {"content": text}}]})

    app = web.Application()
    app.router.add_post("/v1/messages", handle)
    app.router.add_post("/v1/chat/completions", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", state
    await runner.cleanup()


def provider(kind, endpoint, timeout=5):
    path = endpoint if kind == "anthropic" else endpoint + "/v1"
    return HttpProvider(kind, model="test-model", endpoint=path, api_key_env="TEST_AI_KEY", timeout=timeout)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["anthropic", "openai_compatible"])
async def test_success_sends_key_in_header_and_returns_text(server, kind, monkeypatch):
    endpoint, state = server
    monkeypatch.setenv("TEST_AI_KEY", "secret-value")
    text = await provider(kind, endpoint).complete("prompt")
    assert parse_decision(text).verdict == "FALSE_POSITIVE"
    headers = {key.lower(): value for key, value in state["requests"][0]["headers"].items()}
    assert "secret-value" in (headers.get("x-api-key", "") + headers.get("authorization", ""))
    assert "secret-value" not in json.dumps(state["requests"][0]["body"])


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,kind", [("401", "auth"), ("429", "rate_limited"), ("500", "http_status"),
                                       ("not_json", "invalid_output"), ("slow", "timeout")])
async def test_failures_are_classified(server, mode, kind, monkeypatch):
    endpoint, state = server
    monkeypatch.setenv("TEST_AI_KEY", "k")
    state["mode"] = mode
    with pytest.raises(ProviderError) as error:
        await provider("anthropic", endpoint, timeout=0.5).complete("prompt")
    assert error.value.kind == kind


@pytest.mark.asyncio
async def test_missing_key_never_calls_the_provider(server, monkeypatch):
    endpoint, state = server
    monkeypatch.delenv("TEST_AI_KEY", raising=False)
    with pytest.raises(ProviderError) as error:
        await provider("anthropic", endpoint).complete("prompt")
    assert error.value.kind == "credential_missing" and state["requests"] == []


def test_decision_schema_is_strict_and_drops_unknown_evidence():
    result = parse_decision("```json\n" + json.dumps(DECISION) + "\n```", known_event_ids=[11, 12])
    assert result.evidence_event_ids == [11] and result.adjustments == {"threshold": 30.0}
    for change in ({"verdict": "BLOCK_NOW"}, {"version": 2}, {"extra": 1}, {"adjustments": {"x": float("nan")}},
                   {"engine": "Port Scan; rm"}, {"evidence_event_ids": ["11"]}):
        with pytest.raises(ProviderError):
            parse_decision(json.dumps({**DECISION, **change}).replace("NaN", "NaN"))
    with pytest.raises(ProviderError):
        parse_decision("FALSE_POSITIVE because reasons")


@pytest.mark.parametrize("config", [
    {"provider": "unknown"}, {"provider": "anthropic"},
    {"provider": "openai_compatible", "model": "m", "endpoint": "http://203.0.113.5/v1"},
    {"provider": "anthropic", "model": "m", "endpoint": "https://user:pw@example.com"},
    {"provider": "anthropic", "model": "m", "api_key_env": "lower-case"},
])
def test_invalid_provider_configuration_is_rejected(config):
    with pytest.raises(ValueError):
        build_provider(config, 5)


def _service(**overrides):
    config = MagicMock()
    config.section.return_value = {"provider": "anthropic", "model": "m", "endpoint": "http://127.0.0.1:9",
                                   "api_key_env": "TEST_AI_KEY", **overrides}
    config.get.return_value = "en"
    event_repo = MagicMock()
    event_repo.insert = AsyncMock()
    return AIAnalyzerService(config=config, event_repo=event_repo, registry=MagicMock(),
                             dispatcher=MagicMock(), yaml_editor=None)


EVENTS = [{"id": 11, "engine": "port_scan", "severity": "WARNING", "title": "scan", "source_ip": "192.168.0.7",
           "timestamp": "2026-10-10T00:00:00Z"},
          {"id": 12, "engine": "port_scan", "severity": "WARNING", "title": "scan", "source_ip": "1.1.1.1",
           "timestamp": "2026-10-10T00:01:00Z"}]


@pytest.mark.asyncio
async def test_same_input_is_not_sent_twice_and_hashes_replace_raw_text():
    svc = _service()
    svc._fetch_recent_events = AsyncMock(return_value=EVENTS)
    svc._backend.complete = AsyncMock(return_value=json.dumps(DECISION))
    await svc._run_once()
    await svc._run_once()
    assert svc._backend.complete.await_count == 1
    assert set(svc._last_hashes) == {"request_sha256", "response_sha256"}
    prompt = svc._backend.complete.await_args.args[0]
    assert "192.168.0.7" not in prompt and "host-1" in prompt and "1.1.1.1" in prompt


@pytest.mark.asyncio
async def test_daily_call_limit_stops_calls():
    svc = _service(daily_call_limit=1)
    svc._backend.complete = AsyncMock(return_value="x")
    assert await svc._run_ai("a") == "x"
    assert await svc._run_ai("b") == ""
    assert svc._health["last_failure"] == "budget_exhausted" and svc._backend.complete.await_count == 1


@pytest.mark.asyncio
async def test_invalid_output_is_not_applied():
    svc = _service()
    svc._fetch_recent_events = AsyncMock(return_value=EVENTS)
    svc._backend.complete = AsyncMock(return_value="looks fine to me")
    svc._apply_result = AsyncMock()
    await svc._run_once()
    svc._apply_result.assert_not_awaited()
    assert svc._health["last_failure"] == "invalid_output"
