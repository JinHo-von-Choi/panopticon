"""AI 분석 공급자. 모두 같은 입력(프롬프트)을 받아 같은 결과 계약(DecisionResult)을 돌려준다.

공급자는 판단만 한다. 설정 변경은 분석기가 결정론 규칙(연속 판정 수, 조정 상한)을 거쳐
제안으로만 남긴다. 실패는 종류를 붙여 ProviderError로 알린다.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import aiohttp

DECISION_VERSION = 1
VERDICTS = ("CONFIRMED_THREAT", "FALSE_POSITIVE", "MISSED_THREAT", "UNCERTAIN")
MAX_OUTPUT_BYTES = 64 * 1024

CLI_COMMANDS: dict[str, list[str]] = {
    "copilot": ["gh", "copilot", "explain"],
    "claude": ["claude", "-p"],
    "codex": ["codex"],
    "gemini": ["gemini", "-p"],
    "agent": ["claude", "--agent"],
}
HTTP_KINDS = ("anthropic", "openai_compatible")
DEFAULT_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai_compatible": "OPENAI_API_KEY"}
DEFAULT_ENDPOINT = {"anthropic": "https://api.anthropic.com", "openai_compatible": "https://api.openai.com/v1"}


class ProviderError(Exception):
    """kind: not_installed, timeout, exit_status, empty_output, auth, rate_limited,
    http_status, invalid_output, credential_missing, budget_exhausted, error."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(detail or kind)
        self.kind = kind


@dataclass
class DecisionResult:
    """공급자 판단의 버전 계약. evidence_event_ids는 입력에 있던 사건 ID만 남는다."""

    verdict: str
    engine: str
    reason: str = ""
    reasoning: str = ""
    adjustments: dict[str, float] = field(default_factory=dict)
    evidence_event_ids: list[int] = field(default_factory=list)
    version: int = DECISION_VERSION


JSON_INSTRUCTION = (
    'Respond with one JSON object only, no prose: {"version": 1, "verdict": "CONFIRMED_THREAT|FALSE_POSITIVE|'
    'MISSED_THREAT|UNCERTAIN", "engine": "<engine name or empty>", "reason": "<one sentence>", '
    '"reasoning": ["<point>", ...], "adjustments": {"<param>": <number>}, "evidence_event_ids": [<event id>, ...]}. '
    'Use UNCERTAIN when the events do not support a conclusion.'
)


def _reject_constant(value):
    raise ValueError(f"non-finite number {value}")


def parse_decision(text: str, known_event_ids=()) -> DecisionResult:
    """JSON 계약을 엄격히 검증한다. 맞지 않으면 invalid_output으로 거절한다."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ProviderError("invalid_output", "no JSON object")
    try:
        data = json.loads(match.group(0), parse_constant=_reject_constant)
    except ValueError:
        raise ProviderError("invalid_output", "malformed JSON") from None
    allowed = {"version", "verdict", "engine", "reason", "reasoning", "adjustments", "evidence_event_ids"}
    if not isinstance(data, dict) or set(data) - allowed or data.get("version") != DECISION_VERSION:
        raise ProviderError("invalid_output", "unexpected fields or version")
    verdict, engine = data.get("verdict"), data.get("engine", "")
    reason, reasoning = data.get("reason", ""), data.get("reasoning", [])
    adjustments, evidence = data.get("adjustments", {}), data.get("evidence_event_ids", [])
    if (verdict not in VERDICTS or not isinstance(engine, str) or not re.fullmatch(r"[a-z0-9_]{0,64}", engine)
            or not isinstance(reason, str) or len(reason) > 1000
            or not isinstance(reasoning, list) or len(reasoning) > 10
            or not all(isinstance(item, str) and len(item) <= 500 for item in reasoning)
            or not isinstance(adjustments, dict) or len(adjustments) > 16
            or not all(isinstance(key, str) and re.fullmatch(r"\w{1,64}", key)
                       and isinstance(value, (int, float)) and not isinstance(value, bool)
                       and value == value and abs(value) != float("inf") for key, value in adjustments.items())
            or not isinstance(evidence, list) or len(evidence) > 50
            or not all(isinstance(item, int) and not isinstance(item, bool) for item in evidence)):
        raise ProviderError("invalid_output", "schema violation")
    known = set(known_event_ids)
    return DecisionResult(
        verdict=verdict, engine=engine, reason=reason,
        reasoning="\n".join(f"{index}. {item}" for index, item in enumerate(reasoning, 1)),
        adjustments={key: float(value) for key, value in adjustments.items()},
        # 입력에 없던 사건 ID는 근거로 인정하지 않는다.
        evidence_event_ids=[item for item in evidence if item in known])


def _check_endpoint(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
        raise ValueError("ai_analyzer.endpoint must be an http(s) URL without credentials")
    if parts.scheme == "http":
        # 평문 HTTP는 이 호스트 안의 공급자(예: 로컬 추론 서버)에만 허용한다.
        host = parts.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ValueError("ai_analyzer.endpoint must use https unless it is a loopback address")
    return endpoint.rstrip("/")


class CliProvider:
    structured = False

    def __init__(self, name: str, timeout: float):
        self.name, self.timeout = name, timeout
        self.command = CLI_COMMANDS[name]

    def credential_configured(self) -> bool | None:
        return None

    async def complete(self, prompt: str) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.command, prompt, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError:
            raise ProviderError("not_installed") from None
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise ProviderError("timeout") from None
        if proc.returncode != 0:
            raise ProviderError("exit_status", str(proc.returncode))
        output = stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        if not output.strip():
            raise ProviderError("empty_output")
        return output


class HttpProvider:
    """Anthropic Messages API 또는 OpenAI 호환 Chat Completions."""

    structured = True

    def __init__(self, kind: str, *, model: str, endpoint: str | None, api_key_env: str | None,
                 timeout: float, max_tokens: int = 1024):
        if kind not in HTTP_KINDS:
            raise ValueError(f"unknown HTTP provider {kind!r}")
        if not isinstance(model, str) or not re.fullmatch(r"[\w.:/-]{1,128}", model):
            raise ValueError("ai_analyzer.model is required for HTTP providers")
        if not 64 <= max_tokens <= 8192:
            raise ValueError("ai_analyzer.max_tokens must be 64-8192")
        self.name = kind
        self.kind, self.model, self.timeout, self.max_tokens = kind, model, timeout, max_tokens
        self.endpoint = _check_endpoint(endpoint or DEFAULT_ENDPOINT[kind])
        self.api_key_env = api_key_env or DEFAULT_KEY_ENV[kind]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", self.api_key_env):
            raise ValueError("ai_analyzer.api_key_env must be an environment variable name")

    def credential_configured(self) -> bool:
        return bool(os.environ.get(self.api_key_env))

    def _request(self, prompt: str, key: str):
        if self.kind == "anthropic":
            return (f"{self.endpoint}/v1/messages",
                    {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                    {"model": self.model, "max_tokens": self.max_tokens,
                     "messages": [{"role": "user", "content": prompt}]})
        return (f"{self.endpoint}/chat/completions",
                {"authorization": f"Bearer {key}", "content-type": "application/json"},
                {"model": self.model, "max_tokens": self.max_tokens,
                 "messages": [{"role": "user", "content": prompt}]})

    def _text(self, body) -> str:
        try:
            if self.kind == "anthropic":
                return "".join(part["text"] for part in body["content"] if part.get("type") == "text")
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("invalid_output", "unexpected response shape") from None

    async def complete(self, prompt: str) -> str:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise ProviderError("credential_missing")
        url, headers, payload = self._request(prompt, key)
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(url, json=payload, headers=headers, allow_redirects=False) as response:
                    raw = await response.content.read(MAX_OUTPUT_BYTES + 1)
                    status = response.status
        except asyncio.TimeoutError:
            raise ProviderError("timeout") from None
        except aiohttp.ClientError as exc:
            raise ProviderError("error", type(exc).__name__) from None
        if status in (401, 403):
            raise ProviderError("auth", str(status))
        if status == 429:
            raise ProviderError("rate_limited")
        if status != 200:
            raise ProviderError("http_status", str(status))
        if len(raw) > MAX_OUTPUT_BYTES:
            raise ProviderError("invalid_output", "response too large")
        try:
            text = self._text(json.loads(raw))
        except ValueError:
            raise ProviderError("invalid_output", "response is not JSON") from None
        if not isinstance(text, str) or not text.strip():
            raise ProviderError("empty_output")
        return text


def build_provider(ai_cfg: dict, timeout: float):
    name = str(ai_cfg.get("provider", "copilot"))
    if name in CLI_COMMANDS:
        return CliProvider(name, timeout)
    if name in HTTP_KINDS:
        return HttpProvider(name, model=ai_cfg.get("model"), endpoint=ai_cfg.get("endpoint"),
                            api_key_env=ai_cfg.get("api_key_env"), timeout=timeout,
                            max_tokens=int(ai_cfg.get("max_tokens", 1024)))
    raise ValueError(f"ai_analyzer.provider must be one of {sorted([*CLI_COMMANDS, *HTTP_KINDS])} (got {name!r})")
