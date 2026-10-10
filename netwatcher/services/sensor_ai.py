"""AI 작업의 실행 상태만 전달한다. 모델 입력·명령·인증 정보는 포함하지 않는다."""

import re

from netwatcher.ai.providers import CLI_COMMANDS, HTTP_KINDS

FIELDS = {"enabled", "running", "state", "provider", "interval_minutes", "lookback_minutes",
          "fp_threshold", "max_pct", "consecutive_fp", "health", "credential"}
PROVIDERS = {*CLI_COMMANDS, *HTTP_KINDS}
HEALTH_FIELDS = {"last_attempt_at", "last_success_at", "consecutive_failures", "last_failure"}
FAILURES = {None, "not_installed", "timeout", "exit_status", "empty_output", "error", "auth", "rate_limited",
            "http_status", "invalid_output", "credential_missing", "budget_exhausted", "service_account"}
EMPTY_HEALTH = {"last_attempt_at": None, "last_success_at": None, "consecutive_failures": 0, "last_failure": None}


def _validate_health(health):
    if not isinstance(health, dict) or set(health) != HEALTH_FIELDS:
        raise ValueError("Invalid AI health fields")
    for key in ("last_attempt_at", "last_success_at"):
        value = health[key]
        if value is not None and (type(value) is not int or not 0 <= value <= 2**53):
            raise ValueError("Invalid AI health time")
    count = health["consecutive_failures"]
    if type(count) is not int or not 0 <= count <= 2147483647:
        raise ValueError("Invalid AI failure count")
    if health["last_failure"] not in FAILURES:
        raise ValueError("Invalid AI failure kind")


def validate_status(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("Invalid AI status fields")
    if type(value["enabled"]) is not bool or type(value["running"]) is not bool:
        raise ValueError("Invalid AI lifecycle")
    state = value["state"]
    if state not in {"running", "stopped", "unconfigured"}:
        raise ValueError("Invalid AI state")
    _validate_health(value["health"])
    # 키 값은 절대 싣지 않는다. HTTP 공급자일 때 설정 여부만 알린다.
    if value["credential"] not in {None, "configured", "missing"}:
        raise ValueError("Invalid AI credential state")
    if state == "unconfigured":
        if value["enabled"] or value["running"] or value["consecutive_fp"] != {} or value["health"] != EMPTY_HEALTH or value["credential"] is not None or any(
                value[key] is not None for key in {"provider", "interval_minutes", "lookback_minutes", "fp_threshold", "max_pct"}):
            raise ValueError("Unconfigured AI has observations")
        return
    if not value["enabled"] or value["running"] != (state == "running"):
        raise ValueError("Inconsistent AI lifecycle")
    if value["provider"] not in PROVIDERS:
        raise ValueError("Invalid AI provider")
    if (value["credential"] is None) != (value["provider"] in CLI_COMMANDS):
        raise ValueError("Invalid AI credential state")
    for key in ("interval_minutes", "lookback_minutes", "fp_threshold", "max_pct"):
        number = value[key]
        if type(number) is not int or not 0 < number <= 2147483647:
            raise ValueError("Invalid AI setting")
    counters = value["consecutive_fp"]
    if (not isinstance(counters, dict) or len(counters) > 64 or any(
            not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name)
            or type(count) is not int or not 0 <= count <= 2147483647 for name, count in counters.items())):
        raise ValueError("Invalid AI counters")


def _credential(analyzer):
    configured = analyzer._backend.credential_configured()
    return None if configured is None else "configured" if configured else "missing"


def status(analyzer):
    if analyzer is None:
        value = {"enabled": False, "running": False, "state": "unconfigured", "consecutive_fp": {},
                 "health": dict(EMPTY_HEALTH), "credential": None,
                 **dict.fromkeys({"provider", "interval_minutes", "lookback_minutes", "fp_threshold", "max_pct"})}
    else:
        running = analyzer._task is not None and not analyzer._task.done() and not analyzer._stopping
        value = {"enabled": True, "running": running, "state": "running" if running else "stopped",
                 "provider": analyzer._provider, "interval_minutes": analyzer._interval_seconds // 60,
                 "lookback_minutes": analyzer._lookback_minutes, "fp_threshold": analyzer._fp_threshold,
                 "max_pct": analyzer._max_pct, "consecutive_fp": dict(analyzer._consecutive_fp),
                 "health": dict(analyzer._health), "credential": _credential(analyzer)}
    validate_status(value)
    return value


def validate_result(request, result):
    if (not isinstance(result, dict) or set(result) != {"status", "request_id", "ai"}
            or result["status"] != "read" or result["request_id"] != request.request_id):
        raise ValueError("Invalid AI response")
    validate_status(result["ai"])
