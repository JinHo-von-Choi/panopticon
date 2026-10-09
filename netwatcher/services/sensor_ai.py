"""AI 작업의 실행 상태만 전달한다. 모델 입력·명령·인증 정보는 포함하지 않는다."""

import re

FIELDS = {"enabled", "running", "state", "provider", "interval_minutes", "lookback_minutes",
          "fp_threshold", "max_pct", "consecutive_fp"}


def validate_status(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("Invalid AI status fields")
    if type(value["enabled"]) is not bool or type(value["running"]) is not bool:
        raise ValueError("Invalid AI lifecycle")
    state = value["state"]
    if state not in {"running", "stopped", "unconfigured"}:
        raise ValueError("Invalid AI state")
    if state == "unconfigured":
        if value["enabled"] or value["running"] or value["consecutive_fp"] != {} or any(
                value[key] is not None for key in {"provider", "interval_minutes", "lookback_minutes", "fp_threshold", "max_pct"}):
            raise ValueError("Unconfigured AI has observations")
        return
    if not value["enabled"] or value["running"] != (state == "running"):
        raise ValueError("Inconsistent AI lifecycle")
    if value["provider"] not in {"copilot", "claude", "codex", "gemini", "agent"}:
        raise ValueError("Invalid AI provider")
    for key in ("interval_minutes", "lookback_minutes", "fp_threshold", "max_pct"):
        number = value[key]
        if type(number) is not int or not 0 < number <= 2147483647:
            raise ValueError("Invalid AI setting")
    counters = value["consecutive_fp"]
    if (not isinstance(counters, dict) or len(counters) > 64 or any(
            not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name)
            or type(count) is not int or not 0 <= count <= 2147483647 for name, count in counters.items())):
        raise ValueError("Invalid AI counters")


def status(analyzer):
    if analyzer is None:
        value = {"enabled": False, "running": False, "state": "unconfigured", "consecutive_fp": {},
                 **dict.fromkeys({"provider", "interval_minutes", "lookback_minutes", "fp_threshold", "max_pct"})}
    else:
        running = analyzer._task is not None and not analyzer._task.done() and not analyzer._stopping
        value = {"enabled": True, "running": running, "state": "running" if running else "stopped",
                 "provider": analyzer._provider, "interval_minutes": analyzer._interval_seconds // 60,
                 "lookback_minutes": analyzer._lookback_minutes, "fp_threshold": analyzer._fp_threshold,
                 "max_pct": analyzer._max_pct, "consecutive_fp": dict(analyzer._consecutive_fp)}
    validate_status(value)
    return value


def validate_result(request, result):
    if (not isinstance(result, dict) or set(result) != {"status", "request_id", "ai"}
            or result["status"] != "read" or result["request_id"] != request.request_id):
        raise ValueError("Invalid AI response")
    validate_status(result["ai"])
