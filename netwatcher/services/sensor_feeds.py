"""피드 상태만 전달하며 설정·URL·원본 지표는 보내지 않는다."""

import math

COUNTS = {"blocked_ips", "blocked_domains", "blocked_ja3", "custom_ips"}
FIELDS = {"status", "last_success_epoch", "age_hours", "stale_after_hours", "last_attempt", "outcomes", "sources"} | COUNTS
ATTEMPT_COUNTS = {"downloaded", "from_cache", "failed", "blocked_ips", "blocked_domains"}


def _number(value):
    return type(value) in (int, float) and 0 <= value <= 2**53 - 1 and math.isfinite(value)


def _count(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


def validate_health(value):
    if not isinstance(value, dict) or set(value) != FIELDS or value["status"] not in {"ok", "stale", "degraded", "unconfigured"}:
        raise ValueError("Invalid feed health fields")
    if not _number(value["stale_after_hours"]) or value["stale_after_hours"] <= 0:
        raise ValueError("Invalid feed freshness threshold")
    if value["status"] == "unconfigured":
        if any(value[key] is not None for key in COUNTS | {"last_success_epoch", "age_hours", "last_attempt"}) or value["outcomes"] != {} or value['sources'] != []:
            raise ValueError("Unconfigured feeds have observations")
        return
    if any(not _count(value[key]) for key in COUNTS) or not _number(value["last_success_epoch"]):
        raise ValueError("Invalid feed count or timestamp")
    age = value["age_hours"]
    if age is not None and not _number(age):
        raise ValueError("Invalid feed age")
    if (value["last_success_epoch"] == 0) != (age is None):
        raise ValueError("Unconfirmed feed success timestamp")
    if value["status"] == "ok" and (age is None or age > value["stale_after_hours"]):
        raise ValueError("Unconfirmed fresh feeds")
    outcomes = value["outcomes"]
    if (not isinstance(outcomes, dict) or len(outcomes) > 128
            or any(not isinstance(name, str) or not 1 <= len(name) <= 128 or "\x00" in name
                   or outcome not in {"downloaded", "cached", "failed"} for name, outcome in outcomes.items())):
        raise ValueError("Invalid feed outcomes")
    attempt = value["last_attempt"]
    if attempt is not None and (not isinstance(attempt, dict)
            or set(attempt) != ATTEMPT_COUNTS | {"succeeded", "last_update_epoch"}
            or type(attempt["succeeded"]) is not bool or not _number(attempt["last_update_epoch"])
            or any(not _count(attempt[key]) for key in ATTEMPT_COUNTS)):
        raise ValueError("Invalid feed attempt")
    validate_sources(value)


def validate_sources(value):
    sources = value['sources']
    if not isinstance(sources, list) or len(sources) > 128:
        raise ValueError('Invalid feed source list')
    names = set()
    for source in sources:
        if (not isinstance(source, dict) or set(source) != {'name','status','last_success_epoch','age_hours','outcome'}
                or not isinstance(source['name'], str) or not 1 <= len(source['name']) <= 128 or '\x00' in source['name']
                or source['name'] in names or source['status'] not in {'ok','stale','unknown'}
                or source['outcome'] not in {'downloaded','cached','failed',None}):
            raise ValueError('Invalid feed source')
        names.add(source['name'])
        epoch, age = source['last_success_epoch'], source['age_hours']
        if source['status'] == 'unknown':
            if epoch is not None or age is not None:
                raise ValueError('Unknown feed source has confirmed time')
        elif not _number(epoch) or epoch <= 0 or not _number(age):
            raise ValueError('Invalid feed source time')
        elif source['status'] == 'ok' and age > value['stale_after_hours']:
            raise ValueError('Unconfirmed fresh source')
        if source['outcome'] != value['outcomes'].get(source['name']):
            raise ValueError('Inconsistent source outcome')
    if sources:
        fresh = sum(source['status'] == 'ok' for source in sources)
        expected = 'ok' if fresh == len(sources) else 'degraded' if fresh else 'stale'
        if value['status'] != expected:
            raise ValueError('Inconsistent aggregate freshness')


def health(manager):
    value = ({"status": "unconfigured", "last_success_epoch": None, "age_hours": None,
              "stale_after_hours": 12.0, "last_attempt": None, "outcomes": {}, "sources": [], **dict.fromkeys(COUNTS)}
             if manager is None else manager.feed_health())
    validate_health(value)
    return value


def validate_result(request, result):
    if (set(result) != {"status", "request_id", "feeds"} or result["status"] != "read"
            or result["request_id"] != request.request_id):
        raise ValueError("Invalid feed response")
    validate_health(result["feeds"])
