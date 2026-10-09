"""리플레이 자식의 결과를 객체 실행 기능이 없는 JSON으로 전달한다."""

from dataclasses import asdict
import json
import math

from netwatcher.replay.contract import Observation, ReplayResult
from netwatcher.replay.service import BudgetReport, ReplayOutcome


def encode_result(kind, payload) -> bytes:
    if kind == "ok":
        payload = asdict(payload)
    return json.dumps([kind, payload], ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate replay result field")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("Nonfinite replay result")


def _fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Invalid replay result fields")


def _text(value, limit=1024):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Invalid replay result text")


def _number(value, *, integer=False):
    if (type(value) not in ((int,) if integer else (int, float)) or value < 0
            or (type(value) is int and value > 2**63 - 1) or not math.isfinite(value)):
        raise ValueError("Invalid replay result number")


def _strings(values):
    if not isinstance(values, list):
        raise ValueError("Invalid replay result list")
    for value in values:
        _text(value)


def _observation(value):
    _fields(value, ("engine", "kind", "subject", "features", "observed_at", "seq"))
    for field in ("engine", "kind", "subject"):
        _text(value[field])
    if not isinstance(value["features"], dict):
        raise ValueError("Invalid replay observation features")
    _number(value["observed_at"])
    _number(value["seq"], integer=True)
    return Observation(**value)


def _engine_result(value):
    _fields(value, ("engine", "version", "observations", "unsupported", "notes"))
    _text(value["engine"])
    _text(value["version"])
    _strings(value["unsupported"])
    _strings(value["notes"])
    if not isinstance(value["observations"], list):
        raise ValueError("Invalid replay observations")
    return ReplayResult(**{**value, "observations": [_observation(item) for item in value["observations"]]})


def _outcome(value):
    _fields(value, ("run_id", "status", "comparable", "non_comparable_reasons", "results", "budget", "error"))
    _number(value["run_id"], integer=True)
    if value["status"] != "completed" or type(value["comparable"]) is not bool:
        raise ValueError("Invalid replay outcome state")
    if value["error"] is not None:
        _text(value["error"])
    if not isinstance(value["non_comparable_reasons"], list):
        raise ValueError("Invalid replay comparison reasons")
    if value["comparable"] != (not value["non_comparable_reasons"]):
        raise ValueError("Replay comparability mismatch")
    for reason in value["non_comparable_reasons"]:
        _fields(reason, ("code", "detail"))
        _text(reason["code"])
        _text(reason["detail"], limit=16384)
    budget = value["budget"]
    _fields(budget, ("source_bytes", "elapsed_seconds", "max_source_bytes", "max_seconds", "exceeded", "reason"))
    for field in ("source_bytes", "max_source_bytes", "max_seconds"):
        _number(budget[field], integer=True)
    _number(budget["elapsed_seconds"])
    if type(budget["exceeded"]) is not bool:
        raise ValueError("Invalid replay budget state")
    if budget["exceeded"] and value["comparable"]:
        raise ValueError("Exceeded replay cannot be comparable")
    if budget["reason"] is not None:
        _text(budget["reason"])
    if not isinstance(value["results"], dict):
        raise ValueError("Invalid replay engine results")
    results = {}
    for key, document in value["results"].items():
        _text(key)
        side, separator, engine = key.partition(":")
        if not separator or side not in {"baseline", "candidate"}:
            raise ValueError("Invalid replay result side")
        result = _engine_result(document)
        if result.engine != engine or any(item.engine != engine for item in result.observations):
            raise ValueError("Replay result engine mismatch")
        results[key] = result
    return ReplayOutcome(**{**value, "results": results, "budget": BudgetReport(**budget)})


def decode_result(data: bytes, max_bytes: int):
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise ValueError("Replay result exceeds capacity")
    try:
        envelope = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("Invalid replay result encoding") from error
    if not isinstance(envelope, list) or len(envelope) != 2:
        raise ValueError("Invalid replay result envelope")
    kind, payload = envelope
    _text(kind, limit=16)
    if kind == "ok":
        return kind, _outcome(payload)
    if kind not in {"budget", "error"}:
        raise ValueError("Invalid replay result kind")
    _text(payload, limit=128)
    return kind, payload
