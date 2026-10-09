"""센서의 시그니처 규칙 조회와 검증 후 적용."""

from dataclasses import replace
import hashlib
import json
import re


def rule_id(value):
    if not isinstance(value, str) or not 0 < len(value) <= 128 or "\x00" in value:
        raise ValueError("Invalid rule identifier")
    return value


def validate_updates(operation, updates):
    if operation == "rules.list":
        if (set(updates) != {"limit", "offset"} or type(updates["limit"]) is not int
                or not 1 <= updates["limit"] <= 50 or type(updates["offset"]) is not int
                or not 0 <= updates["offset"] <= 2147483647):
            raise ValueError("Invalid rule page")
    elif operation == "rules.reload":
        if updates:
            raise ValueError("Rule reload does not accept a file path")
    else:
        fields = {"rule_id", "enabled"} if operation == "rules.set" else {"rule_id"}
        if set(updates) != fields:
            raise ValueError("Invalid rule request")
        rule_id(updates["rule_id"])
        if operation == "rules.set" and type(updates["enabled"]) is not bool:
            raise ValueError("Invalid rule state")


def rule_document(rule):
    return {"id": rule.id, "name": rule.name, "severity": rule.severity.value,
        "protocol": rule.protocol, "src_ip": rule.src_ip, "dst_ip": rule.dst_ip,
        "src_port": rule.src_port, "dst_port": rule.dst_port, "flags": rule.flags,
        "content_nocase": rule.content_nocase, "has_content": bool(rule.content),
        "content_count": len(rule.content), "has_regex": rule.regex is not None or bool(rule.pcre),
        "threshold": rule.threshold, "enabled": rule.enabled}


def validate_document(doc):
    fields = {"id", "name", "severity", "protocol", "src_ip", "dst_ip", "src_port", "dst_port",
              "flags", "content_nocase", "has_content", "content_count", "has_regex", "threshold", "enabled"}
    if not isinstance(doc, dict) or set(doc) != fields:
        raise ValueError("Invalid rule document")
    rule_id(doc["id"])
    if not isinstance(doc["name"], str) or not 0 < len(doc["name"]) <= 512:
        raise ValueError("Invalid rule name")
    if doc["severity"] not in {"INFO", "WARNING", "CRITICAL"}:
        raise ValueError("Invalid rule severity")
    for key in ("protocol", "src_ip", "dst_ip", "flags"):
        if doc[key] is not None and (not isinstance(doc[key], str) or len(doc[key]) > 128):
            raise ValueError("Invalid rule header")
    for key in ("src_port", "dst_port"):
        value = doc[key]
        if value is not None:
            ports = value if isinstance(value, list) else [value]
            if len(ports) > 256 or any(type(port) is not int or not 0 <= port <= 65535 for port in ports):
                raise ValueError("Invalid rule ports")
    for key in ("content_nocase", "has_content", "has_regex", "enabled"):
        if type(doc[key]) is not bool:
            raise ValueError("Invalid rule boolean")
    if type(doc["content_count"]) is not int or not 0 <= doc["content_count"] <= 1024:
        raise ValueError("Invalid rule content count")
    if doc["threshold"] is not None and (not isinstance(doc["threshold"], dict)
            or len(json.dumps(doc["threshold"], allow_nan=False).encode()) > 2048):
        raise ValueError("Invalid rule threshold")


def digest_rules(rules):
    digest = hashlib.sha256()
    for rule in rules:
        validate_document(rule_document(rule))
        payload = json.dumps(vars(rule), default=str, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


class SensorRules:
    def __init__(self, registry):
        self.registry = registry

    def engine(self):
        engine = self.registry._find_active("signature")
        if engine is None:
            raise ValueError("Signature engine is unavailable")
        return engine

    def state(self, owner, generation):
        engine = self.engine()
        rules = tuple(engine.rules)
        if len({rule.id for rule in rules}) != len(rules):
            raise ValueError("Duplicate active rule identifiers")
        summary = {"rules_hash": digest_rules(rules), "total": len(rules)}
        version = hashlib.sha256(json.dumps({"owner": str(owner), "generation": generation,
            "instance": id(engine), **summary}, sort_keys=True).encode()).hexdigest()
        return {"base_version": version, **summary}

    def read(self, updates):
        rules = self.engine().rules
        if "rule_id" in updates:
            rule = self.engine().rules_by_id.get(updates["rule_id"])
            if rule is None:
                raise KeyError(updates["rule_id"])
            return {"rule": rule_document(rule)}
        start = updates["offset"]
        return {"rules": [rule_document(rule) for rule in rules[start:start + updates["limit"]]],
                "total": len(rules)}

    def stage(self, operation, updates):
        engine = self.engine()
        if operation == "rules.reload":
            candidate = engine.load_rule_candidates(strict=True)
        else:
            if updates["rule_id"] not in engine.rules_by_id:
                raise KeyError(updates["rule_id"])
            candidate = [replace(rule, enabled=updates["enabled"]) if rule.id == updates["rule_id"] else rule
                         for rule in engine.rules]
        digest = digest_rules(candidate)
        if len({rule.id for rule in candidate}) != len(candidate):
            raise ValueError("Duplicate candidate rule identifiers")
        return {"rules_hash": digest, "total": len(candidate)}, engine, candidate

    def apply(self, engine, candidate, operation):
        if engine is not self.engine():
            raise ValueError("Signature engine instance changed")
        engine.install_rules(candidate, reset_matcher=operation == "rules.reload")


def validate_result(request, result):
    operation = request.operation
    expected = {"status", "request_id", "base_version", "rules_hash"}
    updates = json.loads(request.updates_json)
    if operation == "rules.list":
        expected |= {"rules", "total"}
        docs = result.get("rules")
        total = result.get("total")
        if (not isinstance(docs, list) or len(docs) > updates["limit"] or type(total) is not int
                or total < len(docs) or len(docs) != min(updates["limit"], max(0, total - updates["offset"]))):
            raise ValueError("Invalid rule page result")
        for doc in docs:
            validate_document(doc)
        if len({doc["id"] for doc in docs}) != len(docs):
            raise ValueError("Duplicate returned rule identifiers")
    elif operation in {"rules.entry", "rules.set"}:
        expected.add("rule")
        validate_document(result.get("rule"))
        if result["rule"]["id"] != updates["rule_id"]:
            raise ValueError("Wrong rule target")
        if operation == "rules.set" and result["rule"]["enabled"] != updates["enabled"]:
            raise ValueError("Wrong applied rule state")
    else:
        expected.add("total")
        if type(result.get("total")) is not int or result["total"] < 0:
            raise ValueError("Invalid reloaded rule count")
    if (set(result) != expected or result["status"] != ("read" if operation in {"rules.list", "rules.entry"} else "applied")
            or result["request_id"] != request.request_id
            or any(not isinstance(result.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", result[key])
                   for key in ("base_version", "rules_hash"))):
        raise ValueError("Invalid rule result")
