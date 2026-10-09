"""승인된 시그니처 목록을 정규식 옵션까지 보존해 워커에 전달한다."""

import json
import re

from netwatcher.detection.engines.signature_rule import SignatureRule
from netwatcher.services.sensor_rules import digest_rules

MAX_RULE_BYTES = 32 * 1024 * 1024


def rules_payload(rules) -> str:
    digest_rules(rules)
    documents = []
    for rule in rules:
        value = dict(vars(rule))
        value["severity"] = rule.severity.value
        value["regex"] = pattern_document(rule.regex) if rule.regex is not None else None
        value["pcre"] = [pattern_document(pattern) for pattern in rule.pcre]
        documents.append(value)
    payload = json.dumps(documents, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))
    restore_rules(payload)
    return payload


def pattern_document(pattern):
    return {"pattern": pattern.pattern, "flags": pattern.flags}


def restore_pattern(value):
    if (not isinstance(value, dict) or set(value) != {"pattern", "flags"}
            or not isinstance(value["pattern"], str) or type(value["flags"]) is not int):
        raise ValueError("Invalid worker rule pattern")
    return re.compile(value["pattern"], value["flags"])


def restore_rules(payload):
    if not isinstance(payload, str) or len(payload.encode()) > MAX_RULE_BYTES:
        raise ValueError("Worker rules exceed capacity")
    documents = json.loads(payload)
    if not isinstance(documents, list) or len(documents) > 100000:
        raise ValueError("Invalid worker rule list")
    rules = []
    for document in documents:
        if not isinstance(document, dict) or "regex" not in document or not isinstance(document.get("pcre"), list):
            raise ValueError("Invalid worker rule document")
        rule = SignatureRule.from_dict({**document, "regex": None, "pcre": []})
        rule.regex = restore_pattern(document["regex"]) if document["regex"] is not None else None
        rule.pcre = [restore_pattern(pattern) for pattern in document["pcre"]]
        rules.append(rule)
    digest_rules(rules)
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("Duplicate worker rule identifiers")
    return rules
