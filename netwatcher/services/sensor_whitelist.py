"""센서의 실제 탐지 예외 목록을 검증하고 버전이 있는 상태로 전달한다."""

import hashlib
import ipaddress
import json
import re

from netwatcher.detection.whitelist import Whitelist

KEYS = {"ip": "ips", "ip_range": "ip_ranges", "mac": "macs", "domain": "domains", "suffix": "domain_suffixes"}


def normalize_config(values):
    """전체 예외 목록을 누락·알 수 없는 키·잘못된 항목 없이 복원한다."""
    if not isinstance(values, dict) or set(values) != set(KEYS.values()):
        raise ValueError("invalid whitelist configuration")
    if any(not isinstance(entries, list) for entries in values.values()):
        raise ValueError("invalid whitelist entries")
    if sum(len(entries) for entries in values.values()) > 1024:
        raise ValueError("whitelist capacity exceeded")
    normalized = {key: sorted({normalize_entry(kind, entry) for entry in values[key]})
                  for kind, key in KEYS.items()}
    state(Whitelist(normalized), "worker", "worker")
    return normalized


def normalize_entry(kind, value):
    if kind not in KEYS or not isinstance(value, str) or not 0 < len(value) <= 253 or value != value.strip():
        raise ValueError("invalid whitelist entry")
    if kind == "ip":
        if "%" in value:
            raise ValueError("scoped address is unavailable")
        return str(ipaddress.ip_address(value))
    if kind == "ip_range":
        if "%" in value:
            raise ValueError("scoped network is unavailable")
        return str(ipaddress.ip_network(value, strict=False))
    if kind == "mac":
        if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
            raise ValueError("invalid MAC")
        return value.lower()
    suffix = kind == "suffix"
    if suffix and not value.startswith("."):
        raise ValueError("suffix must start with a dot")
    domain = value[1:] if suffix else value
    domain = domain.encode("idna").decode("ascii").lower()
    if len(domain) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
        raise ValueError("invalid domain")
    return ("." if suffix else "") + domain


def state(whitelist, owner, generation):
    if not isinstance(whitelist, Whitelist):
        raise ValueError("whitelist unavailable")
    values = whitelist.to_dict()
    if sum(len(entries) for entries in values.values()) > 1024:
        raise ValueError("whitelist capacity exceeded")
    encoded = json.dumps(values, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > 58000:
        raise ValueError("whitelist size exceeded")
    version = hashlib.sha256(str(owner).encode() + generation.encode() + encoded).hexdigest()
    return {"whitelist": values, "base_version": version}


def candidate(whitelist, updates):
    if set(updates) != {"type", "value", "present"} or type(updates["present"]) is not bool:
        raise ValueError("invalid whitelist change")
    value = normalize_entry(updates["type"], updates["value"])
    values = whitelist.to_dict()
    key = KEYS[updates["type"]]
    entries = set(values[key])
    if updates["present"]:
        entries.add(value)
    else:
        entries.discard(value)
    values[key] = sorted(entries)
    result = Whitelist(values)
    state(result, "candidate", "candidate")
    return result
