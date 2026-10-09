"""센서의 사용자 위협 지표와 DB 기록을 같은 변경 요청으로 관리한다."""

import hashlib
import ipaddress
import json
import re
from datetime import datetime

from netwatcher.services.sensor_whitelist import normalize_entry as normalize_whitelist_entry


def entry_metadata(row):
    if row is None:
        return {"notes": "", "notes_truncated": False, "created_at": None}
    stamp = row["created_at"]
    if isinstance(stamp, str):
        stamp = datetime.fromisoformat(stamp)
    if stamp.utcoffset() is None:
        raise ValueError("indicator timestamp needs an offset")
    return {"notes": row["notes"][:2048], "notes_truncated": len(row["notes"]) > 2048,
            "created_at": stamp.isoformat()}


def normalize_entry(kind, value):
    if kind not in {"ip", "domain"} or not isinstance(value, str) or not 0 < len(value) <= 253 or value != value.strip():
        raise ValueError("invalid blocklist entry")
    if kind == "ip":
        if "%" in value:
            raise ValueError("scoped address is unavailable")
        return str(ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value))
    domain = normalize_whitelist_entry("domain", value)
    if "." not in domain:
        raise ValueError("domain must include a suffix")
    return domain


def validate_updates(operation, updates):
    if operation == "blocklist.stats":
        if updates:
            raise ValueError("invalid statistics request")
        return
    if operation == "blocklist.list":
        if set(updates) != {"entry_type", "source", "search", "limit", "offset"}:
            raise ValueError("invalid list filters")
        if updates["entry_type"] not in {None, "ip", "domain"} or updates["source"] not in {None, "custom", "feed"}:
            raise ValueError("invalid list filters")
        if updates["search"] is not None and (not isinstance(updates["search"], str) or len(updates["search"]) > 253):
            raise ValueError("invalid list search")
        if type(updates["limit"]) is not int or not 0 <= updates["limit"] <= 100:
            raise ValueError("invalid list limit")
        if type(updates["offset"]) is not int or not 0 <= updates["offset"] <= 2147483647:
            raise ValueError("invalid list offset")
        return
    fields = {"type", "value"} if operation == "blocklist.entry" else {"type", "value", "present", "notes"}
    if set(updates) != fields:
        raise ValueError("invalid blocklist change")
    normalize_entry(updates["type"], updates["value"])
    if operation == "blocklist.set" and (type(updates["present"]) is not bool
            or not isinstance(updates["notes"], str) or len(updates["notes"]) > 2048 or "\x00" in updates["notes"]):
        raise ValueError("invalid blocklist change")


class SensorBlocklist:
    def __init__(self, manager):
        self.manager = manager

    def available(self):
        if self.manager is None:
            raise ValueError("blocklist unavailable")

    def page(self, updates):
        self.available()
        entries, total = self.manager.get_all_entries_paginated(**updates)
        return {"entries": entries, "total": total}

    def stats(self):
        self.available()
        return {"total_ips": len(self.manager._blocked_ips), "total_domains": len(self.manager._blocked_domains),
                "custom_ips": len(self.manager._custom_ips), "custom_domains": len(self.manager._custom_domains)}

    async def state(self, conn, updates, owner, generation, *, exact=False):
        self.available()
        kind, raw = updates["type"], updates["value"]
        normalized = normalize_entry(kind, raw)
        # 기존 표기로 저장된 항목은 그 행을 먼저 선택한다. 새 항목은 정규화한다.
        row = await conn.fetchrow("""SELECT value,notes,created_at FROM custom_blocklist
            WHERE entry_type=$1 AND (value=$2 OR value=$3)
            ORDER BY CASE WHEN value=$2 THEN 0 ELSE 1 END LIMIT 1 FOR UPDATE""", kind, raw, raw if exact else normalized)
        value = row["value"] if row else raw if exact else normalized
        entries = self.manager._custom_ips if kind == "ip" else self.manager._custom_domains
        if (value in entries) != (row is not None):
            raise ValueError("blocklist database and sensor disagree")
        entry = {"type": kind, "value": value, "present": row is not None,
                 "notes_sha256": hashlib.sha256(row["notes"].encode()).hexdigest() if row else None,
                 **entry_metadata(row)}
        version = hashlib.sha256(json.dumps({"owner": str(owner), "generation": generation, "entry": entry},
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        return {"entry": entry, "base_version": version}

    async def apply(self, conn, entry, updates):
        kind, value = entry["type"], entry["value"]
        if updates["present"]:
            await conn.execute("""INSERT INTO custom_blocklist(entry_type,value,notes) VALUES($1,$2,$3)
                ON CONFLICT(entry_type,value) DO NOTHING""", kind, value, updates["notes"])
        else:
            await conn.execute("DELETE FROM custom_blocklist WHERE entry_type=$1 AND value=$2", kind, value)

    def apply_memory(self, entry, present):
        kind, value = entry["type"], entry["value"]
        method = (self.manager.add_custom_ip if present else self.manager.remove_custom_ip) if kind == "ip" else (
            self.manager.add_custom_domain if present else self.manager.remove_custom_domain)
        method(value)


def validate_result(request, result):
    operation = request.operation
    expected = {"status", "request_id"}
    if operation == "blocklist.list":
        expected |= {"entries", "total"}
        entries, total = result.get("entries"), result.get("total")
        filters = json.loads(request.updates_json)
        limit = filters["limit"]
        if (not isinstance(entries, list) or len(entries) > limit or type(total) is not int or total < len(entries)
                or any(not isinstance(entry, dict) or set(entry) != {"type", "value", "source"}
                       or entry["type"] not in {"ip", "domain"}
                       or not isinstance(entry["value"], str) or not 0 < len(entry["value"]) <= 253
                       or not isinstance(entry["source"], str) or not 0 < len(entry["source"]) <= 128 for entry in entries)):
            raise ValueError("invalid blocklist page")
        keys = [(entry["source"] != "Custom", entry["type"], entry["value"]) for entry in entries]
        if keys != sorted(keys) or len({(entry["type"], entry["value"]) for entry in entries}) != len(entries):
            raise ValueError("invalid blocklist ordering")
        for entry in entries:
            if (filters["entry_type"] is not None and entry["type"] != filters["entry_type"]
                    or filters["source"] == "custom" and entry["source"] != "Custom"
                    or filters["source"] == "feed" and entry["source"] == "Custom"
                    or filters["search"] and filters["search"].lower() not in entry["value"].lower()):
                raise ValueError("blocklist filter mismatch")
    elif operation == "blocklist.stats":
        expected.add("stats")
        stats = result.get("stats")
        if (not isinstance(stats, dict) or set(stats) != {"total_ips", "total_domains", "custom_ips", "custom_domains"}
                or any(type(count) is not int or count < 0 for count in stats.values())
                or stats["custom_ips"] > stats["total_ips"] or stats["custom_domains"] > stats["total_domains"]):
            raise ValueError("invalid blocklist statistics")
    else:
        expected |= {"entry", "base_version"}
        entry = result.get("entry")
        if (not isinstance(entry, dict) or set(entry) != {"type", "value", "present", "notes_sha256", "notes", "notes_truncated", "created_at"}
                or entry["type"] not in {"ip", "domain"} or type(entry["present"]) is not bool
                or not isinstance(entry["value"], str) or not 0 < len(entry["value"]) <= 253
                or (entry["present"] and (not isinstance(entry["notes_sha256"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", entry["notes_sha256"])))
                or (not entry["present"] and entry["notes_sha256"] is not None)
                or not isinstance(result.get("base_version"), str) or not re.fullmatch(r"[a-f0-9]{64}", result["base_version"])):
            raise ValueError("invalid blocklist entry result")
        if (not isinstance(entry["notes"], str) or len(entry["notes"]) > 2048 or type(entry["notes_truncated"]) is not bool
                or (entry["present"] and (not isinstance(entry["created_at"], str) or not 0 < len(entry["created_at"]) <= 64))
                or (not entry["present"] and (entry["created_at"] is not None or entry["notes"] or entry["notes_truncated"]))):
            raise ValueError("invalid indicator metadata")
        if entry["present"] and datetime.fromisoformat(entry["created_at"]).utcoffset() is None:
            raise ValueError("indicator timestamp needs an offset")
        updates = json.loads(request.updates_json)
        if entry["type"] != updates["type"] or normalize_entry(entry["type"], entry["value"]) != normalize_entry(updates["type"], updates["value"]):
            raise ValueError("wrong blocklist target")
        if operation == "blocklist.set" and entry["present"] != updates["present"]:
            raise ValueError("wrong blocklist presence")
    if set(result) != expected or result["status"] != ("applied" if operation == "blocklist.set" else "read"):
        raise ValueError("invalid blocklist result")
