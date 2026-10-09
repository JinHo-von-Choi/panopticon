"""Suricata EVE JSON 행을 제한된 조사 기록으로 변환한다."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone


SUPPORTED_TYPES = frozenset({"alert", "flow", "dns", "tls"})
MAX_LINE_BYTES = 256 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _reject_constant(value):
    raise ValueError("Non-finite JSON number")


def _text(value, limit=512):
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise ValueError("Invalid text field")
    return value


def _integer(value, maximum=2**64 - 1):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError("Invalid integer field")
    return value


def decode_eve_line(raw: bytes, *, source_id: str, sensor_id: str,
                    generation: str, offset: int, received_at: datetime | None = None) -> dict:
    """원본 참조와 해시를 남기고 허용한 필드만 반환한다.

    파일 세대는 수집기가 생성한 UUID다. 동일 위치를 다시 읽으면 같은 ingest_id를
    반환한다. 원문은 외부 로그의 세대·바이트 위치로 참조하고 본문을 복사하지 않는다.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_LINE_BYTES:
        raise ValueError("EVE line exceeds input budget")
    if not all(isinstance(value, str) and _IDENTIFIER.fullmatch(value)
               for value in (source_id, sensor_id)):
        raise ValueError("Invalid sensor or source identifier")
    generation = str(uuid.UUID(generation))
    _integer(offset, 2**63 - 1)
    record = json.loads(raw, parse_constant=_reject_constant)
    if not isinstance(record, dict):
        raise ValueError("EVE record must be an object")
    event_type = _text(record.get("event_type"), 64)
    observed = datetime.fromisoformat(_text(record.get("timestamp"), 64))
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("EVE timestamp must include a timezone")
    received = received_at or datetime.now(timezone.utc)
    if received.tzinfo is None or received.utcoffset() is None:
        raise ValueError("Receive timestamp must include a timezone")
    result = {
        "ingest_id": str(uuid.uuid5(uuid.NAMESPACE_URL,
            f"panopticon:eve:{sensor_id}:{source_id}:{generation}:{offset}")),
        "source_id": source_id, "sensor_id": sensor_id, "event_type": event_type,
        "supported": event_type in SUPPORTED_TYPES,
        "observed_at": observed.astimezone(timezone.utc).isoformat(),
        "received_at": received.astimezone(timezone.utc).isoformat(),
        "original_ref": {"generation": generation, "offset": offset,
                         "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
    }
    for key in ("src_ip", "dest_ip"):
        if key in record:
            result[key] = str(ipaddress.ip_address(_text(record[key], 64)))
    if "ether" in record:
        ethernet = record["ether"]
        if not isinstance(ethernet, dict):
            raise ValueError("Invalid Ethernet details")
        for key in ("src_mac", "dest_mac"):
            if key in ethernet:
                value = _text(ethernet[key], 17)
                if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
                    raise ValueError("Invalid Ethernet MAC")
                result[key] = value.lower()
        for key in ("src_macs", "dest_macs"):
            if key in ethernet:
                values = ethernet[key]
                if not isinstance(values, list) or not 1 <= len(values) <= 8:
                    raise ValueError("Invalid Ethernet MAC list")
                result[key] = []
                for value in values:
                    value = _text(value, 17)
                    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
                        raise ValueError("Invalid Ethernet MAC")
                    result[key].append(value.lower())
    for key in ("src_port", "dest_port"):
        if key in record:
            result[key] = _integer(record[key], 65535)
    if "flow_id" in record:
        # 문자열로 보존해 JavaScript의 정수 정밀도 손실을 막는다.
        result["flow_id"] = str(_integer(record["flow_id"]))
    for key in ("proto", "app_proto", "community_id"):
        if key in record:
            result[key] = _text(record[key], 128)
    if event_type not in SUPPORTED_TYPES:
        return result
    detail = record.get(event_type)
    if not isinstance(detail, dict):
        raise ValueError("Missing EVE event details")
    data = {}
    if event_type == "alert":
        for key in ("signature_id", "gid", "rev", "severity"):
            if key in detail:
                data[key] = _integer(detail[key], 2**32 - 1)
        for key in ("signature", "category", "action"):
            if key in detail:
                data[key] = _text(detail[key])
        if "severity" not in data or "signature_id" not in data:
            raise ValueError("Alert identification is missing")
    elif event_type == "flow":
        for key in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "age"):
            if key in detail:
                data[key] = _integer(detail[key])
        for key in ("start", "end"):
            if key in detail:
                value = datetime.fromisoformat(_text(detail[key], 64))
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("Flow time must include a timezone")
                data[key] = value.astimezone(timezone.utc).isoformat()
        if "start" in data and "end" in data and datetime.fromisoformat(data["start"]) > datetime.fromisoformat(data["end"]):
            raise ValueError("Flow time range is reversed")
        for key in ("state", "reason"):
            if key in detail:
                data[key] = _text(detail[key], 64)
    elif event_type == "dns":
        for key in ("type", "rrtype", "rcode"):
            if key in detail:
                data[key] = _text(detail[key], 64)
        if "id" in detail:
            data["id"] = _integer(detail["id"], 65535)
    elif event_type == "tls":
        for key in ("version", "fingerprint"):
            if key in detail:
                data[key] = _text(detail[key], 128)
    result["details"] = data
    return result
