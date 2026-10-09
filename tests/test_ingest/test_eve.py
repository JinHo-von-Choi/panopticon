"""EVE 입력의 식별·시간·크기·개인정보 경계를 검증한다."""

import json
from datetime import datetime, timezone

import pytest

from netwatcher.ingest.eve import MAX_LINE_BYTES, decode_eve_line

LOCATION = dict(source_id="office-eve", sensor_id="sensor-1",
                generation="b7efc751-e224-4ffc-bb1a-8e1c9fd96e96", offset=0)


def decode(record, **changes):
    return decode_eve_line(json.dumps(record).encode(), **(LOCATION | changes),
                           received_at=datetime(2026, 10, 8, tzinfo=timezone.utc))


def alert():
    return {"timestamp": "2026-10-08T10:00:00+0900", "event_type": "alert",
            "flow_id": 2**63 + 10, "src_ip": "192.0.2.10", "dest_ip": "2001:db8::1",
            "alert": {"signature_id": 100, "severity": 2, "signature": "Test alert"}}


def test_restart_identity_and_large_flow_id_are_preserved():
    first = decode(alert())
    assert first == decode(alert())
    assert first["ingest_id"] != decode(alert(), offset=100)["ingest_id"]
    assert first["ingest_id"] != decode(alert(), sensor_id="sensor-2")["ingest_id"]
    assert first["flow_id"] == str(2**63 + 10)
    assert first["observed_at"] == "2026-10-08T01:00:00+00:00"
    assert first["details"]["severity"] == 2


@pytest.mark.parametrize("kind,detail", [
    ("alert", {"signature_id": 1, "severity": 1, "payload": "private"}),
    ("dns", {"rrname": "private.example", "rrtype": "A", "answers": [{"rdata": "private"}]}),
    ("tls", {"sni": "private.example", "subject": "private", "version": "TLS 1.3"}),
    ("flow", {"bytes_toserver": 10, "private": "private"}),
    ("http", {"url": "/private", "request_headers": [{"Authorization": "private"}]}),
])
def test_private_protocol_content_is_not_copied(kind, detail):
    result = decode({"timestamp": alert()["timestamp"], "event_type": kind, kind: detail})
    assert "private" not in json.dumps(result)
    assert result["supported"] == (kind != "http")
    assert len(result["original_ref"]["sha256"]) == 64


@pytest.mark.parametrize("changes", [
    {"timestamp": "2026-10-08T10:00:00"}, {"flow_id": True},
    {"src_ip": "invalid"}, {"src_port": 65536}, {"alert": []},
])
def test_invalid_records_are_rejected(changes):
    with pytest.raises(ValueError):
        decode(alert() | changes)


def test_input_size_and_nonfinite_numbers_are_rejected():
    with pytest.raises(ValueError):
        decode_eve_line(b" " * (MAX_LINE_BYTES + 1), **LOCATION)
    with pytest.raises(ValueError):
        decode_eve_line(b'{"unexpected":NaN}', **LOCATION)


def test_optional_ethernet_identity_is_preserved_without_inference():
    record = alert() | {"ether": {"src_mac": "02:AA:00:00:00:01", "dest_mac": "FF:FF:FF:FF:FF:FF"}}
    result = decode(record)
    assert result["src_mac"] == "02:aa:00:00:00:01"
    assert result["dest_mac"] == "ff:ff:ff:ff:ff:ff"
    assert "src_mac" not in decode(alert())


@pytest.mark.parametrize("ether", [None, [], {"src_mac": "invalid"}, {"dest_mac": "02:00:00:00:00:01:02"}])
def test_invalid_ethernet_identity_is_rejected(ether):
    with pytest.raises(ValueError):
        decode(alert() | {"ether": ether})


def test_flow_range_and_mac_lists_are_normalized_without_identity_inference():
    result = decode({"timestamp": alert()["timestamp"], "event_type": "flow",
        "flow": {"start": "2026-10-08T10:00:00.1+0900", "end": "2026-10-08T10:00:01+0900"},
        "ether": {"src_macs": ["02:AA:00:00:00:01"]}})
    assert result["details"]["start"] == "2026-10-08T01:00:00.100000+00:00"
    assert result["src_macs"] == ["02:aa:00:00:00:01"]
    assert "src_mac" not in result


@pytest.mark.parametrize("flow", [
    {"start": "2026-10-08T01:00:00.1+00:00", "end": "2026-10-08T01:00:00+00:00"},
    {"start": "2026-10-08T01:00:00"}, {"end": "invalid"},
])
def test_invalid_flow_time_range_is_rejected(flow):
    with pytest.raises(ValueError):
        decode({"timestamp": alert()["timestamp"], "event_type": "flow", "flow": flow})


@pytest.mark.parametrize("values", [[], "02:00:00:00:00:01", ["invalid"], [None],
                                       ["02:00:00:00:00:01"] * 9])
def test_invalid_mac_lists_are_rejected(values):
    with pytest.raises(ValueError):
        decode(alert() | {"ether": {"src_macs": values}})
