"""NetFlow v5 파서 단위 테스트."""

import struct
import socket
import pytest

from netwatcher.netflow.models import FlowRecord, Protocol
from netwatcher.netflow.parser import parse_netflow_v5, ParseError


def _make_v5_packet(
    flow_records: list[dict],
    sys_uptime: int = 60000,
    unix_secs: int = 1700000000,
) -> bytes:
    """테스트용 NetFlow v5 UDP 페이로드를 생성한다."""
    count = len(flow_records)
    header = struct.pack(
        "!HHIIIIBBH",
        5,           # version
        count,       # count
        sys_uptime,  # sys_uptime (ms)
        unix_secs,   # unix_secs
        0,           # unix_nsecs
        0,           # flow_sequence
        0,           # engine_type
        0,           # engine_id
        0,           # sampling_interval
    )
    records_bytes = b""
    for r in flow_records:
        src = socket.inet_aton(r["src_ip"])
        dst = socket.inet_aton(r["dst_ip"])
        records_bytes += struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            src,                # srcaddr
            dst,                # dstaddr
            b"\x00\x00\x00\x00",  # nexthop
            r.get("input", 0),  # input
            r.get("output", 0), # output
            r.get("packets", 1),# dPkts
            r.get("bytes", 100),# dOctets
            r.get("start", 59000),  # First (uptime ms)
            r.get("end", 60000),    # Last  (uptime ms)
            r.get("src_port", 54321),
            r.get("dst_port", 80),
            0,                  # pad1
            r.get("tcp_flags", 0x02),  # tcp_flags
            r.get("proto", 6),  # prot (6=TCP)
            r.get("tos", 0),    # tos
            r.get("src_as", 0), # src_as
            r.get("dst_as", 0), # dst_as
            0,                  # src_mask
            0,                  # dst_mask
            0,                  # pad2
        )
    return header + records_bytes


class TestParseNetflowV5:
    def test_single_flow(self):
        raw = _make_v5_packet([{
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "bytes": 1500,
            "packets": 10,
        }])
        flows = parse_netflow_v5(raw)
        assert len(flows) == 1
        f = flows[0]
        assert f.src_ip == "192.168.1.10"
        assert f.dst_ip == "8.8.8.8"
        assert f.dst_port == 443
        assert f.bytes_count == 1500
        assert f.packets_count == 10
        assert f.protocol == Protocol.TCP

    def test_multiple_flows(self):
        raw = _make_v5_packet([
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 22},
            {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "dst_port": 80},
            {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "dst_port": 443},
        ])
        flows = parse_netflow_v5(raw)
        assert len(flows) == 3
        assert flows[0].dst_port == 22
        assert flows[1].dst_port == 80
        assert flows[2].dst_port == 443

    def test_udp_protocol(self):
        raw = _make_v5_packet([{
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "proto": 17,  # UDP
        }])
        flows = parse_netflow_v5(raw)
        assert flows[0].protocol == Protocol.UDP
        assert flows[0].is_udp is True

    def test_wrong_version_raises(self):
        # version=9 패킷이 들어오면 ParseError 발생
        bad_header = struct.pack("!HH", 9, 0) + b"\x00" * 20
        with pytest.raises(ParseError):
            parse_netflow_v5(bad_header)

    def test_too_short_raises(self):
        with pytest.raises(ParseError):
            parse_netflow_v5(b"\x00" * 10)

    def test_empty_flows_ok(self):
        raw = _make_v5_packet([])
        flows = parse_netflow_v5(raw)
        assert flows == []

    def test_duration_ms(self):
        raw = _make_v5_packet([{
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "dst_port": 80, "start": 1000, "end": 3500,
        }])
        flows = parse_netflow_v5(raw)
        assert flows[0].duration_ms == 2500
