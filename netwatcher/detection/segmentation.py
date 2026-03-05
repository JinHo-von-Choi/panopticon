"""네트워크 세그먼트 격리 정책 파싱 및 매칭."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SegmentFlow:
    """단일 허용 플로우 규칙."""
    src_net: ipaddress.IPv4Network | ipaddress.IPv6Network
    dst_net: ipaddress.IPv4Network | ipaddress.IPv6Network
    ports:   frozenset[int]  # 빈 set = 모든 포트 허용
    proto:   str             # "tcp", "udp", "any"


def parse_flows(raw: list[dict[str, Any]]) -> list[SegmentFlow]:
    """YAML 설정의 allowed_flows 목록을 SegmentFlow 목록으로 파싱한다.

    각 항목은 src_net, dst_net(필수)과 ports, proto(선택)를 포함한다.
    파싱 불가한 항목은 건너뛴다.
    """
    flows: list[SegmentFlow] = []
    for entry in raw:
        try:
            flows.append(SegmentFlow(
                src_net=ipaddress.ip_network(entry["src_net"], strict=False),
                dst_net=ipaddress.ip_network(entry["dst_net"], strict=False),
                ports=frozenset(int(p) for p in (entry.get("ports") or [])),
                proto=str(entry.get("proto", "any")).lower(),
            ))
        except (KeyError, ValueError):
            continue
    return flows


def is_allowed(
    flows: list[SegmentFlow],
    src_ip: str,
    dst_ip: str,
    dport: int,
    proto: str,
) -> bool:
    """(src_ip, dst_ip, dport, proto) 조합이 허용 목록에 있는지 반환한다.

    flows가 비어 있으면 항상 True(정책 없음 = 통과)를 반환한다.
    IP 파싱 실패 시에도 True를 반환하여 false positive를 방지한다.
    """
    if not flows:
        return True
    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)
    except ValueError:
        return True

    for flow in flows:
        if src not in flow.src_net:
            continue
        if dst not in flow.dst_net:
            continue
        if flow.proto not in ("any", proto):
            continue
        if flow.ports and dport not in flow.ports:
            continue
        return True
    return False
