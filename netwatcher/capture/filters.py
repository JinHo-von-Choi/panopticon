"""커널 수준 패킷 사전 필터링을 위한 BPF 필터 빌더."""

from __future__ import annotations


def build_bpf_filter(extra: str = "") -> str:
    """BPF 필터 문자열을 생성한다.

    ARP, IP (TCP/UDP/ICMP) 트래픽을 캡처한다.
    사용자 지정 추가 필터가 있으면 결합한다.
    """
    parts = [
        "arp",
        "ip",
        "ip6",
    ]
    base = " or ".join(parts)
    bpf = f"({base})"

    if extra and extra.strip():
        bpf = f"({bpf}) and ({extra.strip()})"

    return bpf
