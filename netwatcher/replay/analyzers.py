"""재현 지원 관측 분석기 3종 (계획서 1장).

    "최초 지원 후보는 arp_spoof · port_scan · data_exfil 세 엔진이며, 각각
     주소 바인딩 변화 · 연결 시도 분포 · 전송량 초과라는 관측 의미를 표시한다.
     악성 여부를 확정하는 엔진으로 포장하지 않는다."

그래서 여기 있는 것은 **판정 엔진이 아니라 관측 함수** 다.

- 입력을 바꾸지 않는다
- 시간을 읽지 않는다 (`contract.now` 만 쓴다)
- 네트워크를 호출하지 않는다
- 결과에 악성 판정을 붙이지 않는다

각 분석기는 "무엇을 보았는가" 만 반환한다. 이 보장이 깨지면 같은 입력의
재실행 결과가 달라지고, 그러면 두 버전 비교라는 문장 자체가 무의미해진다.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Sequence

from netwatcher.replay.contract import (
    OBS_ADDRESS_BINDING,
    OBS_CONNECTION_DISTRIBUTION,
    OBS_TRANSFER_VOLUME,
    AnalysisContract,
    Analyzer,
    Observation,
)

# 기록된 특징값 필드 — trace 가 담아야 하는 최소 집합
F_SRC_IP = "src_ip"
F_DST_IP = "dst_ip"
F_SRC_MAC = "src_mac"
F_DST_MAC = "dst_mac"
F_DST_PORT = "dst_port"
F_BYTES = "bytes"
F_TS = "ts"
F_IP_PROTO = "ip_proto"


def _sorted_unique(values: Sequence[Any]) -> list[Any]:
    """집합을 정렬해 순서 비의존적으로 만든다."""
    out = {v for v in values if v is not None}
    try:
        return sorted(out)
    except TypeError:
        return sorted(out, key=str)


# ------------------------------------------------------------------
# 1) 주소 바인딩 변화 (arp_spoof 계열 관측 의미)
# ------------------------------------------------------------------

def analyze_address_binding(
    records: Sequence[dict], contract: AnalysisContract
) -> list[Observation]:
    """같은 IP 가 서로 다른 MAC 에 응답하거나, MAC 이 IP 를 바꾸는지 본다.

    엔진 이름은 arp_spoof 지만 판정하지 않는다. **바인딩이 바뀌었다**는
    관측까지만 낸다. 그게 공격인지 설정 오류인지 판단은 humans 몫이다.
    """
    threshold = int(contract.param("mac_change_threshold", 1))
    by_ip: dict[str, set[str]] = {}
    by_mac: dict[str, set[str]] = {}
    first_ts: dict[str, float] = {}

    for idx, rec in enumerate(records):
        src_ip, src_mac = rec.get(F_SRC_IP), rec.get(F_SRC_MAC)
        if not src_ip or not src_mac:
            continue
        by_ip.setdefault(src_ip, set()).add(src_mac)
        by_mac.setdefault(src_mac, set()).add(src_ip)
        first_ts.setdefault(f"ip:{src_ip}", float(rec.get(F_TS) or 0.0))
        first_ts.setdefault(f"mac:{src_mac}", float(rec.get(F_TS) or 0.0))

    out: list[Observation] = []
    seq = 0
    for src_ip in sorted(by_ip):
        macs = _sorted_unique(by_ip[src_ip])
        if len(macs) < threshold:
            continue
        seq += 1
        out.append(Observation(
            engine="arp_spoof",
            kind=OBS_ADDRESS_BINDING,
            subject=src_ip,
            features={
                "mac_count": len(macs),
                "macs": macs,
                "record_count": len(records),
            },
            observed_at=first_ts.get(f"ip:{src_ip}", 0.0),
            seq=seq,
        ))

    for src_mac in sorted(by_mac):
        ips = _sorted_unique(by_mac[src_mac])
        if len(ips) < threshold:
            continue
        seq += 1
        out.append(Observation(
            engine="arp_spoof",
            kind=OBS_ADDRESS_BINDING,
            subject=f"mac:{src_mac}",
            features={
                "ip_count": len(ips),
                "ips": ips,
                "record_count": len(records),
            },
            observed_at=first_ts.get(f"mac:{src_mac}", 0.0),
            seq=seq,
        ))
    return out


# ------------------------------------------------------------------
# 2) 연결 시도 분포 (port_scan 계열 관측 의미)
# ------------------------------------------------------------------

def analyze_connection_distribution(
    records: Sequence[dict], contract: AnalysisContract
) -> list[Observation]:
    """한 출발점이 몇 개의 목적지 포트에 접속했는지 분포로 본다."""
    threshold = int(contract.param("threshold", 5))
    by_src: dict[str, list[int]] = {}
    first_ts: dict[str, float] = {}
    counts: dict[str, int] = {}

    for rec in records:
        src, port = rec.get(F_SRC_IP), rec.get(F_DST_PORT)
        if not src or port is None:
            continue
        by_src.setdefault(src, []).append(int(port))
        counts[src] = counts.get(src, 0) + 1
        first_ts.setdefault(src, float(rec.get(F_TS) or 0.0))

    out: list[Observation] = []
    for seq, src in enumerate(sorted(by_src), start=1):
        ports = by_src[src]
        unique_ports = _sorted_unique(ports)
        if len(unique_ports) < threshold:
            continue
        out.append(Observation(
            engine="port_scan",
            kind=OBS_CONNECTION_DISTRIBUTION,
            subject=src,
            features={
                "unique_port_count": len(unique_ports),
                "attempt_count": len(ports),
                # 연속 포트 구간은 스캔 모양의 대리 지표다 (판정은 아님)
                "consecutive_span": _max_consecutive_span(unique_ports),
                "port_sample": unique_ports[:16],
            },
            observed_at=first_ts.get(src, 0.0),
            seq=seq,
        ))
    return out


def _max_consecutive_span(ports: Sequence[int]) -> int:
    """정렬된 포트 목록에서 가장 긴 연속 구간 길이."""
    if not ports:
        return 0
    best = run = 1
    for prev, cur in zip(ports, ports[1:]):
        run = run + 1 if cur == prev + 1 else 1
        best = max(best, run)
    return best


# ------------------------------------------------------------------
# 3) 전송량 초과 (data_exfil 계열 관측 의미)
# ------------------------------------------------------------------

def analyze_transfer_volume(
    records: Sequence[dict], contract: AnalysisContract
) -> list[Observation]:
    """발신량 합계가 임계치를 넘는 관측. 유출 여부는 판정하지 않는다."""
    threshold = int(contract.param("threshold", 1_000_000))
    window = int(contract.param("window_seconds", 300))

    buckets: dict[tuple[str, int], int] = {}
    totals: dict[str, int] = {}
    first_ts: dict[str, float] = {}
    proto_counts: dict[str, Counter] = {}

    for rec in records:
        src = rec.get(F_SRC_IP)
        if not src:
            continue
        nbytes = int(rec.get(F_BYTES) or 0)
        ts = float(rec.get(F_TS) or 0.0)
        bucket = int(ts // window) if window > 0 else 0
        buckets[(src, bucket)] = buckets.get((src, bucket), 0) + nbytes
        totals[src] = totals.get(src, 0) + nbytes
        first_ts.setdefault(src, ts)
        proto_counts.setdefault(src, Counter())[str(rec.get(F_IP_PROTO) or "?")] += nbytes

    out: list[Observation] = []
    seq = 0
    for src in sorted(totals):
        total = totals[src]
        peak_bucket = max(
            (k for k in buckets if k[0] == src), key=lambda k: buckets[k], default=None,
        )
        if total < threshold:
            continue
        seq += 1
        out.append(Observation(
            engine="data_exfil",
            kind=OBS_TRANSFER_VOLUME,
            subject=src,
            features={
                "total_bytes": total,
                "threshold": threshold,
                "window_seconds": window,
                "peak_window_bytes": buckets[peak_bucket] if peak_bucket else 0,
                "proto_breakdown": dict(sorted(proto_counts[src].items())),
            },
            observed_at=first_ts.get(src, 0.0),
            seq=seq,
        ))
    return out


# ------------------------------------------------------------------
# 레지스트리 — 지원 엔진은 이 셋뿐
# ------------------------------------------------------------------

ANALYZERS: dict[str, Analyzer] = {
    "arp_spoof": analyze_address_binding,
    "port_scan": analyze_connection_distribution,
    "data_exfil": analyze_transfer_volume,
}


def get_analyzer(engine: str) -> Analyzer | None:
    """지원하지 않는 엔진이면 None. 없는 분석기를 지어내지 않는다."""
    return ANALYZERS.get(engine)
