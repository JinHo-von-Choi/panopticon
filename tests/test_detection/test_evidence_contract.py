"""탐지 결과 계약 테스트 (PR 08, 게이트 G8).

계획서의 요구는 세 층이다: **요약 → 근거 → 원자료**.

이 테스트는 두 가지를 고정한다.

1. 판정 규칙이 의도대로 동작한다 (confidence 는 근거로 치지 않는다)
2. **실제 엔진**이 이 세 층을 채워 넣는다 — 합성된 딕셔너리가 아니라 실제
   패킷을 엔진을 통과시켜 얻은 알림으로 검증한다 (G8 게이트의 근거)
"""

from __future__ import annotations

import pytest
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether

from netwatcher.detection.engines.port_scan import PortScanEngine
from netwatcher.detection.evidence import (
    EVIDENCE_LAYERS,
    LAYER_EVIDENCE,
    LAYER_RAW,
    LAYER_SUMMARY,
    apply_evidence_contract,
    classify_alert,
    describe_contract,
)
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.packet_info import extract_packet_info


def _packet_info(pkt) -> dict:
    return extract_packet_info(pkt)


# ------------------------------------------------------------------
# 1. 판정 규칙
# ------------------------------------------------------------------

def test_all_three_layers_present_is_complete():
    a = Alert(
        engine="port_scan", severity=Severity.WARNING, title="스캔", description="설명",
        metadata={"count": 25}, packet_info={"layers": ["IP"], "length": 74},
    )
    report = classify_alert(a)
    assert report.complete is True
    assert report.status == "complete"
    assert report.missing == []


def test_missing_raw_material_is_detected():
    a = Alert(
        engine="port_scan", severity=Severity.WARNING, title="스캔", description="설명",
        metadata={"count": 25}, packet_info={},
    )
    report = classify_alert(a)
    assert LAYER_RAW in report.missing
    assert report.status == "incomplete"


def test_missing_evidence_is_detected():
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={}, packet_info={"layers": ["IP"], "length": 74},
    )
    assert LAYER_EVIDENCE in classify_alert(a).missing


def test_missing_summary_is_detected():
    a = Alert(
        engine="x", severity=Severity.WARNING, title="", description="",
        metadata={"count": 1}, packet_info={"layers": ["IP"], "length": 74},
    )
    assert LAYER_SUMMARY in classify_alert(a).missing


def test_confidence_alone_is_not_evidence():
    """confidence 는 파이프라인이 나중에 붙이는 값이다.

    그것만으로는 "왜 그렇게 판단했는가" 를 설명할 수 없다.
    """
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={"confidence": 0.9}, packet_info={"layers": ["IP"], "length": 74},
    )
    assert LAYER_EVIDENCE in classify_alert(a).missing


def test_empty_packet_info_is_not_raw_material():
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={"count": 1}, packet_info={},
    )
    assert LAYER_RAW in classify_alert(a).missing


def test_packet_info_without_layers_or_length_is_not_raw():
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={"count": 1}, packet_info={"ip_src": "1.1.1.1"},
    )
    assert LAYER_RAW in classify_alert(a).missing


# ------------------------------------------------------------------
# 2. 계약 적용
# ------------------------------------------------------------------

def test_apply_records_report_in_metadata():
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={}, packet_info={"layers": ["IP"], "length": 74},
    )
    report = apply_evidence_contract(a)
    assert a.metadata["evidence"]["status"] == "incomplete"
    assert a.metadata["evidence"]["missing"] == [LAYER_EVIDENCE]
    assert report.missing == [LAYER_EVIDENCE]


def test_apply_does_not_invent_evidence():
    """누락한 근거를 지어내지 않는다 — 감사에 가장 위험한 행동."""
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={}, packet_info={},
    )
    apply_evidence_contract(a)
    # confidence 만은 근거로 채우지 않는다
    assert a.metadata["evidence"]["missing"] == [LAYER_EVIDENCE, LAYER_RAW]
    assert "confidence" not in a.metadata


def test_apply_is_idempotent():
    a = Alert(
        engine="x", severity=Severity.WARNING, title="제목", description="설명",
        metadata={"count": 1}, packet_info={"layers": ["IP"], "length": 74},
    )
    first = apply_evidence_contract(a).as_dict()
    second = apply_evidence_contract(a).as_dict()
    assert first == second


def test_report_is_json_serializable():
    import json
    a = Alert(engine="x", severity=Severity.WARNING, title="t", description="d",
              metadata={"c": 1}, packet_info={"layers": ["IP"], "length": 1})
    apply_evidence_contract(a)
    json.dumps(a.metadata["evidence"])


def test_contract_spec_lists_three_layers():
    spec = describe_contract()
    assert tuple(spec["layers"]) == EVIDENCE_LAYERS
    assert set(spec["layer_meaning"]) == set(EVIDENCE_LAYERS)


# ------------------------------------------------------------------
# 3. 실제 엔진이 세 층을 채우는가 (게이트 G8 의 근거)
# ------------------------------------------------------------------

def _scan_packets(count: int = 10):
    return [
        Ether() / IP(src="8.8.8.8", dst="10.0.0.2")
        / TCP(sport=54321, dport=port, flags="S")
        for port in range(1, count + 1)
    ]


def test_port_scan_alert_satisfies_contract():
    """실제 포트 스캔 탐지 결과가 세 층을 모두 갖는다."""
    engine = PortScanEngine({
        "enabled": True, "window_seconds": 60, "threshold": 5, "stealth_threshold": 3,
    })

    packets = _scan_packets()
    for pkt in packets:
        engine.analyze(pkt)
    alerts = engine.on_tick(0)

    assert alerts, "스캔이 탐지되지 않았다 — 테스트 전제 자체가 깨졌다"
    for alert in alerts:
        # 파이프라인이 해주는 일까지 수행한 뒤 판정한다
        alert.packet_info = extract_packet_info(packets[-1])
        alert.metadata["confidence"] = alert.confidence
        report = classify_alert(alert)
        assert report.complete, (
            f"{alert.engine} 탐지 결과가 계약을 위반한다: 누락={report.missing}"
        )


def test_alert_without_pipeline_enrichment_reports_missing_raw():
    """파이프라인을 거치지 않으면 원자료 층이 비어 있다 — 그대로 드러나야 한다.

    엔진이 스스로 packet_info 를 채우지 않는다는 사실(25개 엔진 전부)이
    드러나는 지점이다. 계약이 이 공백을 감춘다면 오히려 해롭다.
    """
    engine = PortScanEngine({
        "enabled": True, "window_seconds": 60, "threshold": 5, "stealth_threshold": 3,
    })
    for pkt in _scan_packets():
        engine.analyze(pkt)
    alerts = engine.on_tick(0)

    assert alerts
    raw_alert = alerts[0]
    assert raw_alert.packet_info == {}  # 엔진은 채우지 않는다
    report = classify_alert(raw_alert)
    assert LAYER_RAW in report.missing


@pytest.mark.parametrize("layer", EVIDENCE_LAYERS)
def test_each_layer_is_independently_reported(layer):
    """층 하나만 빠져도 그 층 이름이 드러난다."""
    kwargs = {
        "engine": "x", "severity": Severity.WARNING,
        "title": "제목", "description": "설명",
        "metadata": {"count": 3}, "packet_info": {"layers": ["IP"], "length": 74},
    }
    if layer == LAYER_SUMMARY:
        kwargs["title"] = ""
        kwargs["description"] = ""
    elif layer == LAYER_EVIDENCE:
        kwargs["metadata"] = {}
    else:
        kwargs["packet_info"] = {}

    report = classify_alert(Alert(**kwargs))
    assert layer in report.missing
