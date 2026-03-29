"""엔진별 운영 메트릭 수집기.

SLA 모니터(engine_sla.py)와 별개로, 엔진의 알림 수율, 메모리 추정,
오탐/정탐 비율 등 운영 메트릭을 추적한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from prometheus_client import Counter, Gauge


# Prometheus 메트릭 정의
engine_packets_total = Counter(
    "netwatcher_engine_packets_total",
    "Total packets processed per engine",
    ["engine"],
)
engine_alerts_total = Counter(
    "netwatcher_engine_alerts_generated_total",
    "Total alerts generated per engine",
    ["engine"],
)
engine_alert_yield_rate = Gauge(
    "netwatcher_engine_alert_yield_rate",
    "Alerts per 1000 packets per engine",
    ["engine"],
)
engine_memory_estimate_bytes = Gauge(
    "netwatcher_engine_memory_estimate_bytes",
    "Estimated memory usage per engine (bytes)",
    ["engine"],
)
engine_fp_rate = Gauge(
    "netwatcher_engine_fp_rate",
    "False positive rate per engine (0.0-1.0)",
    ["engine"],
)
engine_tp_rate = Gauge(
    "netwatcher_engine_tp_rate",
    "True positive rate per engine (0.0-1.0)",
    ["engine"],
)


@dataclass
class _EngineMetric:
    """단일 엔진의 운영 메트릭 데이터."""

    packet_count: int = 0
    alert_count: int = 0
    fp_count: int = 0
    tp_count: int = 0
    memory_bytes: int = 0


class EngineMetricsCollector:
    """엔진별 운영 메트릭을 수집하고 조회한다.

    Usage:
        collector = EngineMetricsCollector()
        collector.record_packet("arp_spoof")
        collector.record_alert("arp_spoof")
        metrics = collector.get_metrics("arp_spoof")
    """

    def __init__(self) -> None:
        self._metrics: dict[str, _EngineMetric] = defaultdict(_EngineMetric)

    def record_packet(self, engine_name: str) -> None:
        """엔진이 패킷을 처리했음을 기록한다.

        Args:
            engine_name: 엔진 이름.
        """
        self._metrics[engine_name].packet_count += 1
        engine_packets_total.labels(engine=engine_name).inc()

    def record_alert(self, engine_name: str) -> None:
        """엔진이 알림을 생성했음을 기록한다.

        Args:
            engine_name: 엔진 이름.
        """
        m = self._metrics[engine_name]
        m.alert_count += 1
        engine_alerts_total.labels(engine=engine_name).inc()

        # yield rate 갱신
        if m.packet_count > 0:
            rate = (m.alert_count / m.packet_count) * 1000
            engine_alert_yield_rate.labels(engine=engine_name).set(rate)

    def record_feedback(
        self, engine_name: str, *, is_true_positive: bool,
    ) -> None:
        """AI 분석기 피드백을 기록한다.

        Args:
            engine_name: 엔진 이름.
            is_true_positive: True면 정탐, False면 오탐.
        """
        m = self._metrics[engine_name]
        if is_true_positive:
            m.tp_count += 1
        else:
            m.fp_count += 1

        total_feedback = m.tp_count + m.fp_count
        if total_feedback > 0:
            fp_r = m.fp_count / total_feedback
            tp_r = m.tp_count / total_feedback
            engine_fp_rate.labels(engine=engine_name).set(fp_r)
            engine_tp_rate.labels(engine=engine_name).set(tp_r)

    def update_memory_estimate(self, engine_name: str, engine_obj: Any) -> None:
        """엔진 객체의 대략적 메모리 사용량을 추정한다.

        sys.getsizeof로 얕은 크기를 측정한다.
        정확한 측정이 아닌 참고용 추정치이다.

        Args:
            engine_name: 엔진 이름.
            engine_obj: 엔진 인스턴스.
        """
        try:
            size = sys.getsizeof(engine_obj)
            # __dict__가 있으면 속성들의 크기도 합산
            if hasattr(engine_obj, "__dict__"):
                for v in engine_obj.__dict__.values():
                    size += sys.getsizeof(v)
            self._metrics[engine_name].memory_bytes = size
            engine_memory_estimate_bytes.labels(engine=engine_name).set(size)
        except (TypeError, AttributeError):
            pass

    def get_metrics(self, engine_name: str) -> dict[str, Any]:
        """단일 엔진의 운영 메트릭을 반환한다.

        Args:
            engine_name: 엔진 이름.

        Returns:
            메트릭 딕셔너리.
        """
        m = self._metrics.get(engine_name)
        if m is None:
            return {}

        total_feedback = m.tp_count + m.fp_count
        yield_rate     = (m.alert_count / m.packet_count * 1000) if m.packet_count > 0 else 0.0
        fp_r           = (m.fp_count / total_feedback) if total_feedback > 0 else None
        tp_r           = (m.tp_count / total_feedback) if total_feedback > 0 else None

        return {
            "packet_count":   m.packet_count,
            "alert_count":    m.alert_count,
            "alert_yield_rate": round(yield_rate, 4),
            "memory_bytes":   m.memory_bytes,
            "fp_count":       m.fp_count,
            "tp_count":       m.tp_count,
            "fp_rate":        round(fp_r, 4) if fp_r is not None else None,
            "tp_rate":        round(tp_r, 4) if tp_r is not None else None,
        }

    def get_all_metrics(self) -> dict[str, dict[str, Any]]:
        """모든 엔진의 운영 메트릭을 반환한다."""
        return {name: self.get_metrics(name) for name in self._metrics}
