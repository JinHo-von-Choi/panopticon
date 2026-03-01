"""동작 프로파일링 기반 탐지: 기준(Baseline) 학습 및 편차 탐지."""

from __future__ import annotations

import logging
import statistics
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.behavior_profile")


class BehaviorProfileEngine(DetectionEngine):
    """호스트별 정상 동작 기준을 학습하고, 이를 벗어나는 활동을 탐지한다.

    - Learning Phase: 설정된 기간 동안 각 호스트의 트래픽 특징(IP 수, 포트 수 등) 학습
    - Deviation Detection: 학습된 기준에서 일정 범위를 벗어나는 급격한 변화 탐지
    """

    name = "behavior_profile"
    description = "호스트별 동작 프로파일링을 수행합니다. 평소와 다른 비정상적인 통신 패턴(새로운 연결지, 평소보다 많은 포트 사용 등)을 식별합니다."
    description_key = "engines.behavior_profile.description"
    config_schema = {
        "learning_period_seconds": {
            "type": int, "default": 3600, "min": 600, "max": 86400,
            "label": "학습 기간(초)",
            "label_key": "engines.behavior_profile.learning_period_seconds.label",
            "description": "정상 기준을 수립하기 위해 학습하는 시간. 이 기간 동안은 알림이 발생하지 않음.",
            "description_key": "engines.behavior_profile.learning_period_seconds.description",
        },
        "deviation_threshold": {
            "type": float, "default": 2.5, "min": 1.5, "max": 5.0,
            "label": "편차 임계값",
            "label_key": "engines.behavior_profile.deviation_threshold.label",
            "description": "정상 범위를 벗어나는 정도(표준편차의 배수). 낮을수록 예민하게 탐지.",
            "description_key": "engines.behavior_profile.deviation_threshold.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._learning_period = config.get("learning_period_seconds", 3600)
        self._threshold = config.get("deviation_threshold", 2.5)
        self._start_time = time.time()

        # src_ip -> feature -> deque of values
        self._profiles: dict[str, dict[str, deque[int]]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=100)))
        # 현재 윈도우 카운터
        self._current: dict[str, dict[str, set[Any]]] = defaultdict(lambda: defaultdict(set))
        self._last_tick = time.time()

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷의 특징을 추출하여 현재 프로필에 기록한다."""
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = packet.getlayer(2).dport if hasattr(packet.getlayer(2), "dport") else 0

        self._current[src_ip]["dst_ips"].add(dst_ip)
        self._current[src_ip]["dst_ports"].add(dport)
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 특징을 요약하고 이상 징후를 평가한다."""
        alerts = []
        now = time.time()
        
        # 1분마다 프로필 업데이트
        if now - self._last_tick >= 60:
            is_learning = (now - self._start_time) < self._learning_period
            
            for src_ip, features in self._current.items():
                for name, values in features.items():
                    count = len(values)
                    history = self._profiles[src_ip][name]
                    
                    if not is_learning and len(history) >= 10:
                        avg = statistics.mean(history)
                        std = statistics.stdev(history)
                        if std > 0:
                            dev = (count - avg) / std
                            if dev > self._threshold:
                                alerts.append(Alert(
                                    engine=self.name,
                                    severity=Severity.WARNING,
                                    title="Host Behavior Deviation Detected",
                                    title_key="engines.behavior_profile.alerts.deviation.title",
                                    description=(
                                        f"Host {src_ip} showing unusual '{name}' pattern: {count} "
                                        f"(Baseline: {avg:.1f}, Dev: {dev:.1f})."
                                    ),
                                    description_key="engines.behavior_profile.alerts.deviation.description",
                                    source_ip=src_ip,
                                    confidence=0.6,
                                    metadata={"feature": name, "value": count, "avg": round(avg, 1), "dev": round(dev, 1)},
                                ))
                    
                    history.append(count)
                features.clear()
            
            self._last_tick = now

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._profiles.clear()
        self._current.clear()
