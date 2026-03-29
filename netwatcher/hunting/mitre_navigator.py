"""MITRE ATT&CK Navigator 레이어 JSON 생성기."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from netwatcher.detection.attack_mapping import TTP_REGISTRY, KILL_CHAIN_ORDER

logger = logging.getLogger("netwatcher.hunting.mitre_navigator")

# Enterprise ATT&CK 주요 기법 목록 (탐지 커버리지 갭 분석용)
# 전체 목록이 아닌 네트워크 관련 주요 기법만 포함
_NETWORK_RELEVANT_TECHNIQUES: set[str] = {
    "T1046", "T1018", "T1595", "T1590",
    "T1190", "T1133",
    "T1036", "T1036.005",
    "T1557", "T1557.002", "T1557.003",
    "T1021", "T1599",
    "T1030", "T1041", "T1048",
    "T1071", "T1071.001", "T1071.004",
    "T1573", "T1571", "T1568",
    "T1486", "T1498",
}

# 탐지 횟수 -> 색상 매핑 (빨간색 계열, 높을수록 진함)
_COLOR_SCALE: list[tuple[int, str]] = [
    (1, "#ffe0e0"),
    (5, "#ff9999"),
    (20, "#ff4444"),
    (50, "#cc0000"),
    (100, "#880000"),
]


def _count_to_color(count: int) -> str:
    """탐지 횟수를 Navigator 색상으로 변환한다."""
    color = "#ffffff"
    for threshold, c in _COLOR_SCALE:
        if count >= threshold:
            color = c
    return color


def _count_to_score(count: int) -> int:
    """탐지 횟수를 0-100 점수로 변환한다."""
    if count == 0:
        return 0
    if count < 5:
        return 25
    if count < 20:
        return 50
    if count < 50:
        return 75
    return 100


class MITRENavigator:
    """MITRE ATT&CK Navigator 레이어 JSON을 생성한다."""

    def generate_layer(
        self,
        events: list[dict[str, Any]],
        name: str = "NetWatcher Coverage",
    ) -> dict[str, Any]:
        """탐지 이벤트 목록에서 Navigator 레이어 JSON을 생성한다.

        각 technique의 색상은 탐지 횟수에 비례한다.
        """
        technique_counts = self._count_techniques(events)

        techniques: list[dict[str, Any]] = []
        for tid, count in technique_counts.items():
            ttp_info = TTP_REGISTRY.get(tid)
            techniques.append({
                "techniqueID": tid,
                "tactic": ttp_info.tactic if ttp_info else "",
                "color": _count_to_color(count),
                "score": _count_to_score(count),
                "comment": f"Detected {count} time(s)",
                "enabled": True,
                "showSubtechniques": False,
            })

        layer: dict[str, Any] = {
            "name": name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"Auto-generated from {len(events)} events",
            "filters": {"platforms": ["Linux", "macOS", "Windows", "Network"]},
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff4444"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "1-4 detections", "color": "#ffe0e0"},
                {"label": "5-19 detections", "color": "#ff9999"},
                {"label": "20-49 detections", "color": "#ff4444"},
                {"label": "50-99 detections", "color": "#cc0000"},
                {"label": "100+ detections", "color": "#880000"},
            ],
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
        }

        return layer

    def get_coverage_gaps(self, events: list[dict[str, Any]]) -> list[str]:
        """이벤트에서 탐지되지 않은 네트워크 관련 기법 ID를 반환한다."""
        covered = set(self._count_techniques(events).keys())
        gaps = _NETWORK_RELEVANT_TECHNIQUES - covered
        return sorted(gaps)

    def _count_techniques(self, events: list[dict[str, Any]]) -> dict[str, int]:
        """이벤트 목록에서 MITRE ATT&CK technique ID별 횟수를 집계한다."""
        counter: Counter[str] = Counter()
        for ev in events:
            tid = ev.get("mitre_attack_id")
            if tid:
                counter[tid] += 1
        return dict(counter)
