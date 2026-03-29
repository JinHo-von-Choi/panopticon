"""MITRENavigator 테스트."""

from __future__ import annotations

from netwatcher.hunting.mitre_navigator import (
    MITRENavigator,
    _count_to_color,
    _count_to_score,
)


class TestColorScore:
    def test_zero_count(self):
        assert _count_to_score(0) == 0

    def test_low_count_color(self):
        assert _count_to_color(1) == "#ffe0e0"
        assert _count_to_color(3) == "#ffe0e0"

    def test_medium_count_color(self):
        assert _count_to_color(5) == "#ff9999"

    def test_high_count_color(self):
        assert _count_to_color(20) == "#ff4444"
        assert _count_to_color(50) == "#cc0000"

    def test_very_high_count_color(self):
        assert _count_to_color(100) == "#880000"

    def test_score_brackets(self):
        assert _count_to_score(0) == 0
        assert _count_to_score(1) == 25
        assert _count_to_score(4) == 25
        assert _count_to_score(5) == 50
        assert _count_to_score(20) == 75
        assert _count_to_score(50) == 100


class TestMITRENavigator:
    def setup_method(self):
        self.navigator = MITRENavigator()

    def test_empty_events(self):
        layer = self.navigator.generate_layer([])
        assert layer["name"] == "NetWatcher Coverage"
        assert layer["domain"] == "enterprise-attack"
        assert layer["techniques"] == []

    def test_single_technique(self):
        events = [
            {"mitre_attack_id": "T1046", "engine": "port_scan"},
            {"mitre_attack_id": "T1046", "engine": "port_scan"},
        ]
        layer = self.navigator.generate_layer(events)
        techniques = layer["techniques"]
        assert len(techniques) == 1
        assert techniques[0]["techniqueID"] == "T1046"
        assert techniques[0]["score"] == 25  # 2 detections -> score 25
        assert techniques[0]["comment"] == "Detected 2 time(s)"

    def test_multiple_techniques(self):
        events = [
            {"mitre_attack_id": "T1046"},
            {"mitre_attack_id": "T1557.002"},
            {"mitre_attack_id": "T1071.001"},
            {"mitre_attack_id": "T1071.001"},
        ]
        layer = self.navigator.generate_layer(events, name="Custom Layer")
        assert layer["name"] == "Custom Layer"
        assert len(layer["techniques"]) == 3

    def test_events_without_mitre_id_ignored(self):
        events = [
            {"mitre_attack_id": None},
            {"engine": "port_scan"},
            {"mitre_attack_id": "T1046"},
        ]
        layer = self.navigator.generate_layer(events)
        assert len(layer["techniques"]) == 1

    def test_coverage_gaps_all_uncovered(self):
        gaps = self.navigator.get_coverage_gaps([])
        # 모든 네트워크 관련 기법이 미탐지
        assert len(gaps) > 0
        assert "T1046" in gaps
        assert "T1557" in gaps

    def test_coverage_gaps_some_covered(self):
        events = [
            {"mitre_attack_id": "T1046"},
            {"mitre_attack_id": "T1557"},
        ]
        gaps = self.navigator.get_coverage_gaps(events)
        assert "T1046" not in gaps
        assert "T1557" not in gaps
        # 나머지는 여전히 갭
        assert "T1071" in gaps

    def test_layer_has_required_fields(self):
        layer = self.navigator.generate_layer([])
        assert "versions" in layer
        assert "gradient" in layer
        assert "legendItems" in layer
        assert "filters" in layer
