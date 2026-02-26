"""AIAnalyzerService 단위 테스트."""

from __future__ import annotations

import pytest
from netwatcher.services.ai_analyzer import AIAnalyzerService, AnalysisResult


class TestParseResponse:
    """_parse_response() 파싱 케이스."""

    def _parse(self, text: str) -> AnalysisResult:
        return AIAnalyzerService._parse_response(text)

    def test_confirmed_threat(self):
        text = (
            "VERDICT: CONFIRMED_THREAT\n"
            "ENGINE: port_scan\n"
            "REASON: Multiple SYN packets to 25 distinct ports detected.\n"
        )
        result = self._parse(text)
        assert result.verdict == "CONFIRMED_THREAT"
        assert result.engine == "port_scan"
        assert result.adjustments == {}

    def test_false_positive_with_adjust(self):
        text = (
            "VERDICT: FALSE_POSITIVE\n"
            "ENGINE: dns_anomaly\n"
            "REASON: CDN traffic with high entropy is normal.\n"
            "ADJUST: entropy_threshold=4.2\n"
            "ADJUST: dga_confidence_threshold=0.7\n"
        )
        result = self._parse(text)
        assert result.verdict == "FALSE_POSITIVE"
        assert result.engine == "dns_anomaly"
        assert result.adjustments == {
            "entropy_threshold": 4.2,
            "dga_confidence_threshold": 0.7,
        }

    def test_uncertain(self):
        text = (
            "VERDICT: UNCERTAIN\n"
            "ENGINE: traffic_anomaly\n"
            "REASON: Inconclusive data.\n"
        )
        result = self._parse(text)
        assert result.verdict == "UNCERTAIN"
        assert result.engine == "traffic_anomaly"
        assert result.adjustments == {}

    def test_malformed_returns_uncertain(self):
        result = self._parse("I cannot determine this from the given data.")
        assert result.verdict == "UNCERTAIN"
        assert result.engine == ""
        assert result.adjustments == {}

    def test_adjust_non_numeric_ignored(self):
        text = (
            "VERDICT: FALSE_POSITIVE\n"
            "ENGINE: port_scan\n"
            "REASON: Normal scan.\n"
            "ADJUST: threshold=notanumber\n"
        )
        result = self._parse(text)
        assert result.adjustments == {}

    def test_verdict_case_insensitive(self):
        text = (
            "verdict: confirmed_threat\n"
            "engine: arp_spoof\n"
            "reason: real attack.\n"
        )
        result = self._parse(text)
        assert result.verdict == "CONFIRMED_THREAT"


from unittest.mock import MagicMock


class TestTryAdjustThreshold:
    """_try_adjust_threshold() 연속 카운터 및 상한 캡 검증."""

    def _make_service(self, consecutive_fp_threshold: int = 2,
                      max_pct: int = 20) -> AIAnalyzerService:
        cfg_data = {
            "enabled": True,
            "interval_minutes": 15,
            "lookback_minutes": 30,
            "max_events": 50,
            "consecutive_fp_threshold": consecutive_fp_threshold,
            "max_threshold_increase_pct": max_pct,
            "copilot_timeout_seconds": 60,
        }
        config = MagicMock()
        config.section.return_value = cfg_data
        svc = AIAnalyzerService(
            config=config,
            event_repo=MagicMock(),
            registry=MagicMock(),
            dispatcher=MagicMock(),
            yaml_editor=MagicMock(),
        )
        return svc

    def test_no_adjust_below_threshold(self):
        svc = self._make_service(consecutive_fp_threshold=2)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}
        adjustments = {"threshold": 15}

        svc._try_adjust_threshold("port_scan", adjustments)  # 1회차

        svc._yaml_editor.update_engine_config.assert_not_called()
        svc._registry.reload_engine.assert_not_called()
        assert svc._consecutive_fp["port_scan"] == 1

    def test_adjusts_on_threshold_reached(self):
        svc = self._make_service(consecutive_fp_threshold=2)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}
        svc._registry.reload_engine.return_value = (True, None, [])
        adjustments = {"threshold": 15}

        svc._try_adjust_threshold("port_scan", adjustments)  # 1회차
        svc._try_adjust_threshold("port_scan", adjustments)  # 2회차 → 적용

        svc._yaml_editor.update_engine_config.assert_called_once_with(
            "port_scan", {"threshold": 12.0}  # 10 * 1.2 = 12 (캡: +20%)
        )
        assert svc._consecutive_fp["port_scan"] == 0

    def test_cap_applied(self):
        """requested value가 cap보다 낮으면 requested value 그대로."""
        svc = self._make_service(consecutive_fp_threshold=1, max_pct=50)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}
        svc._registry.reload_engine.return_value = (True, None, [])

        svc._try_adjust_threshold("port_scan", {"threshold": 14})  # 14 < 10*1.5=15

        svc._yaml_editor.update_engine_config.assert_called_once_with(
            "port_scan", {"threshold": 14}
        )

    def test_counter_resets_after_adjust(self):
        svc = self._make_service(consecutive_fp_threshold=1)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}
        svc._registry.reload_engine.return_value = (True, None, [])

        svc._try_adjust_threshold("port_scan", {"threshold": 12})
        assert svc._consecutive_fp.get("port_scan", 0) == 0

    def test_yaml_editor_none_skips_adjust(self):
        """yaml_editor가 None이면 조정 없이 경고만."""
        svc = self._make_service(consecutive_fp_threshold=1)
        svc._yaml_editor = None

        svc._try_adjust_threshold("port_scan", {"threshold": 12})

        svc._registry.reload_engine.assert_not_called()
