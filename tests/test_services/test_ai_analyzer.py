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
