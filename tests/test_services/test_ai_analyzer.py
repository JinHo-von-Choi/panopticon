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


import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


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


class TestRunAI:
    """_run_ai() subprocess 실행 및 프로바이더 디스패치 검증."""

    def _make_service(self, provider: str = "copilot") -> AIAnalyzerService:
        cfg_data = {
            "enabled": True,
            "provider": provider,
            "interval_minutes": 15,
            "lookback_minutes": 30,
            "max_events": 50,
            "consecutive_fp_threshold": 2,
            "max_threshold_increase_pct": 20,
            "copilot_timeout_seconds": 5,
        }
        config = MagicMock()
        config.section.return_value = cfg_data
        return AIAnalyzerService(
            config=config,
            event_repo=MagicMock(),
            registry=MagicMock(),
            dispatcher=MagicMock(),
            yaml_editor=MagicMock(),
        )

    @pytest.mark.asyncio
    async def test_copilot_uses_gh_command(self):
        svc = self._make_service(provider="copilot")
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"VERDICT: CONFIRMED_THREAT\n", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            result = await svc._run_ai("some prompt")

        assert result == "VERDICT: CONFIRMED_THREAT\n"
        mock_exec.assert_called_once()
        args = mock_exec.call_args[0]
        assert args[0] == "gh"
        assert args[1] == "copilot"
        assert args[2] == "explain"
        assert args[3] == "some prompt"

    @pytest.mark.asyncio
    async def test_claude_uses_claude_command(self):
        svc = self._make_service(provider="claude")
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"VERDICT: UNCERTAIN\n", b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await svc._run_ai("prompt")

        args = mock_exec.call_args[0]
        assert args[0] == "claude"
        assert args[1] == "-p"
        assert args[2] == "prompt"

    @pytest.mark.asyncio
    async def test_gemini_uses_gemini_command(self):
        svc = self._make_service(provider="gemini")
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"VERDICT: UNCERTAIN\n", b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await svc._run_ai("prompt")

        args = mock_exec.call_args[0]
        assert args[0] == "gemini"
        assert args[1] == "prompt"

    @pytest.mark.asyncio
    async def test_timeout_returns_empty(self):
        svc = self._make_service()

        async def slow_communicate():
            await asyncio.sleep(10)
            return b"", b""

        mock_proc = AsyncMock()
        mock_proc.communicate = slow_communicate
        mock_proc.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await svc._run_ai("prompt")

        assert result == ""

    @pytest.mark.asyncio
    async def test_cli_not_found_returns_empty(self):
        svc = self._make_service()
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("gh not found")):
            result = await svc._run_ai("prompt")
        assert result == ""

    def test_unknown_provider_falls_back_to_copilot(self):
        """알 수 없는 프로바이더는 'copilot'으로 폴백한다."""
        svc = self._make_service(provider="unknown_provider")
        assert svc._provider == "copilot"


class TestBuildPrompt:
    """_build_prompt() 프롬프트 구조 검증."""

    def _make_service(self) -> AIAnalyzerService:
        cfg_data = {
            "enabled": True,
            "interval_minutes": 15,
            "lookback_minutes": 30,
            "max_events": 50,
            "consecutive_fp_threshold": 2,
            "max_threshold_increase_pct": 20,
            "copilot_timeout_seconds": 60,
        }
        config = MagicMock()
        config.section.return_value = cfg_data
        return AIAnalyzerService(
            config=config,
            event_repo=MagicMock(),
            registry=MagicMock(),
            dispatcher=MagicMock(),
            yaml_editor=MagicMock(),
        )

    def test_prompt_contains_verdict_instruction(self):
        svc = self._make_service()
        events = [
            {"id": 1, "engine": "port_scan", "severity": "CRITICAL",
             "title": "Port scan detected", "source_ip": "192.168.1.100",
             "timestamp": "2026-02-27T12:00:00"}
        ]
        prompt = svc._build_prompt(events)
        assert "VERDICT:" in prompt
        assert "CONFIRMED_THREAT" in prompt
        assert "FALSE_POSITIVE" in prompt
        assert "port_scan" in prompt

    def test_prompt_contains_adjust_instruction(self):
        svc = self._make_service()
        prompt = svc._build_prompt([])
        assert "ADJUST:" in prompt


class TestAnalysisLoop:
    """_apply_result() 및 전체 루프 동작 검증."""

    def _make_service(self, fp_threshold: int = 1) -> AIAnalyzerService:
        cfg_data = {
            "enabled": True,
            "interval_minutes": 15,
            "lookback_minutes": 30,
            "max_events": 50,
            "consecutive_fp_threshold": fp_threshold,
            "max_threshold_increase_pct": 20,
            "copilot_timeout_seconds": 60,
        }
        config = MagicMock()
        config.section.return_value = cfg_data
        return AIAnalyzerService(
            config=config,
            event_repo=MagicMock(),
            registry=MagicMock(),
            dispatcher=MagicMock(),
            yaml_editor=MagicMock(),
        )

    @pytest.mark.asyncio
    async def test_confirmed_threat_enqueues_alert(self):
        svc = self._make_service()
        result = AnalysisResult(
            verdict="CONFIRMED_THREAT",
            engine="port_scan",
            reason="Real port scan detected.",
        )
        await svc._apply_result(result)
        svc._dispatcher.enqueue.assert_called_once()
        alert_arg = svc._dispatcher.enqueue.call_args[0][0]
        assert alert_arg.engine == "ai_analyzer"
        assert alert_arg.severity.value == "CRITICAL"

    @pytest.mark.asyncio
    async def test_false_positive_calls_try_adjust(self):
        svc = self._make_service()
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}
        svc._registry.reload_engine.return_value = (True, None, [])
        result = AnalysisResult(
            verdict="FALSE_POSITIVE",
            engine="port_scan",
            reason="Normal scan.",
            adjustments={"threshold": 12.0},
        )
        await svc._apply_result(result)
        svc._yaml_editor.update_engine_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_uncertain_does_nothing(self):
        svc = self._make_service()
        result = AnalysisResult(verdict="UNCERTAIN", engine="dns_anomaly")
        await svc._apply_result(result)
        svc._dispatcher.enqueue.assert_not_called()
        svc._yaml_editor.update_engine_config.assert_not_called()

    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self):
        svc = self._make_service()
        await svc.start()
        assert svc._task is not None
        assert not svc._task.done()
        await svc.stop()
        assert svc._task.done()
