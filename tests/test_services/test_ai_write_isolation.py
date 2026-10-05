"""AI Analyzer 쓰기 격리 테스트 (PR 03).

계획서의 계약은 명확하다.

    "AI의 설정 쓰기 권한을 실제로 제거한다"
    "제안 전용 경로가 runtime·YAML·방화벽을 바꾸면 출시 중단"

이 파일은 그 계약을 세 층에서 고정한다.

1. **구성 기각** — ``apply_mode: apply`` 로 서비스를 만들 수 없다
2. **소스 부재** — 모듈이 ``update_engine_config`` / ``reload_engine`` 을 호출하지 않는다
3. **제안 payload** — 기록되는 이벤트는 항상 ``status=proposed`` 다
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from netwatcher.services.ai_analyzer import AIAnalyzerService

MODULE_PATH = Path(__file__).resolve().parents[2] / "netwatcher" / "services" / "ai_analyzer.py"


def _make_service(apply_mode: str = "propose", **overrides) -> AIAnalyzerService:
    cfg_data = {
        "enabled": True,
        "apply_mode": apply_mode,
        "interval_minutes": 15,
        "lookback_minutes": 30,
        "max_events": 50,
        "consecutive_fp_threshold": 1,
        "max_threshold_increase_pct": 20,
        "consecutive_mt_threshold": 1,
        "max_threshold_decrease_pct": 10,
        "copilot_timeout_seconds": 60,
    }
    cfg_data.update(overrides)
    config = MagicMock()
    config.section.return_value = cfg_data
    return AIAnalyzerService(
        config=config,
        event_repo=AsyncMock(),
        registry=MagicMock(),
        dispatcher=MagicMock(),
        yaml_editor=MagicMock(),
    )


# ------------------------------------------------------------------
# 1. 구성 기각
# ------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["apply", "auto", "write", "APPLY", ""])
def test_apply_mode_must_be_propose(mode):
    with pytest.raises(ValueError, match="apply_mode"):
        _make_service(apply_mode=mode)


def test_propose_mode_accepted():
    svc = _make_service()
    assert svc._apply_mode == "propose"


def test_default_is_propose_when_absent():
    """키가 없으면 제안 전용이어야 한다."""
    cfg_data = {"enabled": True, "interval_minutes": 15, "copilot_timeout_seconds": 60}
    config = MagicMock()
    config.section.return_value = cfg_data
    svc = AIAnalyzerService(
        config=config, event_repo=AsyncMock(), registry=MagicMock(),
        dispatcher=MagicMock(), yaml_editor=MagicMock(),
    )
    assert svc._apply_mode == "propose"


# ------------------------------------------------------------------
# 2. 소스 수준 부재
# ------------------------------------------------------------------

def _called_attributes(tree: ast.AST) -> set[str]:
    """AST 에서 ``<어떤객체>.<attr>(...)`` 형태의 attr 수집."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                found.add(func.attr)
    return found


def test_module_never_writes_engine_config():
    """모듈 전체에서 update_engine_config 호출이 없어야 한다."""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    assert "update_engine_config" not in _called_attributes(tree)


def test_module_never_reloads_engine():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    assert "reload_engine" not in _called_attributes(tree)


def test_module_never_touches_firewall():
    """제안 경로가 방화벽을 건드리면 출시 중단 사유다."""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    called = _called_attributes(tree)
    assert called.isdisjoint({"block_ip", "add_block", "block", "apply_block"})


# ------------------------------------------------------------------
# 3. 런타임 동작
# ------------------------------------------------------------------

def test_threshold_increase_records_proposal_only():
    svc = _make_service()
    svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}

    svc._try_adjust_threshold("port_scan", {"threshold": 15})

    svc._yaml_editor.update_engine_config.assert_not_called()
    svc._registry.reload_engine.assert_not_called()

    payload = svc._build_proposal("port_scan", {"threshold": 12.0}, "상향", "reason")
    assert payload["metadata"]["status"] == "proposed"
    assert payload["metadata"]["applied"] is False


def test_threshold_decrease_records_proposal_only():
    svc = _make_service()
    svc._yaml_editor.get_engine_config.return_value = {"threshold": 15}

    svc._try_lower_threshold("dns_anomaly", {"entropy_threshold": 3.0})

    svc._yaml_editor.update_engine_config.assert_not_called()
    svc._registry.reload_engine.assert_not_called()


@pytest.mark.asyncio
async def test_proposal_event_is_recorded_through_repository():
    """실제 이벤트 저장 경로가 status=proposed 로 기록되는지 확인한다."""
    import asyncio

    svc = _make_service()
    svc._yaml_editor.get_engine_config.return_value = {"threshold": 10}

    svc._try_adjust_threshold("port_scan", {"threshold": 15})
    await asyncio.sleep(0)  # create_task 된 삽입을 한 번 실행시킨다

    svc._event_repo.insert.assert_awaited_once()
    kwargs = svc._event_repo.insert.await_args.kwargs
    assert kwargs["engine"] == "ai_adjustment"
    assert kwargs["metadata"]["status"] == "proposed"
    assert kwargs["metadata"]["applied"] is False
    assert kwargs["metadata"]["adjusted"] == {"threshold": 12.0}


def test_yaml_editor_none_still_records_proposal():
    """YAML 편집기가 없어도 제안 기록은 동작한다 (비관측 ≠ 무조건 실패)."""
    svc = _make_service()
    svc._yaml_editor = None

    svc._try_adjust_threshold("port_scan", {"threshold": 15})

    assert svc._consecutive_fp["port_scan"] == 0


def test_bool_current_value_is_not_treated_as_number():
    """기존 값이 True 면 bool 을 숫자로 취급하지 않는다."""
    svc = _make_service()
    svc._yaml_editor.get_engine_config.return_value = {"threshold": True}

    with pytest.MonkeyPatch.context() as mp:
        recorded = {}
        mp.setattr(
            svc, "_record_proposal",
            lambda *a: recorded.update(engine=a[0], capped=a[1]),
        )
        svc._try_adjust_threshold("port_scan", {"threshold": 15})

    # bool 을 그대로 쓰지 않고 요청값을 사용한다 (1.0 으로 오인하지 않음)
    assert recorded["capped"] == {"threshold": 15}
