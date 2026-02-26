"""AIAnalyzerService — GitHub Copilot CLI 기반 오탐률 자동 감소 서비스.

주기적으로 CRITICAL/WARNING 이벤트를 배치 분석하여:
- CONFIRMED_THREAT: 알림 재전송 (rate limit 우회)
- FALSE_POSITIVE:   엔진 임계값 자동 상향 + 핫리로드
- UNCERTAIN:        로그 기록만

작성자: 최진호
작성일: 2026-02-27
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.storage.repositories import EventRepository
    from netwatcher.utils.config import Config
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger("netwatcher.services.ai_analyzer")


@dataclass
class AnalysisResult:
    """Copilot 응답 파싱 결과."""

    verdict:     str              # CONFIRMED_THREAT | FALSE_POSITIVE | UNCERTAIN
    engine:      str              # 대상 엔진 이름
    reason:      str = ""
    adjustments: dict[str, float] = field(default_factory=dict)


class AIAnalyzerService:
    """GitHub Copilot CLI 기반 오탐률 자동 감소 서비스."""

    # ------------------------------------------------------------------ #
    # 파싱                                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_response(text: str) -> AnalysisResult:
        """Copilot 응답 텍스트에서 구조화된 결과를 추출한다.

        파싱 실패 시 verdict='UNCERTAIN', engine='' 를 반환한다.
        """
        upper = text.upper()

        # VERDICT
        verdict = "UNCERTAIN"
        for candidate in ("CONFIRMED_THREAT", "FALSE_POSITIVE", "UNCERTAIN"):
            if candidate in upper:
                verdict = candidate
                break

        # ENGINE
        engine = ""
        engine_match = re.search(r"(?i)^ENGINE:\s*(\S+)", text, re.MULTILINE)
        if engine_match:
            engine = engine_match.group(1).strip()

        # REASON
        reason = ""
        reason_match = re.search(r"(?i)^REASON:\s*(.+)", text, re.MULTILINE)
        if reason_match:
            reason = reason_match.group(1).strip()

        # ADJUST  (여러 줄 가능)
        adjustments: dict[str, float] = {}
        for m in re.finditer(r"(?i)^ADJUST:\s*(\w+)=([\d.]+)", text, re.MULTILINE):
            key, raw = m.group(1), m.group(2)
            try:
                adjustments[key] = float(raw)
            except ValueError:
                logger.warning("ADJUST 파싱 실패: %s=%s", key, raw)

        return AnalysisResult(
            verdict=verdict,
            engine=engine,
            reason=reason,
            adjustments=adjustments,
        )
