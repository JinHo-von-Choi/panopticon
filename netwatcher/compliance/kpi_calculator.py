"""탐지 효과성 KPI 계산.

이벤트 데이터로부터 MTTD, 알림 볼륨, 심각도 분포, 엔진별 상위 탐지,
일별 추세 등 핵심 성과 지표를 산출한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from netwatcher.storage.repositories import EventRepository


class KPICalculator:
    """탐지 효과성 KPI를 계산한다."""

    def __init__(self, event_repo: EventRepository) -> None:
        self._event_repo = event_repo

    async def calculate(self, days: int = 30) -> dict[str, Any]:
        """지정된 기간의 KPI를 계산하여 반환한다.

        Args:
            days: 분석 대상 기간(일).

        Returns:
            mean_alert_interval_seconds, alert_volume, severity_distribution, top_engines,
            trend, coverage_score 등을 포함하는 dict.
        """
        since = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()

        # 총 알림 수
        alert_volume = await self._event_repo.count(since=since)

        # 심각도별 분포
        severity_dist = await self._event_repo.count_by_severity_since(since)

        # 엔진별 탐지 수 (상위 10개)
        engine_counts = await self._event_repo.count_by_engine_since(since)
        top_engines   = [
            {"engine": name, "count": cnt}
            for name, cnt in list(engine_counts.items())[:10]
        ]

        # 일별 추세: 최근 events를 집계하여 일별 카운트 산출
        trend = await self._compute_daily_trend(since, days)

        # MTTD 추정: 동일 source_ip의 연속 이벤트 간 평균 간격
        interval = await self._mean_alert_interval(since)

        # 상위 출발지 IP
        top_sources = await self._event_repo.top_sources_since(since, limit=5)

        return {
            "period_days":          days,
            "alert_volume":         alert_volume,
            "severity_distribution": severity_dist,
            "top_engines":          top_engines,
            "top_sources":          top_sources,
            "trend":                trend,
            "mean_alert_interval_seconds": interval,
            "alerts_per_day":       round(alert_volume / max(days, 1), 2),
        }

    async def _compute_daily_trend(
        self, since: str, days: int,
    ) -> list[dict[str, Any]]:
        """UTC 날짜별 알림 수를 DB에서 잘림 없이 집계한다."""
        daily = await self._event_repo.count_by_day_since(since)
        return [
            {"date": k, "count": v}
            for k, v in sorted(daily.items())
        ]

    async def _mean_alert_interval(self, since: str) -> float | None:
        """최근 CRITICAL(부족하면 WARNING) 경보 사이의 평균 간격(초).

        공격 시작부터 탐지까지의 시간(MTTD)이 아니다. 데이터 부족 시 None.
        """
        events = await self._event_repo.list_recent(
            limit=500, since=since, severity="CRITICAL",
        )
        if len(events) < 2:
            # WARNING도 포함하여 재시도
            events = await self._event_repo.list_recent(
                limit=500, since=since, severity="WARNING",
            )
        if len(events) < 2:
            return None

        timestamps: list[datetime] = []
        for evt in events:
            ts = evt.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)

        if len(timestamps) < 2:
            return None

        timestamps.sort()
        deltas = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        return round(sum(deltas) / len(deltas), 2) if deltas else None
