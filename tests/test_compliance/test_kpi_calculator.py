"""KPICalculator 단위 테스트 (모의 EventRepository 사용)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from netwatcher.compliance.kpi_calculator import KPICalculator


def _make_event(
    engine: str = "port_scan",
    severity: str = "WARNING",
    ts_offset_hours: int = 0,
) -> dict:
    """테스트용 이벤트 dict를 생성한다."""
    ts = datetime.now(timezone.utc) - timedelta(hours=ts_offset_hours)
    return {
        "id": 1,
        "engine": engine,
        "severity": severity,
        "title": "Test event",
        "description": "",
        "source_ip": "192.168.1.100",
        "timestamp": ts,
    }


@pytest.fixture
def mock_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.count = AsyncMock(return_value=150)
    repo.count_by_severity_since = AsyncMock(
        return_value={"CRITICAL": 10, "WARNING": 90, "INFO": 50},
    )
    repo.count_by_engine_since = AsyncMock(
        return_value={
            "port_scan": 60,
            "dns_anomaly": 40,
            "threat_intel": 30,
            "arp_spoof": 20,
        },
    )
    repo.top_sources_since = AsyncMock(
        return_value=[
            {"ip": "192.168.1.100", "count": 50},
            {"ip": "10.0.0.5", "count": 30},
        ],
    )
    # list_recent: 시간순 이벤트 (MTTD 계산용)
    events = [
        _make_event(severity="CRITICAL", ts_offset_hours=i)
        for i in range(10)
    ]
    repo.list_recent = AsyncMock(return_value=events)
    return repo


@pytest.mark.asyncio
async def test_calculate_returns_all_keys(mock_repo: AsyncMock):
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=30)

    assert result["period_days"] == 30
    assert result["alert_volume"] == 150
    assert result["alerts_per_day"] == 5.0
    assert "severity_distribution" in result
    assert "top_engines" in result
    assert "top_sources" in result
    assert "trend" in result
    assert "mttd_seconds" in result


@pytest.mark.asyncio
async def test_severity_distribution(mock_repo: AsyncMock):
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=7)

    dist = result["severity_distribution"]
    assert dist["CRITICAL"] == 10
    assert dist["WARNING"] == 90


@pytest.mark.asyncio
async def test_top_engines_limited(mock_repo: AsyncMock):
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=30)

    top = result["top_engines"]
    assert len(top) == 4
    assert top[0]["engine"] == "port_scan"
    assert top[0]["count"] == 60


@pytest.mark.asyncio
async def test_mttd_calculation(mock_repo: AsyncMock):
    """이벤트 간 평균 간격이 MTTD로 반환되는지 확인한다."""
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=30)

    mttd = result["mttd_seconds"]
    assert mttd is not None
    # 10개 이벤트, 각 1시간 간격 -> 평균 3600초
    assert 3500 <= mttd <= 3700


@pytest.mark.asyncio
async def test_mttd_none_when_insufficient_data(mock_repo: AsyncMock):
    """이벤트가 부족하면 MTTD가 None이다."""
    mock_repo.list_recent = AsyncMock(return_value=[])
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=30)

    assert result["mttd_seconds"] is None


@pytest.mark.asyncio
async def test_daily_trend_computation(mock_repo: AsyncMock):
    """일별 추세가 날짜-카운트 쌍으로 반환되는지 확인한다."""
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=30)

    trend = result["trend"]
    assert isinstance(trend, list)
    for entry in trend:
        assert "date" in entry
        assert "count" in entry


@pytest.mark.asyncio
async def test_zero_days_no_division_error(mock_repo: AsyncMock):
    """days=1일 때 0 나누기 오류가 발생하지 않아야 한다."""
    mock_repo.count = AsyncMock(return_value=0)
    calc   = KPICalculator(mock_repo)
    result = await calc.calculate(days=1)
    assert result["alerts_per_day"] == 0.0
