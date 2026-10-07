"""고유 키 폭풍에서도 활성 제한과 전체 예산이 초기화되지 않는다."""

from unittest.mock import AsyncMock, patch

import pytest

from netwatcher.alerts.rate_limiter import EventBudget, RateLimiter
from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.config import Config
from netwatcher.observability.observation import ObservationService, STAGE_ALERT


def test_key_flood_does_not_reset_live_limits():
    limiter = RateLimiter(max_count=1, max_keys=3)
    assert limiter.allow("original")
    for i in range(10000):
        limiter.allow(str(i))
    limiter.cleanup()
    assert len(limiter._timestamps) == 3
    assert not limiter.allow("original")
    with patch("netwatcher.alerts.rate_limiter.time.time", return_value=10**12):
        assert limiter.allow("new-after-expiry")
        assert len(limiter._timestamps) == 1


def test_reserved_budget_and_exact_window_expiry():
    now = [0.0]
    budget = EventBudget(normal=2, critical_reserve=1, clock=lambda: now[0])
    assert budget.allow()
    assert budget.allow()
    assert not budget.allow()
    assert budget.allow(critical=True)
    for _ in range(10000):
        assert not budget.allow(critical=True)
    assert len(budget._normal) + len(budget._reserved) == 3
    now[0] = 60.0
    assert budget.allow()
    assert not budget._reserved


@pytest.mark.asyncio
async def test_dispatcher_bounds_unique_alert_writes_and_reserves_critical():
    repo = AsyncMock()
    repo.insert.return_value = 1
    observation = ObservationService(sensor_id="budget-test")
    dispatcher = AlertDispatcher(Config({"alerts": {"event_budget": {
        "normal_per_minute": 2, "critical_reserve_per_minute": 1}}}), repo,
                                 observation=observation)
    for i in range(100):
        await dispatcher._process_alert(Alert(engine="scan", severity=Severity.WARNING, title=f"Scan {i}"))
    assert repo.insert.await_count == 2
    await dispatcher._process_alert(Alert(engine="arp_spoof", severity=Severity.CRITICAL, title="Spoof"))
    assert repo.insert.await_count == 3
    await dispatcher._process_alert(Alert(engine="dhcp_rogue", severity=Severity.CRITICAL, title="Rogue"))
    assert repo.insert.await_count == 3
    counts = observation._window.stage(STAGE_ALERT)
    assert counts.received == 102
    assert counts.accepted == 3
    assert counts.suppressed == 99
