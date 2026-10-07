from unittest.mock import AsyncMock

import pytest

from netwatcher.alerts.aggregation import AlertAggregator
from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.config import Config
from netwatcher.detection.evidence import classify_alert


def alert(number=1, severity=Severity.WARNING, **kwargs):
    return Alert(engine="scan", severity=severity, title=f"Scan {number} ports",
                 source_ip="192.0.2.1", dest_ip="192.0.2.2", **kwargs)


def test_dynamic_title_repeats_but_new_stage_target_policy_does_not():
    agg = AlertAggregator()
    agg.register(alert(), 1)
    assert agg.repeat(alert(999))
    for field, value in (("attack_stage", "lateral"), ("policy_version", "v2"), ("detection_type", "exfil")):
        assert not agg.repeat(alert(metadata={field: value}))
    other = alert()
    other.dest_ip = "192.0.2.3"
    assert not agg.repeat(other)
    assert not agg.repeat(alert(severity=Severity.CRITICAL))
    assert len(agg.active) == 0
    assert agg.pending[0].count == 2


def test_unknown_asset_does_not_merge_numbered_titles():
    first, second = alert(), alert(2)
    first.source_ip = second.source_ip = None
    assert AlertAggregator.key(first) != AlertAggregator.key(second)


def test_pipeline_bookkeeping_does_not_invent_detection_evidence():
    a = alert(metadata={"aggregation": {"count": 20}, "evidence": {"status": "complete"},
                        "pcap": {"state": "pending"}, "confidence": 0.8})
    assert "evidence" in classify_alert(a).missing


@pytest.mark.asyncio
async def test_simulated_ten_minute_repeat_count_and_single_update_per_window():
    now = [0]
    agg = AlertAggregator(clock=lambda: now[0])
    repo = AsyncMock()
    total = 0
    for minute in range(10):
        first = alert()
        agg.register(first, minute + 1)
        for _ in range(5999):
            assert agg.repeat(alert())
        now[0] += 60
        assert await agg.flush(repo) == 1
        total += repo.update_aggregates.call_args.args[0][0][1]["count"]
        assert not agg.active and not agg.pending
    assert total == 60000
    assert repo.update_aggregates.await_count == 10


@pytest.mark.asyncio
async def test_failed_flush_retains_absolute_snapshot_for_retry():
    agg = AlertAggregator()
    agg.register(alert(), 1)
    for _ in range(11):
        assert agg.repeat(alert())
    repo = AsyncMock()
    repo.update_aggregates.side_effect = [ConnectionError(), None]
    with pytest.raises(ConnectionError):
        await agg.flush(repo, force=True)
    assert agg.pending[0].count == 12
    assert await agg.flush(repo) == 1
    assert not agg.pending
    assert repo.update_aggregates.call_args_list[0] == repo.update_aggregates.call_args_list[1]


def test_active_and_failed_pending_windows_are_bounded():
    agg = AlertAggregator(max_keys=2)
    for cycle in range(3):
        for source in ("192.0.2.1", "192.0.2.2"):
            a = alert()
            a.source_ip = source
            assert agg.register(a, cycle * 2 + 1)
            assert agg.repeat(a)
        assert not agg.register(alert(metadata={"attack_stage": "extra"}), 99)
        agg.expire(force=True)
        assert len(agg.pending) <= 2
    assert agg.overflow > 0


@pytest.mark.asyncio
async def test_dispatcher_saves_first_and_severity_escalation_without_repeat_io():
    repo = AsyncMock()
    repo.insert.side_effect = [1, 2]
    config = Config({"alerts": {"aggregation": {"enabled": True},
                               "rate_limit": {"max_per_key": 1}}})
    dispatcher = AlertDispatcher(config, repo)
    await dispatcher._process_alert(alert())
    for i in range(100):
        await dispatcher._process_alert(alert(i))
    assert repo.insert.await_count == 1
    await dispatcher._process_alert(alert(severity=Severity.CRITICAL))
    assert repo.insert.await_count == 2
    await dispatcher._aggregator.flush(repo, force=True)
    assert repo.update_aggregates.call_args.args[0][0][1]["count"] == 101


@pytest.mark.asyncio
async def test_real_postgres_absolute_update_preserves_metadata_and_no_double_count(event_repo):
    event_id = await event_repo.insert(engine="scan", severity="WARNING", title="Scan",
                                      metadata={"evidence": {"state": "partial"},
                                                "aggregation": {"count": 1, "window_seconds": 60}})
    summary = {"count": 20, "first_seen": "first", "last_seen": "last", "max_severity": "WARNING"}
    await event_repo.update_aggregates([(event_id, summary)])
    await event_repo.update_aggregates([(event_id, summary)])
    await event_repo.update_aggregates([(event_id, {**summary, "count": 3})])
    data = await event_repo.get_by_id(event_id)
    assert data["metadata"]["aggregation"]["count"] == 20
    assert data["metadata"]["aggregation"]["window_seconds"] == 60
    assert data["metadata"]["evidence"] == {"state": "partial"}
