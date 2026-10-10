"""센서 운영 표본: cgroup 읽기, 저장·정리, 재시작 경계의 증분."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

import pytest

from netwatcher.services.sensor_sampler import SensorSampler, read_cgroup


def test_read_cgroup_values_and_missing_files(tmp_path):
    (tmp_path / "cpu.stat").write_text("usage_usec 5000000\nthrottled_usec 2000000\nnr_periods 10\n")
    (tmp_path / "memory.events").write_text("low 0\nhigh 7\nmax 0\n")
    (tmp_path / "memory.current").write_text("402653184\n")
    assert read_cgroup(tmp_path) == {"cpu_usage_usec": 5000000, "cpu_throttled_usec": 2000000,
                                     "memory_current": 402653184, "memory_high_events": 7}
    empty = tmp_path / "empty"
    empty.mkdir()
    # 읽지 못한 값은 0으로 꾸미지 않는다.
    assert set(read_cgroup(empty).values()) == {None}
    assert set(read_cgroup(None).values()) == {None}


def test_interval_bounds():
    with pytest.raises(ValueError):
        SensorSampler(None, "s", interval=1)


@pytest.mark.asyncio
async def test_samples_store_prune_and_record_lease_time(db):
    sampler = SensorSampler(db, "sensor-a", SimpleNamespace(last_publish_ms=12.5), interval=30, retention_days=7)
    row = sampler.sample(3.0)
    assert row["lease_publish_ms"] == 12.5 and row["loop_lag_ms"] == 3.0
    await sampler.store(row)
    await sampler.store(row | {"sampled_at": datetime.now(timezone.utc) - timedelta(days=8)})
    await sampler.prune()
    rows = await db.pool.fetch("SELECT lease_publish_ms FROM sensor_samples WHERE sensor_id='sensor-a'")
    assert [r["lease_publish_ms"] for r in rows] == [12.5]


@pytest.mark.asyncio
async def test_cpu_panel_counts_increments_within_each_boot(db):
    from netwatcher.observability.panels import PANELS
    start = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)
    first, second = uuid.uuid4(), uuid.uuid4()
    # 첫 기동은 10초분 사용, 재시작 후 카운터가 0부터 다시 올라 4초분 사용.
    for boot, minute, used in ((first, 0, 100_000_000), (first, 1, 110_000_000), (second, 2, 1_000_000), (second, 3, 5_000_000)):
        await db.pool.execute(
            "INSERT INTO sensor_samples(sensor_id, boot_id, sampled_at, cpu_usage_usec, cpu_throttled_usec, memory_high_events) "
            "VALUES('s', $1, $2, $3, 0, 0)", boot, start + timedelta(minutes=minute), used)
    rows = await db.pool.fetch(PANELS["sensor_cpu"].sql, start, start + timedelta(hours=1), 3600.0)
    used = sum(row["value"] for row in rows if row["series"] == "cpu_used_s")
    assert used == pytest.approx(14.0)
    assert all(row["value"] >= 0 for row in rows)
