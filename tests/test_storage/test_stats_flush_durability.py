import uuid
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import asyncpg

from netwatcher.services.stats_flush import StatsFlushService
from netwatcher.utils.config import Config


def processor():
    return SimpleNamespace(
        snapshot_and_reset_counters=lambda: {"total_packets": 10, "total_bytes": 400,
            "tcp_count": 10, "udp_count": 0, "arp_count": 0, "dns_count": 0, "distinct_src_macs": 1},
        drain_device_buffer=lambda: {"02:00:00:00:00:01": {"ip": "192.0.2.1", "packets": 10, "bytes": 400}},
    )


@pytest.mark.asyncio
async def test_failed_snapshots_retry_same_id_and_do_not_reset_more_input():
    source = processor()
    snapshot = source.snapshot_and_reset_counters
    calls = []
    source.snapshot_and_reset_counters = lambda: (calls.append(1), snapshot())[1]
    stats = SimpleNamespace(insert_snapshot=AsyncMock(side_effect=[ConnectionError(), None]))
    devices = SimpleNamespace(batch_upsert=AsyncMock(side_effect=[ConnectionError(), None]), count=AsyncMock(return_value=1))
    service = StatsFlushService(Config({}), stats, devices, source)
    await service.flush_once()
    assert service._pending_stats is not None and service._pending_devices is not None
    await service.flush_once()
    assert service._pending_stats is None and service._pending_devices is None
    assert len(calls) == 1
    assert stats.insert_snapshot.call_args_list[0] == stats.insert_snapshot.call_args_list[1]
    assert devices.batch_upsert.call_args_list[0] == devices.batch_upsert.call_args_list[1]


@pytest.mark.asyncio
async def test_real_commit_then_lost_response_does_not_duplicate_stats_or_devices(stats_repo, device_repo):
    original_stats = stats_repo.insert_snapshot
    original_devices = device_repo.batch_upsert
    first_stats, first_devices = [True], [True]
    async def uncertain_stats(**kwargs):
        await original_stats(**kwargs)
        if first_stats and first_stats.pop():
            raise ConnectionError("commit acknowledgement lost")
    async def uncertain_devices(batch, **kwargs):
        await original_devices(batch, **kwargs)
        if first_devices and first_devices.pop():
            raise ConnectionError("commit acknowledgement lost")
    stats_repo.insert_snapshot = uncertain_stats
    device_repo.batch_upsert = uncertain_devices
    service = StatsFlushService(Config({}), stats_repo, device_repo, processor())
    await service.flush_once()
    assert service._pending_stats is not None and service._pending_devices is not None
    await service.flush_once()
    assert (await stats_repo.summary())["total_packets"] == 10
    device = await device_repo.get_by_mac("02:00:00:00:00:01")
    assert device["total_packets"] == 10
    assert device["total_bytes"] == 400
    assert service._pending_stats is None and service._pending_devices is None


@pytest.mark.asyncio
async def test_receipt_is_rolled_back_with_failed_device_transaction(device_repo, db):
    flush_id = uuid.uuid4()
    with pytest.raises(asyncpg.PostgresError):
        await device_repo.batch_upsert({"invalid-mac": {"packets": 1}}, flush_id=flush_id)
    async with db.pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM flush_receipts WHERE flush_id=$1", flush_id) == 0
    await device_repo.batch_upsert({"02:00:00:00:00:01": {"packets": 1, "bytes": 40}}, flush_id=flush_id)
    await device_repo.batch_upsert({"02:00:00:00:00:01": {"packets": 1, "bytes": 40}}, flush_id=flush_id)
    assert (await device_repo.get_by_mac("02:00:00:00:00:01"))["total_packets"] == 1


@pytest.mark.asyncio
async def test_expired_unconfirmed_counts_are_reported_separately_by_stage():
    stats = SimpleNamespace(insert_snapshot=AsyncMock(side_effect=ConnectionError()))
    devices = SimpleNamespace(batch_upsert=AsyncMock(side_effect=ConnectionError()))
    service = StatsFlushService(Config({"storage": {"max_pending_age_seconds": 1}}), stats, devices, processor())
    await service.flush_once()
    first_id = service._pending_stats[1]
    for attr in ("_pending_stats", "_pending_devices"):
        pending = getattr(service, attr)
        setattr(service, attr, (time.monotonic() - 2, *pending[1:]))
    await service.flush_once()
    assert service._pending_stats[1] != first_id
    assert service.status()["unconfirmed_packets"] == {"traffic_stats": 10, "devices": 10}
    assert service.status()["status"] == "degraded"


@pytest.mark.asyncio
async def test_optional_device_gauge_failure_does_not_retry_confirmed_snapshot():
    stats = SimpleNamespace(insert_snapshot=AsyncMock())
    devices = SimpleNamespace(batch_upsert=AsyncMock(), count=AsyncMock(side_effect=ConnectionError()))
    service = StatsFlushService(Config({}), stats, devices, processor())
    await service.flush_once()
    assert service._pending_devices is None
    assert service.status()["status"] == "healthy"
    devices.batch_upsert.assert_awaited_once()
