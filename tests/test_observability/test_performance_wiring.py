"""실제 큐·파일·이벤트 루프의 부하 계측 회귀 검사."""

import asyncio
from collections import deque
import time
from unittest.mock import AsyncMock
from types import SimpleNamespace

from prometheus_client import REGISTRY
import pytest
from scapy.all import Ether, IP, TCP, rdpcap

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.detection.models import Alert, Severity
from netwatcher.observability.loop_monitor import LoopMonitor
from netwatcher.observability.observation import ObservationService
from netwatcher.utils.config import Config
from netwatcher.services.stats_flush import StatsFlushService


def value(name, labels=None):
    return REGISTRY.get_sample_value(name, labels or {}) or 0


def test_capture_denominator_includes_rejected_input_and_reports_queue_bytes():
    loop = asyncio.new_event_loop()
    try:
        obs = ObservationService("test")
        seen = []
        sniffer = PacketSniffer(Config({}), loop, seen.append, observation=obs)
        sniffer._packet_buffer = deque(maxlen=2)
        packet = Ether(bytes(Ether() / IP() / TCP()))
        before = value("netwatcher_capture_received_total")
        for _ in range(3):
            sniffer._on_packet(packet)
        sniffer.flush_observation()
        snapshot = obs.snapshot()
        queue = snapshot["queues"]["input_queue"]
        assert queue["depth"] == 2
        assert queue["wire_bytes"] == 2 * len(packet)
        assert queue["memory_bytes"] is None
        assert snapshot["loss"]["per_stage"]["input_queue"]["app_loss_ratio"] == pytest.approx(1 / 3)
        counters = snapshot["stages"]["input_queue"]
        assert counters["received"] == counters["accepted"] + counters["dropped_app"]
        assert value("netwatcher_capture_received_total") - before == 3
        sniffer._drain_buffer()
        assert seen == [packet, packet]
        assert obs.snapshot()["queues"]["input_queue"]["wire_bytes"] == 0
        # 이미 배출한 계측을 다시 더하지 않는다.
        sniffer.flush_observation()
        assert value("netwatcher_capture_received_total") - before == 3
    finally:
        loop.close()


def test_capture_callback_failure_keeps_remaining_queue_drainable():
    loop = asyncio.new_event_loop()
    try:
        seen = []

        def callback(packet):
            if not seen:
                seen.append("failed")
                raise RuntimeError("packet callback failure")
            seen.append(packet)

        sniffer = PacketSniffer(Config({}), loop, callback)
        packet = Ether(bytes(Ether(dst="02:00:00:00:00:01") / IP() / TCP()))
        sniffer._on_packet(packet)
        sniffer._on_packet(packet)
        with pytest.raises(RuntimeError, match="callback failure"):
            sniffer._drain_buffer()
        assert sniffer._drain_scheduled
        sniffer._drain_buffer()
        assert seen == ["failed", packet]
        assert sniffer._queued_wire_bytes == 0
        assert not sniffer._drain_scheduled
    finally:
        loop.close()


def alert(title):
    return Alert(engine="port_scan", severity=Severity.WARNING, title=title, description="test")


@pytest.mark.asyncio
async def test_stopping_unstarted_dispatcher_clears_queue_age():
    d = AlertDispatcher(Config({"alerts": {}}), None)
    d.enqueue(alert("pending"))
    await d.stop()
    assert d.oldest_queue_age_seconds is None
    assert value("netwatcher_alerts_queue_age_seconds") == 0


@pytest.mark.asyncio
async def test_alert_queue_age_moves_to_next_item_and_store_outcome_is_counted():
    obs = ObservationService("test")
    repo = type("Repo", (), {})()
    release = asyncio.Event()
    entered = asyncio.Event()

    async def insert(**kwargs):
        entered.set()
        await release.wait()
        return 1

    repo.insert = insert
    d = AlertDispatcher(Config({"alerts": {}}), repo, observation=obs)
    d.enqueue(alert("first"))
    await asyncio.sleep(.02)
    d.enqueue(alert("second"))
    second_at = d._enqueue_times[-1]
    before = value("netwatcher_event_store_total", {"result": "committed"})
    await d.start()
    try:
        await asyncio.wait_for(entered.wait(), 1)
        assert d._oldest_enqueued_at == second_at
        assert obs.snapshot()["queues"]["result_queue"]["depth"] == 1
        release.set()
        await asyncio.wait_for(d._queue.join(), 1)
        assert d.oldest_queue_age_seconds is None
        assert value("netwatcher_event_store_total", {"result": "committed"}) - before == 2
        assert obs.snapshot()["stages"]["db"]["received"] == 2
    finally:
        release.set()
        await d.stop()


@pytest.mark.asyncio
async def test_failed_insert_is_measured_as_failure(caplog):
    repo = type("Repo", (), {})()
    repo.insert = AsyncMock(side_effect=RuntimeError("test failure"))
    d = AlertDispatcher(Config({"alerts": {}}), repo, observation=ObservationService("test"))
    before = value("netwatcher_event_store_total", {"result": "failed"})
    await d._process_alert(alert("failure"))
    assert value("netwatcher_event_store_total", {"result": "failed"}) - before == 1
    loss = d._observation.snapshot()["loss"]["per_stage"]["db"]
    assert loss["received"] == 1
    assert loss["app_loss_ratio"] == 1


def test_pcap_write_and_retention_operations_use_real_files(tmp_path):
    writer = PCAPWriter(str(tmp_path), max_storage_mb=1)
    writer.add_packet(IP(src="198.18.0.1", dst="198.18.0.2") / TCP())
    before = value("netwatcher_pcap_operations_total", {"operation": "write", "result": "ok"})
    path = writer.capture_for_alert(1, "198.18.0.1", None)
    assert len(rdpcap(path)) == 1
    assert value("netwatcher_pcap_operations_total", {"operation": "write", "result": "ok"}) - before == 1
    before_delete = value("netwatcher_pcap_operations_total", {"operation": "delete", "result": "ok"})
    writer._max_storage_bytes = 0
    writer._enforce_storage_limit()
    assert not list(tmp_path.glob("*.pcap"))
    assert value("netwatcher_pcap_operations_total", {"operation": "delete", "result": "ok"}) - before_delete == 1


@pytest.mark.asyncio
async def test_loop_monitor_detects_blocking_and_stops_without_orphan_task():
    before = value("netwatcher_event_loop_lag_seconds_sum")
    monitor = LoopMonitor(.005)
    await monitor.start()
    task = monitor._task
    await monitor.start()
    assert monitor._task is task
    time.sleep(.03)
    await asyncio.sleep(.02)
    await monitor.stop()
    assert value("netwatcher_event_loop_lag_seconds_sum") - before >= .02
    assert task.done()
    await monitor.stop()


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_loop_monitor_rejects_invalid_interval(interval):
    with pytest.raises(ValueError):
        LoopMonitor(interval)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_stats_write_success_and_failure_are_instrumented(fail):
    inserted = asyncio.Event()

    async def insert(**kwargs):
        inserted.set()
        if fail:
            raise RuntimeError("stats storage unavailable")

    operation = {"operation": "traffic_stats", "result": "failed" if fail else "ok"}
    before = value("netwatcher_db_write_total", operation)
    processor = SimpleNamespace(
        snapshot_and_reset_counters=lambda: {"total_packets": 2, "total_bytes": 100, "distinct_src_macs": 1},
        drain_device_buffer=lambda: [],
    )
    config = Config({"engines": {"traffic_anomaly": {"stats_interval_minutes": .001}}})
    service = StatsFlushService(config, SimpleNamespace(insert_snapshot=insert), None, processor)
    await service.start()
    task = service._task
    try:
        await asyncio.wait_for(inserted.wait(), 1)
        if fail:
            assert not task.done()
            assert service._pending_stats is not None
        assert value("netwatcher_db_write_total", operation) - before == 1
    finally:
        await service.stop()
        with pytest.raises(asyncio.CancelledError):
            await task
