import asyncio
import hashlib
import threading
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from scapy.all import IP, TCP

from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.detection.models import Alert, Severity
from netwatcher.services.evidence_writer import EvidenceWriter
from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.utils.config import Config


def make_alert(severity=Severity.WARNING):
    return Alert(engine="scan", severity=severity, title="scan", source_ip="192.0.2.1")


@pytest.mark.asyncio
async def test_slow_disk_does_not_block_loop_and_queue_memory_is_bounded(tmp_path):
    writer = PCAPWriter(str(tmp_path))
    writer.add_packet(IP(src="192.0.2.1", dst="192.0.2.2") / TCP())
    repo = AsyncMock()
    service = EvidenceWriter(writer, repo, max_jobs=1, max_bytes=100)
    entered, release = threading.Event(), threading.Event()
    original = writer.write_snapshot
    def slow(*args):
        entered.set()
        release.wait(2)
        return original(*args)
    writer.write_snapshot = slow
    assert service.submit(1, make_alert())["state"] == "pending"
    for _ in range(100):
        if entered.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered.is_set()
    assert service.submit(2, make_alert())["reason"] == "cooldown"
    assert service.submit(3, make_alert(Severity.CRITICAL))["state"] == "pending"
    assert service.pending_bytes <= 100
    await asyncio.wait_for(asyncio.sleep(0.02), timeout=0.2)
    release.set()
    await service.stop()
    assert service.pending_bytes == 0
    assert repo.update_pcap_state.await_count == 2
    for call in repo.update_pcap_state.call_args_list:
        state = call.args[1]
        assert state["state"] == "persisted"
        assert state["context"] == "pre_alert_only"
        assert state["sha256"] == hashlib.sha256(Path(state["path"]).read_bytes()).hexdigest()


@pytest.mark.asyncio
async def test_disk_failure_is_not_reported_as_persisted(tmp_path):
    writer = PCAPWriter(str(tmp_path))
    writer.add_packet(IP(src="192.0.2.1", dst="192.0.2.2") / TCP())
    writer.write_snapshot = lambda *args: None
    repo = AsyncMock()
    service = EvidenceWriter(writer, repo)
    service.submit(1, make_alert())
    await service.stop()
    assert repo.update_pcap_state.call_args.args[1]["state"] == "failed"


def test_critical_jobs_use_reserved_capacity_and_run_first(tmp_path):
    writer = PCAPWriter(str(tmp_path))
    writer.add_packet(IP(src="192.0.2.1", dst="192.0.2.2") / TCP())
    service = EvidenceWriter(writer, AsyncMock(), max_jobs=4, max_bytes=1000)
    service.start = lambda: None  # 소비 전 큐의 admission/순서를 독립 검사한다.
    for i in range(3):
        a = make_alert()
        a.engine = str(i)
        assert service.submit(i, a)["state"] == "pending"
    a = make_alert()
    a.engine = "extra"
    assert service.submit(99, a)["reason"] == "evidence_queue_budget"
    assert service.submit(100, make_alert(Severity.CRITICAL))["state"] == "pending"
    assert service.queue.get_nowait()[2] == 100


@pytest.mark.asyncio
async def test_real_postgres_aggregation_and_pcap_share_committed_event_id(event_repo, tmp_path):
    writer = PCAPWriter(str(tmp_path))
    writer.add_packet(IP(src="192.0.2.1", dst="192.0.2.2") / TCP())
    dispatcher = AlertDispatcher(Config({"alerts": {"aggregation": {"enabled": True}}}),
                                 event_repo, pcap_writer=writer)
    await dispatcher.start()
    for _ in range(12):
        dispatcher.enqueue(make_alert())
    await dispatcher.stop()
    rows = await event_repo.list_recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["metadata"]["aggregation"]["count"] == 12
    state = row["metadata"]["pcap"]
    assert state["state"] == "persisted"
    assert Path(state["path"]).name.startswith(f"event_{row['id']}_")
    assert state["sha256"] == hashlib.sha256(Path(state["path"]).read_bytes()).hexdigest()
