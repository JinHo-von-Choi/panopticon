"""실제 결과 큐 포화가 무한 대기·메모리 증가로 이어지지 않는다."""

import time
from threading import Event
from queue import Queue

from netwatcher.capture.worker import PacketWorker
from netwatcher.detection.models import Alert, Severity
from tests.test_capture.test_worker_pool import _make_config
from tests.test_capture.test_worker_control import create_pool, hosts_for_workers
from tests.test_capture.test_worker_rules import make_rule, emit


def test_oversized_result_refused_before_enqueue_and_failure_reported():
    queue = Queue(maxsize=1)
    failed = Event()
    worker = PacketWorker(0, _make_config(), Queue(), queue, result_failure=failed)
    alert = Alert(engine="signature", severity=Severity.WARNING, title="test", description="test")
    assert worker._emit_alert(alert)
    assert queue.get_nowait()["title"] == "test"
    alert.metadata = {"oversized": "x" * 65536}
    assert not worker._emit_alert(alert)
    assert failed.is_set() and not worker._running and queue.empty()


def test_real_full_queue_stops_workers_and_owner_without_restarting():
    from netwatcher.capture.pool import _RESULT_QUEUE_MAXSIZE
    pool = create_pool()
    stopped = []
    pool.bind_failure(lambda: stopped.append("stop"))
    try:
        pool.configure_engine("signature", {"enabled": True}, timeout=5)
        pool.configure_rules([make_rule()], timeout=5)
        for _ in range(_RESULT_QUEUE_MAXSIZE):
            pool._result_queue.put_nowait({"queued": True})
        emit(pool, hosts_for_workers())
        deadline = time.monotonic() + 5
        while not pool._result_failure.is_set() and time.monotonic() < deadline:
            time.sleep(.02)
        assert pool._result_failure.is_set()
        assert pool.health_check()["configuration_confirmed"] is False
        assert stopped == ["stop"]
        before = pool.dropped_count
        assert pool.route_packet(b"packet", "192.0.2.1") is True
        assert pool.dropped_count == before + 1
        pool.collect_alerts()
        assert stopped == ["stop"]
    finally:
        pool.stop(timeout=2)


def test_stop_reaps_owned_process_even_when_sigterm_cannot_run():
    import os
    import signal
    pool = create_pool()
    processes = list(pool._workers)
    try:
        pool.wait_ready(timeout=5)
        os.kill(processes[0].pid, signal.SIGSTOP)
        started = time.monotonic()
        pool.stop(timeout=.1)
        assert time.monotonic() - started < 1
        assert all(not process.is_alive() for process in processes)
    finally:
        for process in processes:
            if process.is_alive():
                os.kill(process.pid, signal.SIGCONT)
        pool.stop(timeout=2)
