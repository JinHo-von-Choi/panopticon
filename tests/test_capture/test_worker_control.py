"""실제 워커 프로세스의 설정 적용과 미확정 상태를 확인한다."""

import time

import pytest
from scapy.all import Ether, IP, TCP

from netwatcher.capture.pool import WorkerPool
from netwatcher.capture.worker_control import WorkerSynchronizationError
from netwatcher.detection.engines.port_scan import PortScanEngine
from netwatcher.detection.schema_utils import normalize_schema
from tests.test_capture.test_worker_pool import _make_config


def create_pool():
    config = _make_config()
    values = {key: field["default"] for key, field in normalize_schema(PortScanEngine.config_schema).items()}
    values.update({"enabled": True, "threshold": 20, "internal_multiplier": 1.0})
    config.raw["engines"]["port_scan"] = values
    pool = WorkerPool(config, num_workers=2)
    pool.start()
    return pool


def hosts_for_workers():
    hosts = {}
    for number in range(1, 255):
        address = f"192.0.2.{number}"
        hosts.setdefault(hash(address) % 2, address)
        if len(hosts) == 2:
            return list(hosts.values())
    raise AssertionError("Could not select worker hosts")


def send_stealth_scan(pool, hosts):
    for source in hosts:
        for port in range(1200, 1205):
            packet = Ether(src="02:00:00:00:00:81", dst="02:00:00:00:00:82") / IP(src=source, dst="203.0.113.9") / TCP(sport=50000, dport=port, flags=0)
            pool.route_packet(bytes(packet), source)


def send_scan(pool, hosts):
    for address in hosts:
        for port in range(1000, 1005):
            packet = Ether(src="02:00:00:00:00:81", dst="02:00:00:00:00:82") / IP(src=address, dst="203.0.113.9") / TCP(sport=50000, dport=port, flags="S")
            pool.route_packet(bytes(packet), address)


def collect_scans(pool, count):
    sources = set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and len(sources) < count:
        sources.update(alert["source_ip"] for alert in pool.collect_alerts() if alert["engine"] == "port_scan")
        time.sleep(.02)
    assert len(sources) == count
    return sources


def test_all_workers_apply_threshold_and_restarted_worker_uses_confirmed_config():
    pool = create_pool()
    hosts = hosts_for_workers()
    try:
        send_scan(pool, hosts)
        pool.configure_engine("port_scan", {"threshold": 5}, timeout=5)
        send_scan(pool, hosts)
        assert collect_scans(pool, 2) == set(hosts)
        previous = pool._workers[0]
        previous.terminate()
        previous.join(timeout=2)
        assert not previous.is_alive()
        status = pool.health_check()
        assert status["worker_0"] is True
        assert pool._workers[0].pid != previous.pid
        host = next(address for address in hosts if hash(address) % 2 == 0)
        send_scan(pool, [host])
        assert collect_scans(pool, 1) == {host}
    finally:
        pool.stop(timeout=2)


@pytest.mark.parametrize("failure", ["invalid", "dead", "timeout"])
def test_unconfirmed_change_stops_routing_and_never_commits_parent_config(failure):
    pool = create_pool()
    try:
        update = {"threshold": 5}
        timeout = 5
        if failure == "invalid":
            update = {"threshold": True}
        elif failure == "dead":
            pool._workers[0].terminate()
            pool._workers[0].join(timeout=2)
        else:
            # 자체 시험 워커만 정지해 적용 확인이 돌아오지 않게 한다.
            import os
            import signal
            os.kill(pool._workers[0].pid, signal.SIGSTOP)
            timeout = .1
        with pytest.raises(WorkerSynchronizationError):
            pool.configure_engine("port_scan", update, timeout=timeout)
        assert pool._config.get("engines.port_scan.threshold") == 20
        before = pool.dropped_count
        assert pool.route_packet(bytes(Ether() / IP()), "192.0.2.1") is True
        assert pool.dropped_count == before + 1
        assert pool.health_check()["configuration_confirmed"] is False
    finally:
        if failure == "timeout":
            os.kill(pool._workers[0].pid, signal.SIGCONT)
        pool.stop(timeout=2)


@pytest.mark.parametrize("channel", ["input", "result"])
def test_closed_queue_is_failure_and_not_an_empty_queue(channel, caplog):
    pool = create_pool()
    try:
        if channel == "input":
            source = "192.0.2.91"
            pool._input_queues[hash(source) % 2].close()
            pool.route_packet(b"packet", source)
            assert pool.dropped_count == 1
        else:
            pool._result_queue.close()
            assert pool.collect_alerts() == []
        assert pool.health_check()["configuration_confirmed"] is False
        assert "queue failed" in caplog.text
    finally:
        pool.stop(timeout=2)


def test_whitelist_suppresses_both_workers_survives_restart_and_removal_restores_detection():
    from queue import Empty
    pool = create_pool()
    hosts = hosts_for_workers()
    values = {"ips": hosts, "ip_ranges": [], "macs": [], "domains": [], "domain_suffixes": []}
    try:
        pool.configure_whitelist(values, timeout=5)
        send_stealth_scan(pool, hosts)
        pool.configure_whitelist(values, timeout=5)
        with pytest.raises(Empty):
            pool._result_queue.get(timeout=.3)
        worker = pool._workers[0]
        worker.terminate()
        worker.join(timeout=2)
        assert pool.health_check()["worker_0"] is True
        send_stealth_scan(pool, hosts)
        pool.configure_whitelist(values, timeout=5)
        with pytest.raises(Empty):
            pool._result_queue.get(timeout=.3)
        pool.configure_whitelist({**values, "ips": []}, timeout=5)
        send_stealth_scan(pool, hosts)
        assert collect_scans(pool, 2) == set(hosts)
        assert pool._config.raw["whitelist"]["ips"] == []
    finally:
        pool.stop(timeout=2)


@pytest.mark.parametrize("values", [
    {"ips": ["invalid"]},
    {"ips": [], "ip_ranges": ["invalid/99"], "macs": [], "domains": [], "domain_suffixes": []},
    {"ips": "192.0.2.1", "ip_ranges": [], "macs": [], "domains": [], "domain_suffixes": []},
])
def test_invalid_whitelist_is_refused_before_any_worker_mutation(values):
    pool = create_pool()
    try:
        before = dict(pool._config.raw["whitelist"])
        with pytest.raises(ValueError):
            pool.configure_whitelist(values, timeout=5)
        assert pool._config.raw["whitelist"] == before
        assert not pool._control_failed and not pool._routing_paused
        send_stealth_scan(pool, hosts_for_workers())
        assert collect_scans(pool, 2) == set(hosts_for_workers())
    finally:
        pool.stop(timeout=2)
