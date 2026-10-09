"""피드 지표만 전달하며 실제 두 워커가 갱신·복구 후 같은 경보를 만든다."""

import json
from queue import Empty
import time

import pytest
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP

from netwatcher.capture.worker_feeds import WorkerFeeds, feed_payload
from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.utils.config import Config
from tests.test_capture.test_worker_control import create_pool, hosts_for_workers


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "feeds.yaml"
    path.write_text("feeds: []\n")
    return FeedManager(Config({"threatfeeds": {"config_path": str(path)},
                               "postgresql": {"password": "test-secret-not-for-workers"}}))


def test_snapshot_matches_parent_ipv4_ipv6_ranges_domains_and_fingerprints(feeds):
    feeds._ip_to_feed["198.51.100.90"] = "TestFeed"
    feeds._domain_to_feed["malware.example"] = "TestFeed"
    for ip in ("192.0.2.83", "203.0.113.0/24", "2001:db8::/64"):
        feeds.add_custom_ip(ip)
    feeds.add_custom_domain("Backup.Example.")
    feeds._blocked_ja3.add("a" * 32)
    feeds._ja3_to_malware["a" * 32] = "test-malware"
    payload = feed_payload(feeds)
    assert "test-secret-not-for-workers" not in payload
    snapshot = WorkerFeeds.from_payload(payload)
    for ip in ("198.51.100.90", "192.0.2.83", "203.0.113.77", "2001:db8::5", "198.51.100.1"):
        assert snapshot.match_ip(ip) == feeds.match_ip(ip)
    for domain in ("malware.example", "Backup.Example.", "unlisted.example"):
        assert snapshot.match_domain(domain) == feeds.match_domain(domain)
    assert snapshot._blocked_ja3 == feeds._blocked_ja3
    assert snapshot._ja3_to_malware == feeds._ja3_to_malware
    feeds.remove_custom_ip("203.0.113.0/24")
    assert snapshot.match_ip("203.0.113.77") is not None
    assert WorkerFeeds.from_payload(feed_payload(feeds)).match_ip("203.0.113.77") is None


@pytest.mark.parametrize("payload", ['{}', '{"ips":[]}', '"invalid"'])
def test_malformed_feed_snapshot_is_rejected(payload):
    with pytest.raises(ValueError):
        WorkerFeeds.from_payload(payload)


def test_invalid_updated_feed_stops_routing_and_notifies_owner_once(feeds):
    from netwatcher.capture.worker_control import WorkerSynchronizationError
    pool = create_pool()
    failures = []
    pool.bind_failure(lambda: failures.append("stop"))
    try:
        feeds._ip_to_feed["invalid-address"] = "TestFeed"
        for _ in range(2):
            with pytest.raises(WorkerSynchronizationError):
                pool.configure_feeds(feeds)
        assert failures == ["stop"]
        assert pool.health_check()["configuration_confirmed"] is False
        before = pool.dropped_count
        pool.route_packet(b"packet", "192.0.2.1")
        assert pool.dropped_count == before + 1
        assert pool._feed_snapshot_json == "null"
    finally:
        pool.stop(timeout=2)


def emit(pool, hosts, *, domain=None):
    for source in hosts:
        packet = Ether(src="02:00:00:00:00:91", dst="02:00:00:00:00:92") / IP(src=source, dst="203.0.113.9")
        packet /= UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)) if domain else TCP(dport=443, flags="S")
        pool.route_packet(bytes(packet), source)


def collect(pool, hosts):
    sources = set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and sources != set(hosts):
        sources.update(alert["source_ip"] for alert in pool.collect_alerts() if alert["engine"] == "threat_intel")
        time.sleep(.02)
    assert sources == set(hosts)


def test_real_workers_update_custom_ranges_and_domains_and_restart_from_confirmed_feed(feeds):
    pool = create_pool()
    hosts = hosts_for_workers()
    try:
        pool.configure_engine("threat_intel", {"enabled": True}, timeout=5)
        feeds.add_custom_ip("203.0.113.0/24")
        pool.configure_feeds(feeds, timeout=5)
        emit(pool, hosts)
        collect(pool, hosts)
        worker = pool._workers[0]
        worker.terminate()
        worker.join(timeout=2)
        assert pool.health_check()["worker_0"] is True
        emit(pool, hosts)
        collect(pool, hosts)
        feeds.remove_custom_ip("203.0.113.0/24")
        feeds.add_custom_domain("malware.example")
        pool.configure_feeds(feeds, timeout=5)
        emit(pool, hosts, domain="malware.example")
        collect(pool, hosts)
        feeds.remove_custom_domain("malware.example")
        pool.configure_feeds(feeds, timeout=5)
        emit(pool, hosts, domain="malware.example")
        pool.configure_feeds(feeds, timeout=5)
        with pytest.raises(Empty):
            pool._result_queue.get(timeout=.3)
    finally:
        pool.stop(timeout=2)
