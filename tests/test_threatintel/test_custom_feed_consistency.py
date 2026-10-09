"""실제 캐시 파싱과 탐지 엔진으로 피드·사용자 목록의 소유 관계를 확인한다."""

import asyncio
import tracemalloc
import logging
import weakref
import gc

import pytest
import yaml
from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR

from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.detection.engines.threat_intel import ThreatIntelEngine
from netwatcher.detection.registry import EngineRegistry
from netwatcher.detection.engines.tls_fingerprint import TLSFingerprintEngine, compute_ja3
from tests.test_detection.test_tls_fingerprint import make_tls_client_hello
from scapy.layers.tls.handshake import TLSClientHello
from netwatcher.utils.config import Config


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "feeds.yaml"
    path.write_text(yaml.safe_dump({"feeds":[
        {"name":"Owned IP feed","url":"http://127.0.0.1/never-fetch", "type":"ip", "format":"text"},
        {"name":"Owned domain feed","url":"http://127.0.0.1/never-fetch", "type":"domain", "format":"text"},
    ]}))
    result = FeedManager(Config({"threatfeeds":{"config_path":str(path)}}))
    (result._cache_dir / "owned_ip_feed.txt").write_text("203.0.113.7\n")
    (result._cache_dir / "owned_domain_feed.txt").write_text("malware.example\n")
    return result


def detects_ip(manager):
    engine = ThreatIntelEngine({})
    engine.set_feeds(manager)
    return engine.analyze(Ether() / IP(src="192.0.2.1", dst="203.0.113.7") / TCP(flags="S",dport=443))


def detects_domain(manager):
    engine = ThreatIntelEngine({})
    engine.set_feeds(manager)
    return engine.analyze(Ether() / IP(src="192.0.2.1",dst="192.0.2.53") / UDP(dport=53)
                          / DNS(qd=DNSQR(qname="malware.example")))


@pytest.mark.asyncio
async def test_custom_removal_restores_feed_source_and_real_detection(manager):
    summary = await manager.update_all()
    assert summary.succeeded and summary.from_cache == 2
    assert detects_ip(manager).metadata["feed_source"] == "Owned IP feed"
    assert detects_domain(manager).metadata["feed_source"] == "Owned domain feed"
    manager.add_custom_ip("203.0.113.7")
    manager.add_custom_domain("malware.example")
    assert detects_ip(manager).metadata["feed_source"] == "Custom"
    assert detects_domain(manager).metadata["feed_source"] == "Custom"
    for _ in range(2):
        manager.remove_custom_ip("203.0.113.7")
        manager.remove_custom_domain("malware.example")
        assert detects_ip(manager).metadata["feed_source"] == "Owned IP feed"
        assert detects_domain(manager).metadata["feed_source"] == "Owned domain feed"
    assert "203.0.113.7" in manager.get_blocked_ips()
    assert "malware.example" in manager.get_blocked_domains()


@pytest.mark.asyncio
async def test_runtime_hook_observes_finished_update_and_propagates_failure(manager):
    observed = []
    def record(updated):
        observed.append(updated.match_ip("203.0.113.7"))
    manager.bind_runtime_update(record)
    assert (await manager.update_all()).succeeded
    assert observed == [{"source": "Owned IP feed", "category": "malware"}]
    def fail(updated):
        assert updated.match_ip("203.0.113.7")["source"] == "Owned IP feed"
        raise RuntimeError("injected runtime sync failure")
    manager.bind_runtime_update(fail)
    with pytest.raises(RuntimeError, match="runtime sync failure"):
        await manager.update_all()


@pytest.mark.asyncio
async def test_successful_refresh_keeps_custom_precedence_and_feed_provenance(manager):
    manager.add_custom_ip("203.0.113.7")
    manager.add_custom_domain("malware.example")
    assert (await manager.update_all()).succeeded
    assert detects_ip(manager).metadata["feed_source"] == "Custom"
    assert detects_domain(manager).metadata["feed_source"] == "Custom"
    manager.load_custom_entries(set(), set())
    assert detects_ip(manager).metadata["feed_source"] == "Owned IP feed"
    assert detects_domain(manager).metadata["feed_source"] == "Owned domain feed"
    manager.load_custom_entries({"192.0.2.2"}, {"custom.example"})
    manager.load_custom_entries(set(), set())
    assert manager.match_ip("192.0.2.2") is None
    assert manager.match_domain("custom.example") is None


@pytest.mark.asyncio
async def test_removed_feed_indicator_is_not_restored_after_next_successful_refresh(manager):
    assert (await manager.update_all()).succeeded
    manager.add_custom_ip("203.0.113.7")
    manager.add_custom_domain("malware.example")
    (manager._cache_dir / "owned_ip_feed.txt").write_text("203.0.113.8\n")
    (manager._cache_dir / "owned_domain_feed.txt").write_text("replacement.example\n")
    assert (await manager.update_all()).succeeded
    assert detects_ip(manager).metadata["feed_source"] == "Custom"
    assert detects_domain(manager).metadata["feed_source"] == "Custom"
    manager.remove_custom_ip("203.0.113.7")
    manager.remove_custom_domain("malware.example")
    assert detects_ip(manager) is None
    assert detects_domain(manager) is None
    assert manager.match_ip("203.0.113.8")["source"] == "Owned IP feed"
    assert manager.match_domain("replacement.example")["source"] == "Owned domain feed"


@pytest.mark.asyncio
async def test_canceled_refresh_preserves_live_detection_and_releases_update_lock(manager, monkeypatch):
    assert (await manager.update_all()).succeeded
    entered = asyncio.Event()
    original = manager._update_feed

    async def stalled(source, accumulator):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(manager, "_update_feed", stalled)
    task = asyncio.create_task(manager.update_all())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        manager.add_custom_ip("203.0.113.7")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        manager.remove_custom_ip("203.0.113.7")
        assert detects_ip(manager).metadata["feed_source"] == "Owned IP feed"
        assert detects_domain(manager).metadata["feed_source"] == "Owned domain feed"
        monkeypatch.setattr(manager, "_update_feed", original)
        assert (await asyncio.wait_for(manager.update_all(), 2)).succeeded
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_custom_changes_during_real_cache_refresh_are_not_reverted(manager, monkeypatch):
    manager.load_custom_entries({"192.0.2.8"}, {"removed.example"})
    entered, release = asyncio.Event(), asyncio.Event()
    original = manager._update_feed
    async def delayed(source, accumulator):
        entered.set()
        await release.wait()
        await original(source, accumulator)
    monkeypatch.setattr(manager, "_update_feed", delayed)
    task = asyncio.create_task(manager.update_all())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        manager.load_custom_entries({"192.0.2.9"}, {"added.example"})
        release.set()
        assert (await asyncio.wait_for(task, 2)).succeeded
        assert manager.match_ip("192.0.2.8") is None
        assert manager.match_domain("removed.example") is None
        assert manager.match_ip("192.0.2.9")["source"] == "Custom"
        assert manager.match_domain("added.example")["source"] == "Custom"
        assert detects_ip(manager) and detects_domain(manager)
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_concurrent_refresh_serializes_and_canceled_waiter_does_not_touch_live_state(manager, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    original = manager._update_feed
    calls = []
    async def delayed(source, accumulator):
        calls.append(source.name)
        entered.set()
        await release.wait()
        await original(source, accumulator)
    monkeypatch.setattr(manager, "_update_feed", delayed)
    first = asyncio.create_task(manager.update_all())
    second = None
    try:
        await asyncio.wait_for(entered.wait(),2)
        second = asyncio.create_task(manager.update_all())
        await asyncio.sleep(0)
        assert len(calls) == 2
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        manager.add_custom_ip("192.0.2.9")
        release.set()
        assert (await asyncio.wait_for(first,2)).succeeded
        assert manager.match_ip("192.0.2.9")["source"] == "Custom"
        assert len(calls) == 2
    finally:
        for task in (first, second):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(*(task for task in (first, second) if task is not None), return_exceptions=True)


@pytest.mark.asyncio
async def test_feed_pages_keep_custom_priority_filters_and_exact_totals(manager):
    assert (await manager.update_all()).succeeded
    manager.add_custom_ip("192.0.2.9")
    manager.add_custom_domain("Custom.example")
    expected = [
        {"type": "domain", "value": "Custom.example", "source": "Custom"},
        {"type": "ip", "value": "192.0.2.9", "source": "Custom"},
        {"type": "domain", "value": "malware.example", "source": "Owned domain feed"},
        {"type": "ip", "value": "203.0.113.7", "source": "Owned IP feed"},
    ]
    assert manager.get_all_entries_paginated(limit=2, offset=1) == (expected[1:3], 4)
    assert manager.get_all_entries_paginated(source="feed") == (expected[2:], 2)
    assert manager.get_all_entries_paginated(source="custom", entry_type="ip") == ([expected[1]], 1)
    assert manager.get_all_entries_paginated(search="EXAMPLE") == ([expected[0], expected[2]], 2)
    assert manager.get_all_entries_paginated(limit=0, offset=1) == ([], 4)
    assert manager.get_all_entries_paginated(offset=10) == ([], 4)
    with pytest.raises(ValueError):
        manager.get_all_entries_paginated(offset=-1)


def test_first_feed_page_does_not_copy_the_entire_indicator_set(manager):
    manager._domain_to_feed = {f"{index:06d}.example": "Owned domain feed" for index in range(20000)}
    tracemalloc.start()
    try:
        page, total = manager.get_all_entries_paginated(limit=50)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert total == 20000
    assert [entry["value"] for entry in page] == [f"{index:06d}.example" for index in range(50)]
    # 전체 목록 사본은 수 MB를 소비한다. 50개 페이지는 512 KiB 이내여야 한다.
    assert peak < 512 * 1024


@pytest.mark.parametrize("network,inside,outside,layer,origin", [
    ("203.0.113.7/24", "203.0.113.255", "203.0.114.0", IP, "192.0.2.1"),
    ("203.0.113.7/32", "203.0.113.7", "203.0.113.8", IP, "192.0.2.1"),
    ("2001:db8:1::7/64", "2001:db8:1::ffff", "2001:db8:2::1", IPv6, "2001:db8:3::1"),
    ("2001:db8:1::7/128", "2001:db8:1::7", "2001:db8:1::8", IPv6, "2001:db8:3::1"),
])
def test_custom_cidr_detects_real_packets_without_matching_adjacent_addresses(manager, network, inside, outside, layer, origin):
    engine = ThreatIntelEngine({})
    engine.set_feeds(manager)
    manager.add_custom_ip(network)
    alert = engine.analyze(Ether() / layer(src=origin, dst=inside) / TCP(flags="S", dport=443))
    assert alert.metadata["matched_ip"] == inside
    assert alert.metadata["feed_source"] == "Custom"
    assert engine.analyze(Ether() / layer(src=origin, dst=outside) / TCP(flags="S", dport=443)) is None
    assert engine.analyze(Ether() / layer(src=origin, dst=inside) / TCP(flags="SA", dport=443)) is None
    manager.remove_custom_ip(network)
    assert engine.analyze(Ether() / layer(src=origin, dst=inside) / TCP(flags="S", dport=443)) is None


@pytest.mark.asyncio
async def test_cidr_aliases_and_overlapping_ranges_survive_refresh_and_individual_removal(manager):
    manager.load_custom_entries({"203.0.113.7/24", "203.0.113.0/24", "203.0.113.0/25"}, set())
    assert (await manager.update_all()).succeeded
    manager.remove_custom_ip("203.0.113.7/24")
    assert manager.match_ip("203.0.113.255")["source"] == "Custom"
    manager.remove_custom_ip("203.0.113.0/24")
    assert manager.match_ip("203.0.113.255") is None
    assert manager.match_ip("203.0.113.127")["source"] == "Custom"
    manager.load_custom_entries(set(), set())
    assert manager.match_ip("203.0.113.127") is None
    assert detects_ip(manager).metadata["feed_source"] == "Owned IP feed"


@pytest.mark.asyncio
async def test_dns_case_and_custom_aliases_keep_feed_fallback(manager):
    assert (await manager.update_all()).succeeded
    engine = ThreatIntelEngine({})
    engine.set_feeds(manager)
    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(dport=53) / DNS(qd=DNSQR(qname="MALWARE.Example."))
    assert engine.analyze(packet).metadata["feed_source"] == "Owned domain feed"
    manager.load_custom_entries(set(), {"Malware.Example", "malware.example"})
    manager.remove_custom_domain("malware.example")
    assert engine.analyze(packet).metadata["feed_source"] == "Custom"
    manager.remove_custom_domain("Malware.Example")
    assert engine.analyze(packet).metadata["feed_source"] == "Owned domain feed"


@pytest.mark.asyncio
async def test_registry_recreation_and_reenable_keep_live_feed_detection(manager):
    assert (await manager.update_all()).succeeded
    registry = EngineRegistry(Config({}))
    registry._engine_classes = {"threat_intel": ThreatIntelEngine}
    registry.set_feeds(manager)
    packet = Ether() / IP(src="192.0.2.1", dst="203.0.113.7") / TCP(flags="S", dport=443)
    try:
        for _ in range(2):
            assert registry.reload_engine("threat_intel", {"enabled": True})[0]
            assert registry.process_packet(packet)[0].metadata["feed_source"] == "Owned IP feed"
            assert registry.disable_engine("threat_intel")[0]
            assert registry.process_packet(packet) == []
        manager.add_custom_ip("203.0.113.7")
        assert registry.reload_engine("threat_intel", {"enabled": True})[0]
        assert registry.process_packet(packet)[0].metadata["feed_source"] == "Custom"
        manager.remove_custom_ip("203.0.113.7")
        assert registry.process_packet(packet)[0].metadata["feed_source"] == "Owned IP feed"
    finally:
        registry.shutdown()


@pytest.mark.asyncio
async def test_tls_reload_and_shutdown_do_not_clear_shared_feed_data(manager):
    assert (await manager.update_all()).succeeded
    registry = EngineRegistry(Config({}))
    registry._engine_classes = {"tls_fingerprint": TLSFingerprintEngine}
    registry.set_feeds(manager)
    packet = make_tls_client_hello(sni="malware.example")
    try:
        for _ in range(2):
            assert registry.reload_engine("tls_fingerprint", {"enabled": True})[0]
            assert registry.process_packet(packet)[0].metadata["feed"] == "Owned domain feed"
        assert registry.disable_engine("tls_fingerprint")[0]
        assert "malware.example" in manager.get_blocked_domains()
        assert detects_domain(manager).metadata["feed_source"] == "Owned domain feed"
    finally:
        registry.shutdown()


@pytest.mark.asyncio
async def test_tls_reads_latest_feed_sets_and_custom_domain_changes(manager):
    assert (await manager.update_all()).succeeded
    engine = TLSFingerprintEngine({"enabled": True})
    engine.set_feeds(manager)
    previous_domains = weakref.ref(manager._blocked_domains)
    original = make_tls_client_hello(sni="malware.example")
    replacement = make_tls_client_hello(sni="replacement.example")
    assert engine.analyze(original).metadata["feed"] == "Owned domain feed"
    (manager._cache_dir / "owned_domain_feed.txt").write_text("replacement.example\n")
    assert (await manager.update_all()).succeeded
    gc.collect()
    assert previous_domains() is None
    assert engine._blocked_domains is manager._blocked_domains
    assert engine.analyze(original) is None
    assert engine.analyze(replacement).metadata["feed"] == "Owned domain feed"
    manager.add_custom_domain("Malware.Example")
    assert engine.analyze(original).metadata["feed"] == "Custom"
    manager.remove_custom_domain("Malware.Example")
    assert engine.analyze(original) is None
    # 실제 ClientHello의 해시를 새 피드 집합으로 바꿔도 엔진 재시작 없이 반영한다.
    hash_value = compute_ja3(original[TLSClientHello])
    manager._blocked_ja3 = {hash_value}
    manager._ja3_to_malware = {hash_value: "Updated feed evidence"}
    assert engine.analyze(original).metadata["malware"] == "Updated feed evidence"
    engine.shutdown()
    assert manager._blocked_ja3 == {hash_value}
    assert manager._ja3_to_malware[hash_value] == "Updated feed evidence"


def test_invalid_matching_inputs_leave_diagnostics_without_creating_alerts(manager, caplog):
    manager.add_custom_ip("203.0.113.0/24")
    with caplog.at_level(logging.DEBUG, logger="netwatcher.threatintel.feed_manager"):
        assert manager.match_ip("invalid address") is None
        assert manager.match_domain("\ud800.example") is None
    records = [record for record in caplog.records if record.name == "netwatcher.threatintel.feed_manager"]
    assert len(records) == 2
    assert all(record.exc_info and issubclass(record.exc_info[0], (ValueError, UnicodeError)) for record in records)
