"""정규식 옵션과 규칙 활성 상태를 두 실제 워커에서 보존한다."""

from dataclasses import replace
from queue import Empty
import re
import time

import pytest
from scapy.all import Ether, IP, TCP, Raw

from netwatcher.capture.worker_rules import rules_payload, restore_rules
from netwatcher.detection.engines.signature_rule import SignatureRule
from netwatcher.services.sensor_rules import digest_rules
from tests.test_capture.test_worker_control import create_pool, hosts_for_workers


def make_rule():
    rule = SignatureRule.from_dict({"id": "worker-test-1", "name": "worker rule", "protocol": "TCP",
        "dst_port": 443, "content": ["payload"], "flowbits": {"set": "worker-seen"},
        "metadata": {"category": "test"}, "severity": "WARNING"})
    rule.regex = re.compile("evil", re.IGNORECASE)
    rule.pcre = [re.compile("evil.*payload", re.IGNORECASE | re.DOTALL)]
    return rule


def test_rule_serialization_preserves_full_digest_and_regex_flags():
    original = make_rule()
    restored = restore_rules(rules_payload([original]))
    assert digest_rules(restored) == digest_rules([original])
    assert restored[0].matches_payload(b"EVIL\npayload")
    assert restored[0].flowbits == original.flowbits
    assert restored[0].metadata == original.metadata


def emit(pool, hosts):
    for source in hosts:
        packet = Ether(src="02:00:00:00:00:91", dst="02:00:00:00:00:92") / IP(src=source, dst="203.0.113.9") / TCP(dport=443, flags="PA") / Raw(b"EVIL\npayload")
        pool.route_packet(bytes(packet), source)


def collect(pool, hosts):
    sources = set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and sources != set(hosts):
        sources.update(alert["source_ip"] for alert in pool.collect_alerts() if alert["engine"] == "signature")
        time.sleep(.02)
    assert sources == set(hosts)


def test_real_workers_replace_disable_and_restore_rule_after_restart():
    pool = create_pool()
    hosts = hosts_for_workers()
    rule = make_rule()
    try:
        pool.configure_engine("signature", {"enabled": True}, timeout=5)
        pool.configure_rules([rule], timeout=5)
        emit(pool, hosts)
        collect(pool, hosts)
        pool.configure_rules([replace(rule, enabled=False)], reset_matcher=False, timeout=5)
        emit(pool, hosts)
        pool.configure_rules([replace(rule, enabled=False)], reset_matcher=False, timeout=5)
        with pytest.raises(Empty):
            pool._result_queue.get(timeout=.3)
        pool.configure_rules([rule], timeout=5)
        worker = pool._workers[0]
        worker.terminate()
        worker.join(timeout=2)
        assert pool.health_check()["worker_0"] is True
        emit(pool, hosts)
        collect(pool, hosts)
    finally:
        pool.stop(timeout=2)


def test_duplicate_rule_identifiers_are_refused():
    with pytest.raises(ValueError):
        rules_payload([make_rule(), make_rule()])
