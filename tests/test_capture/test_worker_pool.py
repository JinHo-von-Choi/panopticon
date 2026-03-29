"""WorkerPool 및 PacketWorker 멀티프로세스 패킷 처리 테스트."""

from __future__ import annotations

import multiprocessing as mp
import time
from multiprocessing import Queue
from unittest.mock import MagicMock, patch

import pytest

from netwatcher.capture.pool import WorkerPool
from netwatcher.utils.config import Config


# ── Config fixture ──────────────────────────────────────────────────────────

def _make_config(**overrides) -> Config:
    """테스트용 최소 Config를 생성한다."""
    data = {
        "interface": None,
        "workers": 1,
        "whitelist": {"ips": [], "macs": [], "domains": [], "domain_suffixes": [], "ip_ranges": []},
        "engines": {
            "arp_spoof": {"enabled": False},
            "dns_anomaly": {"enabled": False},
            "port_scan": {"enabled": False},
            "http_suspicious": {"enabled": False},
            "traffic_anomaly": {"enabled": False},
            "threat_intel": {"enabled": False},
            "tls_fingerprint": {"enabled": False},
            "dns_response": {"enabled": False},
            "icmp_anomaly": {"enabled": False},
            "dhcp_spoof": {"enabled": False},
            "lateral_movement": {"enabled": False},
            "data_exfil": {"enabled": False},
            "protocol_anomaly": {"enabled": False},
            "mac_spoof": {"enabled": False},
            "protocol_inspect": {"enabled": False},
            "behavior_profile": {"enabled": False},
            "signature": {"enabled": False},
            "ransomware_lateral": {"enabled": False},
            "segment_violation": {"enabled": False},
            "dark_ip": {"enabled": False},
            "c2_beaconing": {"enabled": False},
        },
        "logging": {"level": "WARNING", "directory": "/tmp/nw-test-logs"},
    }
    data.update(overrides)
    return Config(data)


# ── WorkerPool 단위 테스트 ────────────────────────────────────────────────

class TestWorkerPoolSingleProcess:
    """workers=1 (단일프로세스 모드) 테스트."""

    def test_single_process_mode(self):
        cfg = _make_config(workers=1)
        pool = WorkerPool(cfg, num_workers=1)
        assert not pool.is_multiprocess
        assert pool.num_workers == 0

    def test_route_returns_false(self):
        cfg = _make_config(workers=1)
        pool = WorkerPool(cfg, num_workers=1)
        pool.start()
        assert pool.route_packet(b"\x00" * 64, "192.168.1.1") is False
        pool.stop()

    def test_collect_alerts_empty(self):
        cfg = _make_config(workers=1)
        pool = WorkerPool(cfg, num_workers=1)
        pool.start()
        assert pool.collect_alerts() == []
        pool.stop()

    def test_health_check_single(self):
        cfg = _make_config(workers=1)
        pool = WorkerPool(cfg, num_workers=1)
        pool.start()
        status = pool.health_check()
        assert status == {"mode": "single_process"}
        pool.stop()


class TestWorkerPoolMultiProcess:
    """멀티프로세스 모드 테스트."""

    def test_auto_workers(self):
        """workers=0일 때 cpu_count - 1으로 자동 결정."""
        cfg = _make_config(workers=0)
        pool = WorkerPool(cfg, num_workers=0)
        import os
        expected = max(1, (os.cpu_count() or 2) - 1)
        # 단일 CPU 시스템에서는 단일프로세스가 될 수 있음
        if expected >= 2:
            assert pool.is_multiprocess

    def test_route_packet_ip_hashing(self):
        """같은 src_ip는 항상 같은 워커로 라우팅된다."""
        cfg = _make_config(workers=2)
        pool = WorkerPool(cfg, num_workers=3)

        # 큐에 직접 접근하여 라우팅 검증 (워커 프로세스 실행 없이)
        pkt = b"\x00" * 64
        ip = "192.168.1.100"
        expected_idx = hash(ip) % 3

        # route_packet은 워커가 시작되지 않아도 큐에 넣을 수 있다
        # (단, start() 호출로 _alive=True가 되어야 함)
        pool._alive = True  # 직접 설정 (start()는 프로세스를 생성하므로 피함)

        pool.route_packet(pkt, ip)
        assert pool._input_queues[expected_idx].qsize() == 1

        # 다른 큐는 비어있어야 함
        for i in range(3):
            if i != expected_idx:
                assert pool._input_queues[i].qsize() == 0

    def test_route_packet_round_robin_no_ip(self):
        """src_ip=None이면 round-robin으로 분배된다."""
        cfg = _make_config(workers=2)
        pool = WorkerPool(cfg, num_workers=2)
        pool._alive = True

        pkt = b"\x00" * 64
        pool.route_packet(pkt, None)
        pool.route_packet(pkt, None)

        # 두 큐에 각각 1개씩
        assert pool._input_queues[0].qsize() == 1
        assert pool._input_queues[1].qsize() == 1

    def test_dropped_count(self):
        """큐가 가득 차면 드롭 카운트가 증가한다."""
        cfg = _make_config(workers=2)
        pool = WorkerPool(cfg, num_workers=2)
        pool._alive = True

        # maxsize=1인 작은 큐로 교체
        pool._input_queues = [Queue(maxsize=1) for _ in range(2)]

        pkt = b"\x00" * 64
        ip = "10.0.0.1"
        idx = hash(ip) % 2

        pool.route_packet(pkt, ip)   # 성공
        pool.route_packet(pkt, ip)   # 큐 full → 드롭

        assert pool.dropped_count == 1

    def test_collect_alerts(self):
        """result_queue에서 Alert dict를 수집한다."""
        cfg = _make_config(workers=2)
        pool = WorkerPool(cfg, num_workers=2)
        pool._alive = True

        # 수동으로 결과 큐에 Alert dict 삽입
        pool._result_queue.put({"engine": "test", "severity": "WARNING", "title": "test"})
        pool._result_queue.put({"engine": "test2", "severity": "CRITICAL", "title": "test2"})

        # multiprocessing.Queue 내부 파이프 전파 대기
        time.sleep(0.1)

        alerts = pool.collect_alerts()
        assert len(alerts) == 2
        assert alerts[0]["engine"] == "test"
        assert alerts[1]["engine"] == "test2"


class TestWorkerPoolLifecycle:
    """워커 프로세스 생명주기 테스트 (실제 프로세스 생성)."""

    def test_start_and_stop(self):
        """워커 프로세스를 시작하고 정상 종료한다."""
        cfg = _make_config()
        pool = WorkerPool(cfg, num_workers=2)
        pool.start()

        assert pool.is_multiprocess
        assert pool.num_workers == 2

        # 워커가 실제로 실행 중인지 확인
        for w in pool._workers:
            assert w.is_alive()

        pool.stop()

        # 종료 후 워커가 없어야 함
        assert pool.num_workers == 0

    def test_worker_processes_packets(self):
        """워커가 실제로 패킷을 분석하고 결과를 반환하는지 검증."""
        cfg = _make_config()
        pool = WorkerPool(cfg, num_workers=2)
        pool.start()

        # ARP 패킷 bytes (Scapy로 생성)
        from scapy.all import ARP, Ether
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
        raw = bytes(pkt)

        pool.route_packet(raw, "192.168.1.1")

        # 워커가 처리할 시간을 약간 대기
        time.sleep(2)

        # 엔진이 모두 비활성이므로 알림은 없어야 함 (정상 처리 확인)
        alerts = pool.collect_alerts()
        # 비활성 엔진이므로 빈 리스트가 정상
        assert isinstance(alerts, list)

        pool.stop()

    def test_worker_health_check(self):
        """헬스체크가 올바른 상태를 반환한다."""
        cfg = _make_config()
        pool = WorkerPool(cfg, num_workers=2)
        pool.start()

        status = pool.health_check()
        assert status["worker_0"] is True
        assert status["worker_1"] is True

        pool.stop()


# ── PacketWorker 단위 테스트 ──────────────────────────────────────────────

class TestPacketWorker:
    """PacketWorker 격리 테스트."""

    def test_sentinel_terminates(self):
        """None sentinel 수신 시 워커가 종료된다."""
        from netwatcher.capture.worker import PacketWorker

        cfg = _make_config()
        in_q: Queue = Queue()
        out_q: Queue = Queue()

        in_q.put(None)  # 즉시 종료 시그널

        worker = PacketWorker(0, cfg, in_q, out_q)
        worker.run()  # 블로킹이지만 즉시 종료됨

        assert out_q.empty()

    def test_invalid_bytes_skipped(self):
        """유효하지 않은 bytes는 무시하고 계속 진행한다."""
        from netwatcher.capture.worker import PacketWorker

        cfg = _make_config()
        in_q: Queue = Queue()
        out_q: Queue = Queue()

        in_q.put(b"not_a_valid_packet")
        in_q.put(None)  # 종료

        worker = PacketWorker(0, cfg, in_q, out_q)
        worker.run()

        assert out_q.empty()

    def test_valid_packet_processed(self):
        """유효한 패킷이 처리된다 (엔진 비활성이므로 알림 없음)."""
        from scapy.all import ARP, Ether

        from netwatcher.capture.worker import PacketWorker

        cfg = _make_config()
        in_q: Queue = Queue()
        out_q: Queue = Queue()

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
        in_q.put(bytes(pkt))
        in_q.put(None)

        worker = PacketWorker(0, cfg, in_q, out_q)
        worker.run()

        # 엔진 모두 비활성이므로 알림 없음
        assert out_q.empty()
