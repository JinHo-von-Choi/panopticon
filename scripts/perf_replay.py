#!/usr/bin/env python3
"""합성 입력으로 격리 PostgreSQL·PCAP 파이프라인을 측정한다."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import platform
import random
import resource
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import asyncpg
from prometheus_client import REGISTRY
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.registry import EngineRegistry
from netwatcher.observability.observation import ObservationService
from netwatcher.services.packet_processor import PacketProcessor
from netwatcher.services.tick_service import TickService
from netwatcher.storage.database import Database
from netwatcher.storage.repositories import EventRepository
from netwatcher.storage.schemas import ALL_SCHEMAS
from netwatcher.utils.config import Config
from netwatcher.utils.network import AsyncDNSResolver


def frames(seed: int, scenario: str) -> list[bytes]:
    """개인정보 없는 고정 입력. 정상 업무와 스캔 입력을 구분한다."""
    rng = random.Random(seed)
    result = []
    for i in range(128):
        host = rng.randrange(2, 32)
        ethernet = Ether(src=f"02:00:00:00:00:{host:02x}", dst="02:00:00:00:00:01")
        ip = IP(src=f"198.18.0.{host}", dst="198.18.1.1")
        if scenario == "mixed" and i % 2 == 0:
            packet = ethernet / IP(src="198.18.0.250", dst="198.18.1.1") / TCP(dport=i + 1, flags="S")
        elif i % 3 == 0:
            packet = ethernet / ip / UDP(sport=20000 + i, dport=53) / DNS(id=i, rd=1, qd=DNSQR(qname="example.invalid"))
        else:
            # NAS/DB/VM 모양의 합성 부하이며 애플리케이션 프로토콜 정답 데이터는 아니다.
            packet = ethernet / ip / TCP(sport=20000 + i, dport=(445, 5432, 443)[i % 3], flags="PA") / Raw(b"x" * 512)
        result.append(bytes(packet))
    return result


def validate(args: argparse.Namespace) -> None:
    if not args.db_name.startswith("netwatcher_perf_"):
        raise ValueError("dedicated database name must start with netwatcher_perf_")
    if args.db_host not in {"localhost", "127.0.0.1", "::1"} and not args.db_host.startswith("/tmp/"):
        raise ValueError("only local dedicated PostgreSQL is allowed")
    if not math.isfinite(args.duration_seconds) or not 0 < args.duration_seconds <= 86400:
        raise ValueError("duration must be finite and within (0, 86400]")
    if not 1 <= args.pps <= 20000:
        raise ValueError("pps must be within [1, 20000]")
    if not 1 <= args.alerts_per_second <= 1000:
        raise ValueError("alerts per second must be within [1, 1000]")
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("output must be outside the repository")
    if output.exists():
        raise ValueError("output directory already exists; use a new isolated path")


def samples() -> list[dict]:
    return [
        {"name": s.name, "labels": s.labels, "value": s.value}
        for family in REGISTRY.collect()
        for s in family.samples
        if s.name.startswith("netwatcher_") and not s.name.endswith("_created")
    ]


async def run(args: argparse.Namespace) -> dict:
    validate(args)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    schema = "perf_" + uuid.uuid4().hex
    pg = {
        "host": args.db_host, "port": args.db_port,
        "database": args.db_name, "username": args.db_user,
        "password": os.environ.get("NETWATCHER_PERF_DB_PASSWORD", ""),
        "pool_size": 3, "search_path": schema,
    }
    config = Config({
        "postgresql": pg, "whitelist": {},
        "alerts": {"rate_limit": {"window_seconds": 300, "max_per_key": 5}, "channels": {}},
        "engines": {"signature": {"enabled": False}},
    })
    admin = await asyncpg.connect(host=pg["host"], port=pg["port"], database=pg["database"],
                                  user=pg["username"], password=pg["password"], timeout=5)
    db = Database(config)
    dispatcher = None
    tick = None
    producer = None
    stop = threading.Event()
    registry = EngineRegistry(config)
    created = False
    workload = frames(args.seed, args.scenario)
    emitted = 0
    source_errors: list[str] = []
    cpu_start = time.process_time()
    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        created = True
        await db.connect(max_retries=1)
        async with db.pool.acquire() as conn:
            for sql in ALL_SCHEMAS:
                await conn.execute(sql)
        obs = ObservationService(sensor_id="synthetic-local-input")
        writer = PCAPWriter(output_dir=str(args.output_dir / "pcaps"), max_storage_mb=8)
        dispatcher = AlertDispatcher(config, EventRepository(db), pcap_writer=writer if args.pcap else None, observation=obs)
        registry.discover_and_register()
        processor = PacketProcessor(registry, dispatcher, writer, AsyncDNSResolver(), observation=obs)
        sniffer = PacketSniffer(config, asyncio.get_running_loop(), processor.on_packet, observation=obs)
        tick = TickService(registry, dispatcher, observation=obs)
        await dispatcher.start()
        await tick.start()
        started = time.monotonic()
        deadline = started + args.duration_seconds

        def produce() -> None:
            nonlocal emitted
            try:
                while not stop.is_set():
                    now = time.monotonic()
                    if now >= deadline:
                        break
                    due = min(int((now - started) * args.pps) + 1, math.ceil(args.duration_seconds * args.pps))
                    while emitted < due and not stop.is_set():
                        sniffer._on_packet(Ether(workload[emitted % len(workload)]))
                        emitted += 1
                        if time.monotonic() >= deadline:
                            break
                    stop.wait(0.005)
            except Exception as exc:
                source_errors.append(type(exc).__name__)

        producer = threading.Thread(target=produce, name="synthetic-source")
        producer.start()
        injected = 0
        while time.monotonic() < deadline:
            await asyncio.sleep(0.05)
            sniffer.flush_observation()
            if args.scenario in {"alert-storm", "unique-key"}:
                due = int(min(args.duration_seconds, time.monotonic() - started) * args.alerts_per_second)
                for i in range(injected, due):
                    dispatcher.enqueue(Alert(
                        engine="port_scan", severity=Severity.WARNING,
                        title=f"synthetic {i}" if args.scenario == "unique-key" else "synthetic repeated",
                        description="queue workload, not an engine verdict", source_ip="198.18.0.2",
                    ))
                injected = due
        stop.set()
        await asyncio.to_thread(producer.join, 2)
        # 캡처 버퍼와 경보 큐에 처리 시간을 별도로 제공한다.
        drain_deadline = time.monotonic() + 5
        while sniffer._packet_buffer and time.monotonic() < drain_deadline:
            await asyncio.sleep(0.01)
        await tick.stop()
        await dispatcher.stop(drain_timeout=5)
        sniffer.flush_observation()
        elapsed = time.monotonic() - started
        async with db.pool.acquire() as conn:
            persisted = await conn.fetchval("SELECT COUNT(*) FROM events")
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        usage = resource.getrusage(resource.RUSAGE_SELF)
        report = {
            "format_version": 1,
            "scenario": args.scenario, "seed": args.seed,
            "input_sha256": hashlib.sha256(b"".join(workload)).hexdigest(),
            "revision": revision, "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
            "python": platform.python_version(), "platform": platform.platform(),
            "logical_cpu_count": os.cpu_count(),
            "database_backend": "PostgreSQL", "database_isolated_schema": schema,
            "measured_kernel_drop": None,
            "duration_requested_seconds": args.duration_seconds, "elapsed_with_drain_seconds": elapsed,
            "requested_pps": args.pps, "emitted_packets": emitted,
            "planned_packets": math.ceil(args.duration_seconds * args.pps),
            "source_errors": source_errors, "injected_alerts": injected,
            "persisted_events": persisted, "cpu_seconds": time.process_time() - cpu_start,
            "peak_rss_bytes": usage.ru_maxrss * 1024 if sys.platform != "darwin" else usage.ru_maxrss,
            "pcap_enabled": args.pcap, "engines": [e.name for e in registry.engines],
            "config_sha256": hashlib.sha256(json.dumps({k: v for k, v in config.raw.items() if k != "postgresql"}, sort_keys=True).encode()).hexdigest(),
            "observation": obs.snapshot(), "metrics": samples(),
            "limitations": [
                "Synthetic local callback input; NIC, link and kernel loss are not measured.",
                "Single worker only; no external webhooks, DNS requests, response execution or stats flush.",
                "Packet corpus hash identifies the repeating source, not every emitted packet timestamp.",
                "Source throughput shortfall is reported separately from application drops.",
                "Peak RSS includes test setup; CPU includes setup and drain.",
            ],
        }
        if source_errors:
            raise RuntimeError("synthetic input failed")
        (args.output_dir / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return report
    finally:
        stop.set()
        if producer is not None:
            await asyncio.to_thread(producer.join, 2)
        if tick is not None:
            await tick.stop()
        if dispatcher is not None:
            await dispatcher.stop(drain_timeout=1)
        registry.shutdown()
        await db.close()
        try:
            if created:
                await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        finally:
            await admin.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["normal", "alert-storm", "unique-key", "mixed"], default="normal")
    parser.add_argument("--duration-seconds", type=float, default=30)
    parser.add_argument("--pps", type=int, default=100)
    parser.add_argument("--alerts-per-second", type=int, default=100)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--pcap", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=5432)
    parser.add_argument("--db-name", required=True)
    parser.add_argument("--db-user", default="netwatcher")
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR)
    try:
        report = asyncio.run(run(args))
    except (ValueError, OSError, asyncpg.PostgresError):
        # 접속 예외 문자열에 인증/주소 정보가 포함될 수 있다.
        print("Replay failed: check isolated output, database and workload arguments.", file=sys.stderr)
        return 1
    print(json.dumps({"result": str(args.output_dir / "result.json"), "emitted_packets": report["emitted_packets"],
                      "persisted_events": report["persisted_events"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
