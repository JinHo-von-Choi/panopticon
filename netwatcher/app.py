"""메인 오케스트레이터: 캡처, 탐지, 알림, 웹, 스토리지 통합 관리."""

from __future__ import annotations

import asyncio
import logging
import signal

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.proposals import ProposalService
from netwatcher.detection.registry import EngineRegistry
from netwatcher.observability.observation import ObservationService
from netwatcher.response.blocker import BlockManager
from netwatcher.services.maintenance import MaintenanceService
from netwatcher.services.packet_processor import PacketProcessor
from netwatcher.services.stats_flush import StatsFlushService
from netwatcher.services.tick_service import TickService
from netwatcher.storage.database import Database
from netwatcher.storage.repositories import (
    BlocklistRepository,
    ConfigProposalRepository,
    DeviceRepository,
    EventRepository,
    IncidentRepository,
    TrafficStatsRepository,
)
from netwatcher.support import enforce_support
from netwatcher.utils.config import Config
from netwatcher.utils.logging_setup import setup_logging
from netwatcher.utils.network import AsyncDNSResolver
from netwatcher.utils.yaml_editor import YamlConfigEditor
from netwatcher.web.server import create_app

logger = logging.getLogger("netwatcher.app")


def _sensor_id(config) -> str:
    """센서 식별자 — 관측 창이 어느 호스트의 것인지 구분한다."""
    import socket

    host = socket.gethostname() or "unknown"
    iface = config.get("interface") or "auto"
    return f"{host}/{iface}"


class NetWatcher:
    """최상위 애플리케이션 오케스트레이터.

    모든 백그라운드 작업을 전담 서비스 객체에 위임하며,
    컴포넌트 연결, 시작 순서 제어, 정상 종료만 담당한다.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.loop: asyncio.AbstractEventLoop | None = None
        # 지원 프로필 계약. run() 에서 기동 직전에 검증한다.
        self.support_contract = None
        # 관측 범위. run() 에서 계측 지점과 함께 만든다.
        self.observation: ObservationService | None = None

        # 핵심 컴포넌트
        self.db         = Database(config)
        self.registry   = EngineRegistry(config)
        self.correlator = AlertCorrelator()
        self.pcap_writer = PCAPWriter()

        # 비동기 호스트명 해석
        self._dns_resolver = AsyncDNSResolver()

        # YAML 설정 편집기 (엔진 설정 UI용)
        if config.config_path:
            self._yaml_editor: YamlConfigEditor | None = YamlConfigEditor(config.config_path)
        else:
            self._yaml_editor = None
            logger.warning("Config file path not available; engine config editing disabled")

    async def run(self) -> None:
        """메인 진입점: 모든 컴포넌트를 시작한다."""
        self.loop = asyncio.get_running_loop()

        setup_logging(self.config)
        
        # i18n 초기화
        from pathlib import Path
        from netwatcher.utils.i18n import i18n
        locales_dir = Path(__file__).parent / "web" / "static" / "locales"
        default_lang = self.config.get("netwatcher.language.default", "ko")
        i18n.init(locales_dir, default_lang)
        
        logger.info("NetWatcher starting...")

        # ── 지원 프로필 계약 (PR 01) ───────────────────────────────────
        # 미지원 조합은 어떤 컴포넌트도 시작되기 전에 거부한다. enforcement나
        # 검증 게이트가 통과한 것처럼 보이는 상태를 남기지 않기 위함이다.
        self.support_contract = enforce_support(self.config)
        logger.info("Support profile: %s", self.support_contract.profile)

        # ── 데이터베이스 & 리포지토리 ──────────────────────────────────
        await self.db.connect()
        event_repo    = EventRepository(self.db)
        device_repo   = DeviceRepository(self.db)
        stats_repo    = TrafficStatsRepository(self.db)
        incident_repo = IncidentRepository(self.db)
        blocklist_repo = BlocklistRepository(self.db)

        self.correlator.set_incident_repo(incident_repo)

        # ── Redis ────────────────────────────────────────────────────────
        from netwatcher.cache.redis_client import RedisClient

        redis_cfg = self.config.section("redis") or {}
        redis_client = RedisClient(
            host=redis_cfg.get("host", "localhost"),
            port=redis_cfg.get("port", 6379),
            db=redis_cfg.get("db", 0),
            password=redis_cfg.get("password", ""),
            key_prefix=redis_cfg.get("key_prefix", "nw:"),
            enabled=redis_cfg.get("enabled", False),
        )
        await redis_client.connect()

        # ── HA 관리자 ─────────────────────────────────────────────────────
        from netwatcher.ha.manager import HAManager

        ha_manager = HAManager(
            redis_client=redis_client,
            config=self.config.raw,
            instance_id=None,
        )

        # ── 차단 관리자 (IRS 자동 차단) ──────────────────────────────────
        block_manager: BlockManager | None = None
        response_cfg = self.config.section("response") or {}
        if response_cfg.get("enabled", False):
            block_manager = BlockManager(
                enabled=True,
                backend=response_cfg.get("backend", "iptables"),
                chain_name=response_cfg.get("chain_name", "NETWATCHER_BLOCK"),
                whitelist=response_cfg.get("whitelist", []),
                max_blocks=response_cfg.get("max_blocks", 1000),
                default_duration=response_cfg.get("default_duration", 3600),
            )
            await block_manager.init_chain()
            logger.info(
                "BlockManager enabled (backend=%s, chain=%s)",
                response_cfg.get("backend", "iptables"),
                response_cfg.get("chain_name", "NETWATCHER_BLOCK"),
            )
        else:
            logger.info("BlockManager disabled")

        obs_cfg = self.config.section("observability") or {}

        # ── 관측 범위 (계획서 3장) ────────────────────────────────────────
        # "경보 없음" 이 "문제 없음" 으로 읽히지 않게, 경보 옆에 무엇을
        # 관측했고 무엇을 관측하지 못했는지 남긴다. 기동 시점에 만든다.
        observation = ObservationService(
            sensor_id=_sensor_id(self.config),
            heartbeat_seconds=obs_cfg.get("heartbeat_seconds", 10.0),
            missed_beats_to_stale=obs_cfg.get("missed_beats_to_stale", 3),
        )
        self.observation = observation

        # ── 알림 디스패처 ────────────────────────────────────────────────
        dispatcher = AlertDispatcher(
            config=self.config,
            event_repo=event_repo,
            device_repo=device_repo,
            correlator=self.correlator,
            pcap_writer=self.pcap_writer,
            block_manager=block_manager,
            observation=observation,
        )
        await dispatcher.start()

        # ── 탐지 엔진 ─────────────────────────────────────────────────────
        self.registry.discover_and_register()
        logger.info(
            "Registered %d detection engines: %s",
            len(self.registry.engines),
            [e.name for e in self.registry.engines],
        )

        # ── 엔진 상태 체크포인트 서비스 ──────────────────────────────────
        from netwatcher.cache.engine_state import EngineStateManager
        from netwatcher.services.checkpoint_service import CheckpointService

        checkpoint_service: CheckpointService | None = None
        if redis_client.available:
            checkpoint_interval = self.config.get("redis.checkpoint_interval", 60)
            state_manager = EngineStateManager(redis_client, interval_seconds=checkpoint_interval)
            checkpoint_service = CheckpointService(
                registry=self.registry,
                state_manager=state_manager,
                interval_seconds=checkpoint_interval,
            )
            await checkpoint_service.start()
            logger.info("Checkpoint service started (interval=%ds)", checkpoint_interval)

        # ── HA 콜백 설정 + 시작 ──────────────────────────────────────────
        async def _on_become_leader() -> None:
            logger.info("HA: This instance is now the leader")

        async def _on_lose_leader() -> None:
            logger.warning("HA: This instance lost leadership")
            if checkpoint_service is not None:
                await checkpoint_service.save_now()

        ha_manager.on_become_leader = _on_become_leader
        ha_manager.on_lose_leader = _on_lose_leader
        await ha_manager.start()

        # ── 위협 인텔리전스 피드 ──────────────────────────────────────────
        feed_mgr = None
        try:
            from netwatcher.threatintel.feed_manager import FeedManager
            feed_mgr = FeedManager(self.config)

            custom_ips     = await blocklist_repo.get_all_custom_ips()
            custom_domains = await blocklist_repo.get_all_custom_domains()
            feed_mgr.load_custom_entries(custom_ips, custom_domains)

            await feed_mgr.update_all()
            for engine in self.registry.engines:
                if hasattr(engine, "set_feeds"):
                    engine.set_feeds(feed_mgr)

            try:
                from netwatcher.web.metrics import feed_last_update
                feed_last_update.set(feed_mgr.last_update_epoch)
            except ImportError:
                pass
        except Exception:
            logger.warning("Threat intel feeds not loaded (non-fatal)", exc_info=True)

        # ── 멀티프로세스 워커 풀 ─────────────────────────────────────────
        from netwatcher.capture.pool import WorkerPool

        num_workers = self.config.get("workers", 1)
        worker_pool = WorkerPool(self.config, num_workers=num_workers)
        worker_pool.start()
        if worker_pool.is_multiprocess:
            logger.info(
                "멀티프로세스 모드: %d 워커 활성",
                worker_pool.num_workers,
            )
        else:
            logger.info("단일프로세스 모드")

        # ── 서비스 ────────────────────────────────────────────────────────
        packet_processor = PacketProcessor(
            observation=observation,
            registry=self.registry,
            dispatcher=dispatcher,
            pcap_writer=self.pcap_writer,
            dns_resolver=self._dns_resolver,
            worker_pool=worker_pool,
        )
        await packet_processor.init_seen_macs(device_repo)

        tick_service = TickService(
            registry=self.registry,
            dispatcher=dispatcher,
            observation=observation,
        )
        tick_service.set_worker_pool(worker_pool)
        tick_service.set_packet_processor(packet_processor)

        stats_flush = StatsFlushService(
            config=self.config,
            stats_repo=stats_repo,
            device_repo=device_repo,
            packet_processor=packet_processor,
        )

        maintenance = MaintenanceService(
            config=self.config,
            event_repo=event_repo,
            stats_repo=stats_repo,
            incident_repo=incident_repo,
            feed_manager=feed_mgr,
            block_manager=block_manager,
        )

        # ── 설정 제안 승인 큐 (PR 10) ────────────────────────────────────
        # AI 는 설정을 바꾸지 못한다. 제안만 큐에 올리고, 사람이 승인한
        # 경우에만 검증된 경로로 반영된다.
        proposal_repo = ConfigProposalRepository(self.db)
        proposal_service = ProposalService(
            registry=self.registry,
            yaml_editor=self._yaml_editor,
            proposal_repo=proposal_repo,
        )

        # ── 시그니처 엔진 (규칙 관리 API용) ───────────────────────────────
        sig_engine = None
        for engine in self.registry.engines:
            if engine.name == "signature":
                sig_engine = engine
                break

        # ── NetFlow/IPFIX 수신기 (선택, enabled: true 시 활성화) ──────────
        # create_app 보다 먼저 초기화해야 FlowEngine이 엔진 목록 API에 노출된다.
        flow_processor = None
        flow_collector = None
        netflow_cfg = self.config.section("netflow") or {}
        if netflow_cfg.get("enabled", False):
            from netwatcher.netflow.collector import FlowCollector
            from netwatcher.netflow.processor import FlowProcessor
            from netwatcher.netflow.engines.port_scan import FlowPortScanEngine
            from netwatcher.netflow.engines.data_exfil import FlowDataExfilEngine

            flow_processor = FlowProcessor(dispatcher=dispatcher)

            engines_cfg = netflow_cfg.get("engines", {})

            ps_cfg = engines_cfg.get("flow_port_scan", {})
            if ps_cfg.get("enabled", True):
                flow_processor.register_engine(FlowPortScanEngine(ps_cfg))

            de_cfg = engines_cfg.get("flow_data_exfil", {})
            if de_cfg.get("enabled", True):
                flow_processor.register_engine(FlowDataExfilEngine(de_cfg))

            flow_collector = FlowCollector(
                processor = flow_processor,
                host      = netflow_cfg.get("host", "0.0.0.0"),
                port      = netflow_cfg.get("port", 2055),
            )
            await flow_collector.start()
            tick_service.set_flow_processor(flow_processor)
            logger.info(
                "NetFlow collector enabled on %s:%d (%d flow engines)",
                netflow_cfg.get("host", "0.0.0.0"),
                netflow_cfg.get("port", 2055),
                len(flow_processor.engines),
            )
        else:
            logger.info("NetFlow collector disabled (netflow.enabled: false)")

        # ── AI 오탐 분석기 (create_app 전 초기화 필수) ───────────────────
        ai_analyzer = None
        ai_analyzer_cfg = self.config.section("ai_analyzer") or {}
        if ai_analyzer_cfg.get("enabled"):
            from netwatcher.services.ai_analyzer import AIAnalyzerService
            ai_analyzer = AIAnalyzerService(
                config=self.config,
                event_repo=event_repo,
                registry=self.registry,
                dispatcher=dispatcher,
                yaml_editor=self._yaml_editor,
                whitelist=self.registry.whitelist,
                proposal_service=proposal_service,
            )

        # ── 리플레이 실행·비교 (계획서 1장, PR 12) ───────────────────────
        # 운영 Dispatcher 를 호출하지 않는 격리 실행이다. 같은 DB 를 쓰지만
        # 운영 events 테이블이 아니라 replay_results 에만 기록한다.
        from netwatcher.replay.runs import ReplayRunService
        from netwatcher.storage.repositories import ReplayRepository

        replay_service = ReplayRunService(ReplayRepository(self.db))

        # ── 조치 생애주기 (계획서 2장, PR 13) ────────────────────────────
        # OS 를 변경하는 백엔드는 없다. 계획서가 "검증된 만료 백엔드·권한
        # 분리·적용 경로 증명이 하나라도 없으면 shadow/제안만 출시한다" 라고
        # 했으므로, 지금은 shadow 실행기만 등록한다. 기존 iptables 자동 차단도
        # 복구 검증 전까지 계속 비활성화한다.
        from netwatcher.response.executor import build_executor, executor_capabilities
        from netwatcher.storage.repositories import (
            ResponseActionRepository,
            ResponseProposalRepository,
        )

        response_repository = ResponseActionRepository(self.db)
        response_proposal_repo = ResponseProposalRepository(self.db)

        # 실행기 선택. nftables 은 구현되어 있지만 **커널 만료가 실측 확인되기
        # 전까지는 스스로를 쓸 수 있다고 말하지 않는다.** 기동 시 자동 검증하면
        # 라이브 장비 방화벽에 우리 테이블을 남기므로, 검증은 운영자가
        #   sudo python -m netwatcher.verify_nftables
        # 로 명시적으로 수행한다.
        backend = (response_cfg or {}).get("backend", "shadow")
        response_executor = build_executor(backend)
        caps = executor_capabilities(backend, response_executor)
        logger.info(
            "Response executor: %s (applies_to_os=%s, kernel_expiry_verified=%s)",
            caps["backend"], caps["applies_to_os"],
            caps.get("kernel_expiry_verified"),
        )
        if caps["applies_to_os"] and not caps.get("kernel_expiry_verified"):
            logger.warning(
                "nftables 백엔드가 구현되어 있으나 커널 만료가 검증되지 않았다 — "
                "적용 시 거부된다. sudo python -m netwatcher.verify_nftables 로 검증한다."
            )

        # ── 웹 서버 ───────────────────────────────────────────────────────
        from netwatcher.observability.observation import KernelDropProbe
        from netwatcher.web.auth import AuthManager
        auth_manager = AuthManager(self.config)

        # 대시보드와 스니퍼가 같은 프로브를 써야 "측정 불가" 와 "측정 안 함" 이
        # 어긋나지 않는다.
        kernel_probe = KernelDropProbe(observation)

        app = create_app(
            config=self.config,
            event_repo=event_repo,
            device_repo=device_repo,
            stats_repo=stats_repo,
            dispatcher=dispatcher,
            auth_manager=auth_manager,
            correlator=self.correlator,
            whitelist=self.registry.whitelist,
            blocklist_repo=blocklist_repo,
            feed_manager=feed_mgr,
            sniffer=None,
            block_manager=block_manager,
            signature_engine=sig_engine,
            registry=self.registry,
            yaml_editor=self._yaml_editor,
            flow_processor=flow_processor,
            ai_analyzer=ai_analyzer,
            proposal_service=proposal_service,
            observation_service=observation,
            kernel_probe=kernel_probe,
            replay_service=replay_service,
            response_repository=response_repository,
            response_executor=response_executor,
            response_proposal_repo=response_proposal_repo,
        )

        import uvicorn
        web_host = self.config.get("web.host", "0.0.0.0")
        web_port = self.config.get("web.port", 38585)

        # TLS 설정
        tls_cfg  = self.config.section("web").get("tls", {})
        ssl_args: dict = {}
        if tls_cfg.get("enabled"):
            certfile = tls_cfg.get("certfile", "")
            keyfile  = tls_cfg.get("keyfile", "")
            if certfile and keyfile:
                ssl_args["ssl_certfile"] = certfile
                ssl_args["ssl_keyfile"]  = keyfile
                logger.info("TLS enabled: cert=%s", certfile)
            else:
                logger.warning("TLS enabled but certfile/keyfile not configured; falling back to HTTP")

        uvi_config = uvicorn.Config(
            app, host=web_host, port=web_port,
            log_level="warning", loop="none",
            **ssl_args,
        )
        server = uvicorn.Server(uvi_config)

        # ── 일일 리포트 스케줄러 ──────────────────────────────────────────
        daily_reporter = None
        daily_cfg    = self.config.section("daily_report") or {}
        channels_cfg = self.config.section("alerts").get("channels", {})
        _any_channel_enabled = any(
            channels_cfg.get(ch, {}).get("enabled")
            for ch in ("slack", "telegram", "discord")
        )
        if daily_cfg.get("enabled") and _any_channel_enabled:
            from netwatcher.alerts.daily_report import DailyReporter
            daily_reporter = DailyReporter(
                config=self.config,
                event_repo=event_repo,
                device_repo=device_repo,
                stats_repo=stats_repo,
            )
            await daily_reporter.start()

        # ── 자산 변경 모니터 ──────────────────────────────────────────────
        asset_monitor = None
        asset_monitor_cfg = self.config.section("asset_monitor") or {}
        if asset_monitor_cfg.get("enabled"):
            from netwatcher.services.asset_monitor import AssetMonitorService
            asset_monitor = AssetMonitorService(
                device_repo=device_repo,
                dispatcher=dispatcher,
                config=self.config,
            )
            await asset_monitor.start()

        # ── AI 오탐 분석기 시작 ──────────────────────────────────────────
        if ai_analyzer is not None:
            await ai_analyzer.start()
            logger.info(
                "AIAnalyzerService started (provider=%s, interval=%dmin)",
                ai_analyzer_cfg.get("provider", "copilot"),
                ai_analyzer_cfg.get("interval_minutes", 15),
            )

        # ── DNS 리졸버 & 스니퍼 ──────────────────────────────────────────
        await self._dns_resolver.start()

        sniffer = PacketSniffer(
            self.config, self.loop, packet_processor.on_packet,
            observation=observation, kernel_probe=kernel_probe,
        )
        sniffer.start()

        # 스니퍼가 필요한 서비스에 주입
        tick_service.set_sniffer(sniffer)
        stats_flush.set_sniffer(sniffer)

        # ── 시그널 처리 ─────────────────────────────────────────────────
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            logger.info("Shutdown signal received")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            self.loop.add_signal_handler(sig, _signal_handler)

        # ── 백그라운드 서비스 시작 ────────────────────────────────────────
        await tick_service.start()
        await stats_flush.start()
        await maintenance.start()
        server_task = asyncio.create_task(server.serve())

        proto = "https" if ssl_args else "http"
        logger.info("NetWatcher ready - Dashboard: %s://%s:%d", proto, web_host, web_port)

        await stop_event.wait()

        # ── 종료 ──────────────────────────────────────────────────────────
        logger.info("Shutting down...")
        if flow_collector is not None:
            flow_collector.stop()
        sniffer.stop()
        worker_pool.stop()
        await tick_service.stop()
        await stats_flush.stop()
        await maintenance.stop()
        self.registry.shutdown()
        await self._dns_resolver.stop()
        if daily_reporter:
            await daily_reporter.stop()
        if asset_monitor:
            await asset_monitor.stop()
        if ai_analyzer:
            await ai_analyzer.stop()
        if checkpoint_service is not None:
            await checkpoint_service.stop()
        await ha_manager.stop()
        server.should_exit = True
        await server_task
        await dispatcher.stop()
        await redis_client.close()
        await self.db.close()
        logger.info("NetWatcher stopped")
