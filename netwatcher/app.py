"""메인 오케스트레이터: 캡처, 탐지, 알림, 웹, 스토리지 통합 관리."""

from __future__ import annotations

import asyncio
import logging
import signal

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.registry import EngineRegistry
from netwatcher.response.blocker import BlockManager
from netwatcher.services.maintenance import MaintenanceService
from netwatcher.services.packet_processor import PacketProcessor
from netwatcher.services.stats_flush import StatsFlushService
from netwatcher.services.tick_service import TickService
from netwatcher.storage.database import Database
from netwatcher.storage.repositories import (
    BlocklistRepository,
    DeviceRepository,
    EventRepository,
    IncidentRepository,
    TrafficStatsRepository,
)
from netwatcher.utils.config import Config
from netwatcher.utils.logging_setup import setup_logging
from netwatcher.utils.network import AsyncDNSResolver
from netwatcher.utils.yaml_editor import YamlConfigEditor
from netwatcher.web.server import create_app

logger = logging.getLogger("netwatcher.app")


class NetWatcher:
    """최상위 애플리케이션 오케스트레이터.

    모든 백그라운드 작업을 전담 서비스 객체에 위임하며,
    컴포넌트 연결, 시작 순서 제어, 정상 종료만 담당한다.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.loop: asyncio.AbstractEventLoop | None = None

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
        logger.info("NetWatcher starting...")

        # ── 데이터베이스 & 리포지토리 ──────────────────────────────────
        await self.db.connect()
        event_repo    = EventRepository(self.db)
        device_repo   = DeviceRepository(self.db)
        stats_repo    = TrafficStatsRepository(self.db)
        incident_repo = IncidentRepository(self.db)
        blocklist_repo = BlocklistRepository(self.db)

        self.correlator.set_incident_repo(incident_repo)

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

        # ── 알림 디스패처 ────────────────────────────────────────────────
        dispatcher = AlertDispatcher(
            config=self.config,
            event_repo=event_repo,
            correlator=self.correlator,
            pcap_writer=self.pcap_writer,
            block_manager=block_manager,
        )
        await dispatcher.start()

        # ── 탐지 엔진 ─────────────────────────────────────────────────────
        self.registry.discover_and_register()
        logger.info(
            "Registered %d detection engines: %s",
            len(self.registry.engines),
            [e.name for e in self.registry.engines],
        )

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

        # ── 서비스 ────────────────────────────────────────────────────────
        packet_processor = PacketProcessor(
            registry=self.registry,
            dispatcher=dispatcher,
            pcap_writer=self.pcap_writer,
            dns_resolver=self._dns_resolver,
        )
        await packet_processor.init_seen_macs(device_repo)

        tick_service = TickService(
            registry=self.registry,
            dispatcher=dispatcher,
        )

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

        # ── 웹 서버 ───────────────────────────────────────────────────────
        app = create_app(
            config=self.config,
            event_repo=event_repo,
            device_repo=device_repo,
            stats_repo=stats_repo,
            dispatcher=dispatcher,
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

        # ── DNS 리졸버 & 스니퍼 ──────────────────────────────────────────
        await self._dns_resolver.start()

        sniffer = PacketSniffer(self.config, self.loop, packet_processor.on_packet)
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
        await tick_service.stop()
        await stats_flush.stop()
        await maintenance.stop()
        self.registry.shutdown()
        await self._dns_resolver.stop()
        if daily_reporter:
            await daily_reporter.stop()
        if asset_monitor:
            await asset_monitor.stop()
        server.should_exit = True
        await server_task
        await dispatcher.stop()
        await self.db.close()
        logger.info("NetWatcher stopped")
