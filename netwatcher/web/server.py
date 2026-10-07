"""FastAPI 애플리케이션 팩토리 (Path Standardized)."""

from __future__ import annotations

import logging
from pathlib import Path
from fastapi import FastAPI, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from netwatcher.web.auth import AuthMiddleware
from netwatcher.web.routes.devices import create_devices_router
from netwatcher.web.routes.stats import create_stats_router
from netwatcher.web.routes.events import create_events_router, create_ws_router

def create_app(config, event_repo, device_repo, stats_repo, dispatcher, auth_manager=None, sniffer=None, correlator=None, whitelist=None, blocklist_repo=None, feed_manager=None, block_manager=None, signature_engine=None, registry=None, yaml_editor=None, flow_processor=None, ai_analyzer=None, proposal_service=None, observation_service=None, kernel_probe=None, replay_service=None, response_repository=None, response_executor=None, response_proposal_repo=None, health_checker=None, audit_logger=None, audit_required=False, pcap_writer=None):
    web_cfg = config.section("web") if hasattr(config, 'section') else {}
    cors_cfg = web_cfg.get("cors", {}) if isinstance(web_cfg, dict) else {}
    allowed_origins = cors_cfg.get("allowed_origins", ["http://localhost:38585"])
    enable_docs = web_cfg.get("enable_docs", False) if isinstance(web_cfg, dict) else False
    docs_url = "/docs" if enable_docs else None
    openapi_url = "/openapi.json" if enable_docs else None

    app = FastAPI(title="Panopticon API", docs_url=docs_url, openapi_url=openapi_url)
    static_dir = Path(__file__).parent / "static"

    # CORS & Auth Middleware
    app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_methods=["*"], allow_headers=["*"])
    if auth_manager:
        app.add_middleware(AuthMiddleware, auth_manager=auth_manager)
        # rbac.require_role() 이 토큰 role 클레임을 보려면 app.state 가 필요하다.
        # 이게 없으면 권한 검사가 조용히 anonymous-admin 으로 통과한다(PR 03).
        app.state.auth_manager = auth_manager

    from netwatcher.web.api_rate_limiter import APIRateLimiter
    from netwatcher.web.request_guard import RequestGuard
    from netwatcher.observability.health import HealthChecker
    auth_cfg = config.section("auth")
    auth_cfg = auth_cfg if isinstance(auth_cfg, dict) else {}
    rate_cfg = auth_cfg.get("api_rate_limit", {})
    limiter = APIRateLimiter(requests_per_minute=rate_cfg.get("requests_per_minute", 60),
                             burst=rate_cfg.get("burst", 10)) if rate_cfg.get("enabled", True) else None
    app.state.login_limiter = APIRateLimiter(requests_per_minute=auth_cfg.get("login_attempts_per_minute", 10), burst=0)
    app.state.audit_logger = audit_logger
    app.state.audit_required = audit_required
    app.state.health_checker = health_checker or HealthChecker(
        dispatcher=dispatcher, sniffer=sniffer, registry=registry, observation=observation_service,
    )
    app.add_middleware(RequestGuard, limiter=limiter, audit_logger=audit_logger)

    # 피드 신선도는 상태 경로에서 조회하므로 app.state 로 노출한다 (PR 07)
    if feed_manager is not None:
        app.state.feed_manager = feed_manager

    # 관측 범위 (PR 11)
    if observation_service is not None:
        app.state.observation_service = observation_service

    # API Routers (Standardized Prefix)
    api_prefix = "/api"
    # 인증이 꺼져 있어도 /auth/status는 응답해야 대시보드가 로그인 화면 표시 여부를 판단한다.
    from netwatcher.web.routes.auth import create_auth_router
    app.include_router(create_auth_router(auth_manager), prefix=api_prefix)
    app.include_router(create_events_router(event_repo, dispatcher, pcap_writer=pcap_writer, auth_manager=auth_manager, device_repo=device_repo), prefix=api_prefix)
    app.include_router(create_ws_router(dispatcher, auth_manager=auth_manager), prefix=api_prefix)
    app.include_router(create_devices_router(device_repo), prefix=api_prefix)
    from netwatcher.web.routes.onboarding import create_onboarding_router
    app.include_router(create_onboarding_router(config, app.state.health_checker,
                       observation_service, auth_manager, yaml_editor), prefix=api_prefix)
    app.include_router(create_stats_router(stats_repo, event_repo, correlator=correlator), prefix=api_prefix)

    if whitelist:
        from netwatcher.web.routes.whitelist import create_whitelist_router
        app.include_router(create_whitelist_router(whitelist, yaml_editor), prefix=api_prefix)

    if blocklist_repo and feed_manager:
        from netwatcher.web.routes.blocklist import create_blocklist_router
        app.include_router(create_blocklist_router(blocklist_repo, feed_manager), prefix=api_prefix)

    if registry and yaml_editor:
        from netwatcher.web.routes.engines import create_engines_router
        app.include_router(create_engines_router(registry, yaml_editor, flow_processor=flow_processor), prefix=api_prefix)

    if correlator:
        from netwatcher.web.routes.incidents import create_incidents_router
        app.include_router(create_incidents_router(correlator), prefix=api_prefix)

    if block_manager:
        from netwatcher.web.routes.blocks import create_blocks_router
        app.include_router(create_blocks_router(block_manager), prefix=api_prefix)

    if signature_engine:
        from netwatcher.web.routes.rules import create_rules_router
        app.include_router(create_rules_router(signature_engine), prefix=api_prefix)

    if ai_analyzer:
        from netwatcher.web.routes.ai_analyzer import create_ai_analyzer_router
        app.include_router(create_ai_analyzer_router(ai_analyzer), prefix=api_prefix)

    if response_proposal_repo is not None:
        from netwatcher.web.routes.response_proposals import (
            create_response_proposals_router,
        )
        app.include_router(
            create_response_proposals_router(response_proposal_repo), prefix=api_prefix,
        )

    if response_repository is not None and response_executor is not None:
        from netwatcher.web.routes.response import create_response_router
        app.include_router(
            create_response_router(response_repository, response_executor),
            prefix=api_prefix,
        )

    if replay_service is not None:
        from netwatcher.web.routes.replay import create_replay_router
        app.include_router(create_replay_router(replay_service), prefix=api_prefix)

    if observation_service is not None:
        from netwatcher.web.routes.observation import create_observation_router
        app.include_router(
            create_observation_router(observation_service, kernel_probe),
            prefix=api_prefix,
        )

    if proposal_service:
        from netwatcher.web.routes.proposals import create_proposals_router
        app.include_router(
            create_proposals_router(proposal_service), prefix=api_prefix
        )

    # Threat Hunting
    from netwatcher.hunting.ioc_correlator import IOCCorrelator
    from netwatcher.hunting.mitre_navigator import MITRENavigator
    from netwatcher.hunting.timeline import ThreatTimeline
    from netwatcher.web.routes.hunting import create_hunting_router
    _ioc_correlator = IOCCorrelator(event_repo)
    _navigator      = MITRENavigator()
    _timeline       = ThreatTimeline(event_repo)
    app.include_router(
        create_hunting_router(event_repo, _ioc_correlator, _navigator, _timeline),
        prefix=api_prefix,
    )

    @app.get("/health")
    async def health_check():
        """프로세스 liveness. 센서·DB 준비 상태는 /ready에서 조회한다."""
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready():
        result = await app.state.health_checker.readiness()
        return JSONResponse({"status": "ready" if result["ready"] else "not_ready"},
                            status_code=200 if result["ready"] else 503)

    from netwatcher.web.rbac import Role, require_role

    @app.get("/api/health", dependencies=[Depends(require_role(Role.VIEWER))])
    async def detailed_health():
        return await app.state.health_checker.readiness()

    @app.get("/api/support-profile")
    async def support_profile():
        """현재 설정이 지원하는 배포 조합과 위반 사항을 노출한다 (PR 01).

        대시보드가 "차단이 실제로 적용된다"고 오인하지 않도록, enforcement
        백엔드·프로필·위반 목록을 함께 반환한다.

        위협 피드 상태(PR 07)도 함께 노출한다. 갱신 루프가 살아 있어도 모든
        다운로드가 실패하면 threat_intel 엔진은 아무것도 탐지하지 못하므로,
        "작동 중" 과 "지표가 최신" 을 구분해 보여준다.

        관측 상태(PR 11)도 함께 노출한다. **계약 통과와 실제 관측은 별개다.**
        프로필이 유효해도 센서가 stale 이면 대시보드는 그 사실을 함께 보여줘야
        한다. 상세 조회는 ``GET /api/observation`` 을 사용한다.
        """
        from netwatcher.support import SupportContract

        payload = SupportContract(config).describe()

        observation = getattr(app.state, "observation_service", None)
        if observation is not None:
            # 계약 통과와 실제 관측은 별개다. 프로필이 유효해도 센서가
            # stale 이면 대시보드는 그 사실을 함께 보여줘야 한다.
            try:
                payload["observation"] = observation.snapshot()
            except Exception:
                payload["observation"] = {"state": "unknown", "reasons": ["관측 상태 조회 실패"]}

        manager = getattr(app.state, "feed_manager", None)
        if manager is not None:
            try:
                health = manager.feed_health()
                violations = manager.health_as_violations() if health["status"] != "ok" else []
            except Exception:
                health = {"status": "unknown", "reason": "위협 피드 상태 조회 실패"}
                violations = []
            payload["feeds"] = health
            if health["status"] != "ok":
                payload["violations"] = list(payload["violations"]) + [
                    v.as_dict() for v in violations
                ]
                payload["profile_note"] = (
                    "위반이 있어도 기동은 하지만, threat_intel 은 지표가 없어 "
                    "탐지하지 않는다"
                )
        return payload

    # Static Assets
    app.mount("/css",     StaticFiles(directory=str(static_dir / "css")),     name="css")
    app.mount("/js",      StaticFiles(directory=str(static_dir / "js")),      name="js")
    app.mount("/locales", StaticFiles(directory=str(static_dir / "locales")), name="locales")
    app.mount("/img",     StaticFiles(directory=str(static_dir / "img")),     name="img")
    app.mount("/fonts",   StaticFiles(directory=str(static_dir / "fonts")),   name="fonts")

    @app.get("/")
    async def root(): return FileResponse(str(static_dir / "index.html"))

    return app
