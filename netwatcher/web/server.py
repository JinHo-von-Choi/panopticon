"""FastAPI 애플리케이션 팩토리."""

from __future__ import annotations

import ipaddress
import logging
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.whitelist import Whitelist
from netwatcher.storage.repositories import (
    BlocklistRepository,
    DeviceRepository,
    EventRepository,
    TrafficStatsRepository,
)
from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.utils.config import Config
from netwatcher.response.blocker import BlockManager
from netwatcher.web.auth import AuthManager, AuthMiddleware
from netwatcher.web.routes.blocklist import create_blocklist_router
from netwatcher.web.routes.blocks import create_blocks_router
from netwatcher.web.routes.devices import create_devices_router
from netwatcher.web.routes.events import create_events_router
from netwatcher.web.routes.incidents import create_incidents_router
from netwatcher.web.routes.stats import create_stats_router
from netwatcher.web.routes.rules import create_rules_router
from netwatcher.web.routes.whitelist import create_whitelist_router

logger = logging.getLogger(__name__)


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# 인메모리 API 속도 제한기
# ---------------------------------------------------------------------------
class _RateLimiter:
    """API 엔드포인트용 단순 인메모리 슬라이딩 윈도우 속도 제한기."""

    def __init__(self) -> None:
        """타임스탬프 기반 요청 기록 딕셔너리를 초기화한다."""
        self._requests: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str, max_requests: int, window: int) -> bool:
        """윈도우 내 요청 수가 제한 미만이면 True를 반환한다."""
        now    = time.time()
        cutoff = now - window
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
        if len(self._requests[key]) >= max_requests:
            return False
        self._requests[key].append(now)
        return True


# ---------------------------------------------------------------------------
# 미들웨어 설정
# ---------------------------------------------------------------------------
def _setup_middleware(app: FastAPI, config: Config, auth_manager: AuthManager) -> None:
    """CORS, 인증, 요청 ID, 보안 헤더, API 속도 제한 미들웨어를 등록한다."""

    # CORS
    cors_config     = config.section("web").get("cors", {})
    allowed_origins = cors_config.get("allowed_origins", ["http://localhost:38585"])
    allow_creds     = "*" not in allowed_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_creds,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    if auth_manager.enabled:
        app.add_middleware(AuthMiddleware, auth_manager=auth_manager)

    # 요청 ID 미들웨어
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        """요청/응답에 고유 X-Request-ID 헤더를 부여한다."""
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        response   = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # 보안 헤더 미들웨어
    default_csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:"
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        """모든 응답에 보안 관련 HTTP 헤더를 추가한다."""
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        csp = config.section("web").get("csp", default_csp)
        response.headers["Content-Security-Policy"] = csp
        return response

    # API 속도 제한 미들웨어
    rate_limiter = _RateLimiter()
    raw_proxies  = config.section("web").get("trusted_proxies", ["127.0.0.1", "::1"])
    trusted_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for proxy in raw_proxies:
        try:
            trusted_nets.append(ipaddress.ip_network(proxy, strict=False))
        except ValueError:
            logger.warning("무효한 trusted_proxy 항목 무시: %s", proxy)

    def _get_client_ip(request: Request) -> str:
        """신뢰된 프록시 헤더를 고려하여 실제 클라이언트 IP를 추출한다.

        직접 연결이 구성된 신뢰된 프록시 주소에서 온 경우에만
        X-Forwarded-For를 신뢰한다.
        """
        direct_ip = request.client.host if request.client else "unknown"
        if direct_ip == "unknown":
            return direct_ip
        try:
            addr = ipaddress.ip_address(direct_ip)
        except ValueError:
            return direct_ip
        if not any(addr in net for net in trusted_nets):
            return direct_ip
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return direct_ip

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """클라이언트 IP 기반 API 요청 속도를 제한한다."""
        path = request.url.path
        if path.startswith("/api/"):
            client_ip = _get_client_ip(request)
            if path == "/api/auth/login":
                if not rate_limiter.allow(f"login:{client_ip}", max_requests=10, window=60):
                    return JSONResponse({"error": "Too many requests"}, status_code=429)
            else:
                auth_header = request.headers.get("authorization", "")
                limit = 200 if auth_header.startswith("Bearer ") else 60
                if not rate_limiter.allow(f"api:{client_ip}", max_requests=limit, window=60):
                    return JSONResponse({"error": "Too many requests"}, status_code=429)
        return await call_next(request)


# ---------------------------------------------------------------------------
# 인증 엔드포인트
# ---------------------------------------------------------------------------
def _register_auth_endpoints(app: FastAPI, auth_manager: AuthManager) -> None:
    """로그인, 상태 조회, 토큰 검증 엔드포인트를 등록한다."""

    @app.get("/api/auth/status")
    async def auth_status():
        """인증 기능 활성화 상태를 반환한다."""
        return {"enabled": auth_manager.enabled}

    @app.post("/api/auth/login")
    async def auth_login(body: LoginRequest):
        """사용자 자격증명으로 로그인하여 JWT 토큰을 발급한다."""
        token = auth_manager.authenticate(body.username, body.password)
        if not token:
            return JSONResponse({"error": "Invalid credentials"}, status_code=401)
        return {"token": token}

    @app.get("/api/auth/check")
    async def auth_check(request: Request):
        """Bearer 토큰의 유효성을 검증한다."""
        if not auth_manager.enabled:
            return {"valid": True}
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "Missing token"}, status_code=401)
        token   = auth_header[7:]
        payload = auth_manager.verify_token(token)
        if not payload:
            return JSONResponse({"error": "Invalid or expired token"}, status_code=401)
        return {"valid": True, "user": payload.get("sub")}


# ---------------------------------------------------------------------------
# 시스템 엔드포인트 (헬스체크, 메트릭)
# ---------------------------------------------------------------------------
def _register_system_endpoints(
    app: FastAPI,
    event_repo: EventRepository,
    sniffer,
    feed_manager: FeedManager | None,
    dispatcher: AlertDispatcher,
) -> None:
    """헬스체크(/health)와 Prometheus 메트릭(/metrics) 엔드포인트를 등록한다."""

    @app.get("/health")
    async def health_check():
        """DB, 스니퍼, 피드, 알림 큐 등 시스템 상태를 점검한다."""
        checks: dict = {}

        try:
            await event_repo._db.pool.fetchval("SELECT 1")
            checks["database"] = "ok"
        except Exception as e:
            logger.error("Health check DB probe failed: %s", e)
            checks["database"] = "error"

        if sniffer is not None:
            checks["sniffer"] = "running" if sniffer.is_running else "stopped"
        else:
            checks["sniffer"] = "not_configured"

        if feed_manager is not None:
            age = time.time() - feed_manager.last_update_epoch
            if feed_manager.last_update_epoch == 0:
                checks["feeds"] = "not_loaded"
            elif age < 86400:
                checks["feeds"] = "ok"
            else:
                checks["feeds"] = f"stale ({age / 3600:.0f}h)"
        else:
            checks["feeds"] = "not_configured"

        checks["alert_queue"] = dispatcher._queue.qsize()

        healthy_values = {"ok", "running", "not_configured", "not_loaded"}
        overall = "ok" if all(
            v in healthy_values or isinstance(v, int)
            for v in checks.values()
        ) else "degraded"
        status_code = 200 if overall == "ok" else 503
        return JSONResponse({"status": overall, "checks": checks}, status_code=status_code)

    @app.get("/metrics")
    async def metrics_endpoint():
        """Prometheus 형식의 메트릭 데이터를 반환한다."""
        try:
            from netwatcher.web.metrics import get_metrics_output
            return Response(
                content=get_metrics_output(),
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )
        except ImportError:
            return JSONResponse({"error": "prometheus-client not installed"}, status_code=501)


# ---------------------------------------------------------------------------
# API 라우터 및 정적 파일 등록
# ---------------------------------------------------------------------------
def _register_routers_and_static(
    app: FastAPI,
    static_dir: Path,
    index_html: Path,
    event_repo: EventRepository,
    device_repo: DeviceRepository,
    stats_repo: TrafficStatsRepository,
    dispatcher: AlertDispatcher,
    auth_manager: AuthManager,
    correlator: AlertCorrelator | None,
    whitelist: Whitelist | None,
    blocklist_repo: BlocklistRepository | None,
    feed_manager: FeedManager | None,
    block_manager: BlockManager | None,
    signature_engine,
    registry,
    yaml_editor,
) -> None:
    """API 라우터, 정적 에셋, 루트 경로를 등록한다."""

    # 필수 라우터 (항상 등록)
    app.include_router(
        create_events_router(event_repo, dispatcher, auth_manager=auth_manager),
        prefix="/api",
    )
    app.include_router(create_devices_router(device_repo), prefix="/api")
    app.include_router(create_stats_router(stats_repo, event_repo), prefix="/api")

    # 선택적 라우터 (의존 컴포넌트가 있을 때만 등록)
    if correlator:
        app.include_router(create_incidents_router(correlator), prefix="/api")

    if whitelist:
        app.include_router(create_whitelist_router(whitelist), prefix="/api")

    if blocklist_repo and feed_manager:
        app.include_router(create_blocklist_router(blocklist_repo, feed_manager), prefix="/api")

    if block_manager is not None:
        app.include_router(create_blocks_router(block_manager), prefix="/api")

    if signature_engine is not None:
        app.include_router(create_rules_router(signature_engine), prefix="/api")

    if registry is not None and yaml_editor is not None:
        from netwatcher.web.routes.engines import create_engines_router
        app.include_router(create_engines_router(registry, yaml_editor), prefix="/api")

    # 정적 에셋 마운트 (API 라우터 등록 후)
    app.mount("/css", StaticFiles(directory=str(static_dir / "css")), name="css")
    app.mount("/js",  StaticFiles(directory=str(static_dir / "js")),  name="js")
    app.mount("/img", StaticFiles(directory=str(static_dir / "img")), name="img")

    @app.get("/")
    async def root():
        """대시보드 메인 페이지(index.html)를 반환한다."""
        return FileResponse(str(index_html))


# ---------------------------------------------------------------------------
# 애플리케이션 팩토리
# ---------------------------------------------------------------------------
def create_app(
    config: Config,
    event_repo: EventRepository,
    device_repo: DeviceRepository,
    stats_repo: TrafficStatsRepository,
    dispatcher: AlertDispatcher,
    correlator: AlertCorrelator | None = None,
    whitelist: Whitelist | None = None,
    blocklist_repo: BlocklistRepository | None = None,
    feed_manager: FeedManager | None = None,
    sniffer=None,
    block_manager: BlockManager | None = None,
    signature_engine=None,
    registry=None,
    yaml_editor=None,
) -> FastAPI:
    """FastAPI 애플리케이션을 생성하고 구성한다."""
    enable_docs = config.get("web.enable_docs", False)
    app = FastAPI(
        title="NetWatcher",
        description="Local Network Packet Monitoring Dashboard",
        version="0.3.0",
        docs_url="/docs" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
    )

    static_dir = Path(__file__).parent / "static"
    auth_manager = AuthManager(config)

    _setup_middleware(app, config, auth_manager)
    _register_auth_endpoints(app, auth_manager)
    _register_system_endpoints(app, event_repo, sniffer, feed_manager, dispatcher)
    _register_routers_and_static(
        app, static_dir, static_dir / "index.html",
        event_repo, device_repo, stats_repo, dispatcher, auth_manager,
        correlator, whitelist, blocklist_repo, feed_manager,
        block_manager, signature_engine, registry, yaml_editor,
    )

    return app
