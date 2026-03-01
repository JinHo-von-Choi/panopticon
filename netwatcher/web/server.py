"""FastAPI 애플리케이션 팩토리 (Path Standardized)."""

from __future__ import annotations

import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from netwatcher.web.auth import AuthMiddleware
from netwatcher.web.routes.devices import create_devices_router
from netwatcher.web.routes.stats import create_stats_router
from netwatcher.web.routes.events import create_events_router, create_ws_router

def create_app(config, event_repo, device_repo, stats_repo, dispatcher, auth_manager, sniffer=None, correlator=None, whitelist=None, blocklist_repo=None, feed_manager=None, block_manager=None, signature_engine=None, registry=None, yaml_editor=None, flow_processor=None, ai_analyzer=None):
    app = FastAPI(title="Panopticon API")
    static_dir = Path(__file__).parent / "static"

    # CORS & Auth Middleware
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    if auth_manager: app.add_middleware(AuthMiddleware, auth_manager=auth_manager)

    # API Routers (Standardized Prefix)
    api_prefix = "/api"
    if auth_manager:
        from netwatcher.web.routes.auth import create_auth_router
        app.include_router(create_auth_router(auth_manager), prefix=api_prefix)
    app.include_router(create_events_router(event_repo, dispatcher, auth_manager=auth_manager), prefix=api_prefix)
    app.include_router(create_ws_router(dispatcher, auth_manager=auth_manager), prefix=api_prefix)
    app.include_router(create_devices_router(device_repo), prefix=api_prefix)
    app.include_router(create_stats_router(stats_repo, event_repo), prefix=api_prefix)

    if whitelist:
        from netwatcher.web.routes.whitelist import create_whitelist_router
        app.include_router(create_whitelist_router(whitelist, yaml_editor), prefix=api_prefix)

    if blocklist_repo and feed_manager:
        from netwatcher.web.routes.blocklist import create_blocklist_router
        app.include_router(create_blocklist_router(blocklist_repo, feed_manager), prefix=api_prefix)

    if registry and yaml_editor:
        from netwatcher.web.routes.engines import create_engines_router
        app.include_router(create_engines_router(registry, yaml_editor, flow_processor=flow_processor), prefix=api_prefix)

    if ai_analyzer:
        from netwatcher.web.routes.ai_analyzer import create_ai_analyzer_router
        app.include_router(create_ai_analyzer_router(ai_analyzer), prefix=api_prefix)

    # Static Assets
    app.mount("/css",     StaticFiles(directory=str(static_dir / "css")),     name="css")
    app.mount("/js",      StaticFiles(directory=str(static_dir / "js")),      name="js")
    app.mount("/locales", StaticFiles(directory=str(static_dir / "locales")), name="locales")
    app.mount("/img",     StaticFiles(directory=str(static_dir / "img")),     name="img")

    @app.get("/")
    async def root(): return FileResponse(str(static_dir / "index.html"))

    return app
