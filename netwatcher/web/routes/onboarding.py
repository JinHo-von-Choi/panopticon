"""조회 전용 설치 점검 API."""
import asyncio

from fastapi import APIRouter, Depends

from netwatcher.services.onboarding import build_report, storage_probe
from netwatcher.utils.yaml_editor import ConfigurationReadOnlyError
from netwatcher.web.rbac import Role, require_role


def create_onboarding_router(config, health_checker, observation=None, auth_manager=None, yaml_editor=None):
    router = APIRouter(tags=['onboarding'])

    @router.get('/onboarding', dependencies=[Depends(require_role(Role.VIEWER))])
    async def installation_report():
        health = await health_checker.readiness()
        writable = None
        if yaml_editor is not None:
            try:
                await asyncio.to_thread(yaml_editor.ensure_writable)
                writable = True
            except ConfigurationReadOnlyError:
                writable = False
            except OSError:
                writable = None
        required = max(0, int(config.get('evidence.max_storage_mb', 500))) * 1024 * 1024 + 128 * 1024 * 1024
        if config.get('input.mode', 'native') == 'eve':
            storage = {'status': 'unknown', 'reason': 'database_storage_unverified'}
        else:
            storage = await asyncio.to_thread(storage_probe, str(config.get('evidence.directory', 'data/pcaps')), required)
        return build_report(config, health, observation.snapshot() if observation else None,
                            storage=storage, auth_enabled=bool(auth_manager and auth_manager.enabled),
                            config_writable=writable)
    return router
