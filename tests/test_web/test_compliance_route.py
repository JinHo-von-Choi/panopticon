"""컴플라이언스 커버리지: 분리 콘솔은 센서가 알려 준 활성 엔진으로 계산한다."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.compliance.framework_mapper import FrameworkMapper
from netwatcher.web.routes.compliance import create_compliance_router


def _app(engine_names):
    mapper = FrameworkMapper()
    app = FastAPI()
    app.include_router(create_compliance_router(
        mapper, SimpleNamespace(), SimpleNamespace(), SimpleNamespace(engines=[]), engine_names), prefix="/api")
    return app, mapper.list_frameworks()[0]


async def _get(app, path):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path)


@pytest.mark.asyncio
async def test_coverage_uses_sensor_engine_states():
    seen = []

    async def sensor_engines(actor):
        seen.append(actor["sub"])
        return ["port_scan", "arp_spoof", "dns_anomaly"]

    app, framework = _app(sensor_engines)
    with_sensor = (await _get(app, f"/api/compliance/coverage/{framework}")).json()
    empty_app, _ = _app(None)
    without = (await _get(empty_app, f"/api/compliance/coverage/{framework}")).json()
    assert seen == ["anonymous"]
    assert with_sensor != without


@pytest.mark.asyncio
async def test_unreachable_sensor_is_reported_not_zero_coverage():
    async def sensor_down(actor):
        raise ConnectionError("socket closed")

    app, framework = _app(sensor_down)
    for path in (f"/api/compliance/coverage/{framework}", f"/api/compliance/gaps/{framework}"):
        assert (await _get(app, path)).status_code == 503
