"""컴플라이언스 REST API 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse

from netwatcher.compliance.framework_mapper import FrameworkMapper
from netwatcher.compliance.kpi_calculator import KPICalculator
from netwatcher.compliance.report_generator import ReportGenerator
from netwatcher.detection.registry import EngineRegistry


def create_compliance_router(
    mapper: FrameworkMapper,
    kpi_calc: KPICalculator,
    report_gen: ReportGenerator,
    registry: EngineRegistry,
) -> APIRouter:
    """컴플라이언스 API 라우터를 생성한다."""
    router = APIRouter(prefix="/compliance", tags=["compliance"])

    def _active_engine_names() -> list[str]:
        return [e.name for e in registry.engines]

    @router.get("/frameworks")
    async def list_frameworks():
        """사용 가능한 컴플라이언스 프레임워크 목록."""
        names = mapper.list_frameworks()
        frameworks = []
        for name in names:
            data = mapper.load_framework(name)
            frameworks.append({
                "id":   name,
                "name": data.get("framework", name),
                "controls_count": len(data.get("controls", [])),
            })
        return {"frameworks": frameworks}

    @router.get("/coverage/{framework}")
    async def get_coverage(framework: str):
        """프레임워크별 컨트롤 커버리지 분석."""
        active = _active_engine_names()
        coverage = mapper.get_coverage(framework, active)
        score    = mapper.get_coverage_score(framework, active)
        if not coverage:
            return JSONResponse(
                status_code=404,
                content={"detail": f"Framework '{framework}' not found"},
            )
        return {
            "framework":      framework,
            "coverage_score": score,
            "active_engines": active,
            "controls":       coverage,
        }

    @router.get("/gaps/{framework}")
    async def get_gaps(framework: str):
        """프레임워크별 갭 분석."""
        active = _active_engine_names()
        gaps = mapper.get_gaps(framework, active)
        return {
            "framework":     framework,
            "gap_count":     len(gaps),
            "active_engines": active,
            "gaps":          gaps,
        }

    @router.get("/kpis")
    async def get_kpis(days: int = Query(30, ge=1, le=365)):
        """탐지 효과성 KPI."""
        return await kpi_calc.calculate(days=days)

    @router.get("/report/{framework}")
    async def get_report(
        framework: str,
        fmt: str = Query("json", regex="^(json|html)$"),
        days: int = Query(30, ge=1, le=365),
    ):
        """종합 컴플라이언스 보고서 생성."""
        active = _active_engine_names()
        result = await report_gen.generate(
            framework=framework,
            active_engines=active,
            fmt=fmt,
            days=days,
        )
        if fmt == "html":
            return HTMLResponse(content=result)
        return result

    return router
