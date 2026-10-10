"""컴플라이언스 REST API 라우트."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

from netwatcher.compliance.framework_mapper import FrameworkMapper
from netwatcher.compliance.kpi_calculator import KPICalculator
from netwatcher.compliance.report_generator import ReportGenerator
from netwatcher.web.rbac import Role, require_role

if TYPE_CHECKING:
    # 레지스트리는 scapy를 끌어온다. 캡처 없는 EVE 콘솔도 이 라우터를 쓴다.
    from netwatcher.detection.registry import EngineRegistry


def create_compliance_router(
    mapper: FrameworkMapper,
    kpi_calc: KPICalculator,
    report_gen: ReportGenerator,
    registry: EngineRegistry,
    engine_names=None,
) -> APIRouter:
    """컴플라이언스 API 라우터를 생성한다.

    engine_names는 분리 콘솔에서 센서의 활성 엔진 이름을 돌려주는 비동기 함수다.
    """
    router = APIRouter(prefix="/compliance", tags=["compliance"])

    async def _active_engine_names(actor) -> list[str]:
        if engine_names is None:
            return [e.name for e in registry.engines]
        try:
            return await engine_names(actor)
        except Exception:
            # 엔진 상태를 모르면 커버리지 0%로 보이게 하지 않는다.
            raise HTTPException(503, "센서의 엔진 상태를 확인할 수 없어 커버리지를 계산하지 않습니다.") from None

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
    async def get_coverage(framework: str, actor=Depends(require_role(Role.VIEWER))):
        """프레임워크별 컨트롤 커버리지 분석."""
        active = await _active_engine_names(actor)
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
    async def get_gaps(framework: str, actor=Depends(require_role(Role.VIEWER))):
        """프레임워크별 갭 분석."""
        active = await _active_engine_names(actor)
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
        actor=Depends(require_role(Role.VIEWER)),
    ):
        """종합 컴플라이언스 보고서 생성."""
        active = await _active_engine_names(actor)
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
