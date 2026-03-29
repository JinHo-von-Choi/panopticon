"""ReportGenerator 단위 테스트."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml

from netwatcher.compliance.framework_mapper import FrameworkMapper
from netwatcher.compliance.kpi_calculator import KPICalculator
from netwatcher.compliance.report_generator import ReportGenerator


@pytest.fixture
def compliance_dir(tmp_path: Path) -> Path:
    d = tmp_path / "compliance"
    d.mkdir()

    fw = {
        "framework": "Test Framework v1",
        "controls": [
            {
                "id": "CTRL-01",
                "name": "Basic monitoring",
                "description": "Basic network monitoring",
                "engines": ["port_scan", "dns_anomaly"],
            },
            {
                "id": "CTRL-02",
                "name": "Threat detection",
                "description": "Detect threats",
                "engines": ["threat_intel"],
            },
        ],
    }
    (d / "test_fw.yaml").write_text(yaml.dump(fw))
    return d


@pytest.fixture
def mapper(compliance_dir: Path) -> FrameworkMapper:
    return FrameworkMapper(mappings_dir=str(compliance_dir))


@pytest.fixture
def mock_kpi_calc() -> KPICalculator:
    calc = AsyncMock(spec=KPICalculator)
    calc.calculate = AsyncMock(return_value={
        "period_days":          30,
        "alert_volume":         100,
        "severity_distribution": {"CRITICAL": 5, "WARNING": 45, "INFO": 50},
        "top_engines":          [{"engine": "port_scan", "count": 60}],
        "top_sources":          [{"ip": "10.0.0.1", "count": 20}],
        "trend":                [{"date": "2026-03-01", "count": 10}],
        "mttd_seconds":         1800.0,
        "alerts_per_day":       3.33,
    })
    return calc


@pytest.fixture
def report_gen(
    mapper: FrameworkMapper, mock_kpi_calc: KPICalculator,
) -> ReportGenerator:
    return ReportGenerator(mapper, mock_kpi_calc)


@pytest.mark.asyncio
async def test_generate_json(report_gen: ReportGenerator):
    result = await report_gen.generate(
        framework="test_fw",
        active_engines=["port_scan", "dns_anomaly", "threat_intel"],
        fmt="json",
    )

    assert isinstance(result, dict)
    assert result["framework"] == "Test Framework v1"
    assert result["coverage_score"] == 1.0
    assert result["total_controls"] == 2
    assert result["covered_count"] == 2
    assert result["gap_count"] == 0
    assert "kpis" in result
    assert result["kpis"]["alert_volume"] == 100


@pytest.mark.asyncio
async def test_generate_json_with_gaps(report_gen: ReportGenerator):
    result = await report_gen.generate(
        framework="test_fw",
        active_engines=["port_scan"],
        fmt="json",
    )

    assert isinstance(result, dict)
    assert result["gap_count"] == 1
    assert result["partial_count"] == 1
    assert result["coverage_score"] < 1.0


@pytest.mark.asyncio
async def test_generate_html(report_gen: ReportGenerator):
    result = await report_gen.generate(
        framework="test_fw",
        active_engines=["port_scan", "dns_anomaly"],
        fmt="html",
    )

    assert isinstance(result, str)
    assert "<!DOCTYPE html>" in result
    assert "Test Framework v1" in result
    assert "CTRL-01" in result
    assert "CTRL-02" in result


@pytest.mark.asyncio
async def test_html_contains_kpi_data(report_gen: ReportGenerator):
    result = await report_gen.generate(
        framework="test_fw",
        active_engines=["port_scan"],
        fmt="html",
    )

    assert "Alert Volume" in result
    assert "100" in result
    assert "1800s" in result  # MTTD


@pytest.mark.asyncio
async def test_html_escapes_special_chars(
    compliance_dir: Path, mock_kpi_calc: KPICalculator,
):
    """HTML 특수문자가 이스케이프되는지 확인한다."""
    fw = {
        "framework": "Test <script>alert(1)</script>",
        "controls": [
            {
                "id": "XSS-01",
                "name": "Test <b>bold</b>",
                "description": "",
                "engines": ["x"],
            },
        ],
    }
    (compliance_dir / "xss_test.yaml").write_text(yaml.dump(fw))

    mapper = FrameworkMapper(mappings_dir=str(compliance_dir))
    gen    = ReportGenerator(mapper, mock_kpi_calc)
    result = await gen.generate(
        framework="xss_test", active_engines=[], fmt="html",
    )

    assert "<script>" not in result
    assert "&lt;script&gt;" in result


@pytest.mark.asyncio
async def test_generate_missing_framework(report_gen: ReportGenerator):
    result = await report_gen.generate(
        framework="nonexistent",
        active_engines=["x"],
        fmt="json",
    )

    assert isinstance(result, dict)
    assert result["total_controls"] == 0
    assert result["coverage_score"] == 0.0
