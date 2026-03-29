"""컴플라이언스 보고서 생성.

JSON 또는 HTML 형식으로 프레임워크 커버리지, 갭 분석, KPI를 포함한
종합 보고서를 생성한다.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from netwatcher.compliance.framework_mapper import FrameworkMapper
from netwatcher.compliance.kpi_calculator import KPICalculator


class ReportGenerator:
    """컴플라이언스 보고서를 생성한다."""

    def __init__(
        self,
        mapper: FrameworkMapper,
        kpi_calc: KPICalculator,
    ) -> None:
        self._mapper   = mapper
        self._kpi_calc = kpi_calc

    async def generate(
        self,
        framework: str,
        active_engines: list[str],
        fmt: str = "json",
        days: int = 30,
    ) -> str | dict[str, Any]:
        """컴플라이언스 보고서를 생성한다.

        Args:
            framework: 프레임워크 이름.
            active_engines: 활성 엔진 목록.
            fmt: 'json' 또는 'html'.
            days: KPI 분석 기간(일).

        Returns:
            JSON 형식이면 dict, HTML 형식이면 str.
        """
        fw_data  = self._mapper.load_framework(framework)
        coverage = self._mapper.get_coverage(framework, active_engines)
        gaps     = self._mapper.get_gaps(framework, active_engines)
        score    = self._mapper.get_coverage_score(framework, active_engines)
        kpis     = await self._kpi_calc.calculate(days=days)

        report: dict[str, Any] = {
            "framework":      fw_data.get("framework", framework),
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "active_engines": active_engines,
            "coverage_score": score,
            "total_controls": len(coverage),
            "covered_count":  sum(1 for v in coverage.values() if v["status"] == "covered"),
            "partial_count":  sum(1 for v in coverage.values() if v["status"] == "partial"),
            "gap_count":      len(gaps),
            "coverage":       coverage,
            "gaps":           gaps,
            "kpis":           kpis,
        }

        if fmt == "html":
            return self._render_html(report)
        return report

    def _render_html(self, report: dict[str, Any]) -> str:
        """보고서 dict를 HTML 테이블로 렌더링한다."""
        fw_name   = html.escape(str(report["framework"]))
        gen_at    = html.escape(str(report["generated_at"]))
        score_pct = round(report["coverage_score"] * 100, 1)

        coverage_rows = ""
        for ctrl_id, info in report["coverage"].items():
            status_class = {
                "covered": "status-covered",
                "partial": "status-partial",
                "gap":     "status-gap",
            }.get(info["status"], "")

            engines_str = ", ".join(info["matched_engines"]) or "-"
            coverage_rows += (
                f"<tr>"
                f"<td>{html.escape(ctrl_id)}</td>"
                f"<td>{html.escape(info['name'])}</td>"
                f"<td class='{status_class}'>{info['status'].upper()}</td>"
                f"<td>{html.escape(engines_str)}</td>"
                f"</tr>\n"
            )

        kpis = report.get("kpis", {})
        mttd = kpis.get("mttd_seconds")
        mttd_str = f"{mttd:.0f}s" if mttd is not None else "N/A"

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>Compliance Report - {fw_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; color: #1a1a1a; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
h2 {{ margin-top: 2rem; color: #333; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #f5f5f5; font-weight: 600; }}
.status-covered {{ color: #16a34a; font-weight: 600; }}
.status-partial {{ color: #d97706; font-weight: 600; }}
.status-gap {{ color: #dc2626; font-weight: 600; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.summary-card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; }}
.summary-card .label {{ font-size: 0.85rem; color: #6b7280; }}
.summary-card .value {{ font-size: 1.5rem; font-weight: 700; margin-top: 0.25rem; }}
</style>
</head>
<body>
<h1>Compliance Report: {fw_name}</h1>
<p>Generated: {gen_at}</p>

<div class="summary-grid">
<div class="summary-card"><div class="label">Coverage Score</div><div class="value">{score_pct}%</div></div>
<div class="summary-card"><div class="label">Total Controls</div><div class="value">{report['total_controls']}</div></div>
<div class="summary-card"><div class="label">Covered</div><div class="value status-covered">{report['covered_count']}</div></div>
<div class="summary-card"><div class="label">Partial</div><div class="value status-partial">{report['partial_count']}</div></div>
<div class="summary-card"><div class="label">Gaps</div><div class="value status-gap">{report['gap_count']}</div></div>
</div>

<h2>Detection KPIs ({kpis.get('period_days', 30)}-day)</h2>
<div class="summary-grid">
<div class="summary-card"><div class="label">Alert Volume</div><div class="value">{kpis.get('alert_volume', 0)}</div></div>
<div class="summary-card"><div class="label">Alerts/Day</div><div class="value">{kpis.get('alerts_per_day', 0)}</div></div>
<div class="summary-card"><div class="label">MTTD</div><div class="value">{mttd_str}</div></div>
</div>

<h2>Control Coverage</h2>
<table>
<thead><tr><th>Control ID</th><th>Name</th><th>Status</th><th>Matched Engines</th></tr></thead>
<tbody>
{coverage_rows}
</tbody>
</table>

<h2>Active Engines ({len(report['active_engines'])})</h2>
<p>{html.escape(', '.join(report['active_engines']))}</p>
</body>
</html>"""
