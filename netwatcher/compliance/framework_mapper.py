"""컴플라이언스 프레임워크와 탐지 엔진 간 매핑.

YAML 기반 프레임워크 정의를 로드하고, 활성 엔진 대비 커버리지를 분석한다.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("netwatcher.compliance.framework_mapper")


class FrameworkMapper:
    """탐지 엔진을 컴플라이언스 프레임워크 컨트롤에 매핑한다."""

    def __init__(self, mappings_dir: str = "config/compliance") -> None:
        self._mappings_dir = Path(mappings_dir)
        self._cache: dict[str, dict] = {}

    def list_frameworks(self) -> list[str]:
        """사용 가능한 프레임워크 이름 목록을 반환한다."""
        if not self._mappings_dir.exists():
            return []
        return sorted(
            p.stem for p in self._mappings_dir.glob("*.yaml")
        )

    def load_framework(self, name: str) -> dict:
        """프레임워크 YAML 파일을 로드한다.

        캐시된 결과가 있으면 재사용한다. 파일이 없으면 빈 dict를 반환한다.

        Args:
            name: 프레임워크 파일명(확장자 제외).

        Returns:
            파싱된 YAML dict.
        """
        if name in self._cache:
            return self._cache[name]

        path = self._mappings_dir / f"{name}.yaml"
        if not path.exists():
            logger.warning("Framework file not found: %s", path)
            return {}

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self._cache[name] = data
        return data

    def get_coverage(
        self, framework: str, active_engines: list[str],
    ) -> dict[str, dict[str, Any]]:
        """프레임워크 컨트롤별 커버리지 상태를 반환한다.

        Args:
            framework: 프레임워크 이름.
            active_engines: 현재 활성화된 엔진 이름 목록.

        Returns:
            {control_id: {name, description, status, engines, matched_engines}} 형태의 dict.
            status는 'covered', 'partial', 'gap' 중 하나.
        """
        data           = self.load_framework(framework)
        controls       = data.get("controls", [])
        active_set     = set(active_engines)
        result: dict[str, dict[str, Any]] = {}

        for ctrl in controls:
            ctrl_id     = ctrl.get("id", "")
            ctrl_name   = ctrl.get("name", "")
            description = ctrl.get("description", "")
            engines     = ctrl.get("engines", [])

            # "*"는 모든 엔진이 기여한다는 의미
            if engines == ["*"]:
                matched = list(active_set)
                status  = "covered" if active_set else "gap"
            else:
                matched = [e for e in engines if e in active_set]
                if not matched:
                    status = "gap"
                elif len(matched) >= len(engines):
                    status = "covered"
                else:
                    status = "partial"

            result[ctrl_id] = {
                "name":            ctrl_name,
                "description":     description,
                "status":          status,
                "required_engines": engines,
                "matched_engines":  matched,
            }

        return result

    def get_gaps(
        self, framework: str, active_engines: list[str],
    ) -> list[dict[str, Any]]:
        """커버리지가 없는(gap) 컨트롤 목록을 반환한다.

        Args:
            framework: 프레임워크 이름.
            active_engines: 활성 엔진 목록.

        Returns:
            gap 상태인 컨트롤의 리스트.
        """
        coverage = self.get_coverage(framework, active_engines)
        gaps: list[dict[str, Any]] = []
        for ctrl_id, info in coverage.items():
            if info["status"] == "gap":
                gaps.append({"id": ctrl_id, **info})
        return gaps

    def get_coverage_score(
        self, framework: str, active_engines: list[str],
    ) -> float:
        """프레임워크 전체 커버리지 점수를 0.0-1.0 범위로 반환한다.

        covered=1.0, partial=0.5, gap=0.0 가중치를 적용한다.
        """
        coverage = self.get_coverage(framework, active_engines)
        if not coverage:
            return 0.0

        weights = {"covered": 1.0, "partial": 0.5, "gap": 0.0}
        total   = sum(weights.get(v["status"], 0.0) for v in coverage.values())
        return round(total / len(coverage), 4)
