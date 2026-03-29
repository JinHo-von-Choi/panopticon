"""FrameworkMapper 단위 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from netwatcher.compliance.framework_mapper import FrameworkMapper


@pytest.fixture
def compliance_dir(tmp_path: Path) -> Path:
    """테스트용 프레임워크 YAML을 포함한 임시 디렉토리."""
    d = tmp_path / "compliance"
    d.mkdir()

    pci = {
        "framework": "PCI-DSS v4.0",
        "controls": [
            {
                "id": "1.3.1",
                "name": "Network traffic restrictions",
                "description": "Restrict inbound and outbound traffic",
                "engines": ["port_scan", "segment_violation", "lateral_movement"],
            },
            {
                "id": "5.2",
                "name": "Malware detection",
                "description": "Malicious software is prevented or detected",
                "engines": ["signature", "threat_intel"],
            },
            {
                "id": "10.6.1",
                "name": "Log review",
                "description": "Security events are reviewed",
                "engines": ["*"],
            },
        ],
    }
    (d / "pci_dss.yaml").write_text(yaml.dump(pci))
    return d


@pytest.fixture
def mapper(compliance_dir: Path) -> FrameworkMapper:
    return FrameworkMapper(mappings_dir=str(compliance_dir))


class TestListFrameworks:
    def test_returns_available_frameworks(self, mapper: FrameworkMapper):
        frameworks = mapper.list_frameworks()
        assert "pci_dss" in frameworks

    def test_empty_dir(self, tmp_path: Path):
        m = FrameworkMapper(mappings_dir=str(tmp_path / "nonexistent"))
        assert m.list_frameworks() == []


class TestLoadFramework:
    def test_loads_framework_data(self, mapper: FrameworkMapper):
        data = mapper.load_framework("pci_dss")
        assert data["framework"] == "PCI-DSS v4.0"
        assert len(data["controls"]) == 3

    def test_caches_result(self, mapper: FrameworkMapper):
        d1 = mapper.load_framework("pci_dss")
        d2 = mapper.load_framework("pci_dss")
        assert d1 is d2

    def test_missing_framework_returns_empty(self, mapper: FrameworkMapper):
        assert mapper.load_framework("nonexistent") == {}


class TestGetCoverage:
    def test_all_engines_active_full_coverage(self, mapper: FrameworkMapper):
        active = ["port_scan", "segment_violation", "lateral_movement",
                  "signature", "threat_intel"]
        coverage = mapper.get_coverage("pci_dss", active)

        assert coverage["1.3.1"]["status"] == "covered"
        assert coverage["5.2"]["status"] == "covered"
        assert coverage["10.6.1"]["status"] == "covered"

    def test_partial_coverage(self, mapper: FrameworkMapper):
        active = ["port_scan", "signature"]
        coverage = mapper.get_coverage("pci_dss", active)

        assert coverage["1.3.1"]["status"] == "partial"
        assert coverage["1.3.1"]["matched_engines"] == ["port_scan"]

    def test_gap_detection(self, mapper: FrameworkMapper):
        active = ["dns_anomaly"]  # 어떤 컨트롤도 매치하지 않음
        coverage = mapper.get_coverage("pci_dss", active)

        assert coverage["1.3.1"]["status"] == "gap"
        assert coverage["5.2"]["status"] == "gap"

    def test_wildcard_covered_with_any_engine(self, mapper: FrameworkMapper):
        active = ["any_engine"]
        coverage = mapper.get_coverage("pci_dss", active)
        assert coverage["10.6.1"]["status"] == "covered"

    def test_wildcard_gap_with_no_engines(self, mapper: FrameworkMapper):
        coverage = mapper.get_coverage("pci_dss", [])
        assert coverage["10.6.1"]["status"] == "gap"

    def test_missing_framework_returns_empty(self, mapper: FrameworkMapper):
        assert mapper.get_coverage("missing", ["x"]) == {}


class TestGetGaps:
    def test_returns_only_gaps(self, mapper: FrameworkMapper):
        active = ["port_scan", "segment_violation", "lateral_movement"]
        gaps = mapper.get_gaps("pci_dss", active)

        gap_ids = {g["id"] for g in gaps}
        assert "5.2" in gap_ids
        assert "1.3.1" not in gap_ids

    def test_no_gaps_when_fully_covered(self, mapper: FrameworkMapper):
        active = ["port_scan", "segment_violation", "lateral_movement",
                  "signature", "threat_intel"]
        gaps = mapper.get_gaps("pci_dss", active)
        assert len(gaps) == 0


class TestGetCoverageScore:
    def test_full_coverage_score(self, mapper: FrameworkMapper):
        active = ["port_scan", "segment_violation", "lateral_movement",
                  "signature", "threat_intel"]
        score = mapper.get_coverage_score("pci_dss", active)
        assert score == 1.0

    def test_zero_coverage_score(self, mapper: FrameworkMapper):
        score = mapper.get_coverage_score("pci_dss", [])
        assert score == 0.0

    def test_partial_score(self, mapper: FrameworkMapper):
        # port_scan: 1.3.1 partial, 5.2 gap, 10.6.1 covered
        active = ["port_scan"]
        score = mapper.get_coverage_score("pci_dss", active)
        # (0.5 + 0.0 + 1.0) / 3 = 0.5
        assert score == 0.5

    def test_missing_framework_zero(self, mapper: FrameworkMapper):
        assert mapper.get_coverage_score("missing", ["x"]) == 0.0
