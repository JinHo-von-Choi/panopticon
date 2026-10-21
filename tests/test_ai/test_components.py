"""프롬프트 컴포넌트 단위 테스트.

컴포넌트는 파일 단위 계약이다 — 유효성·차이·다양성·누출·위생·절단 가드를
각각 검증한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netwatcher.ai.components import (
    COMPONENT_ORDER,
    LEAK_MARKERS,
    PromptComponent,
    PromptLeakError,
    PromptTree,
    assert_no_leak,
    default_surface,
    describe_coverage,
    diff_summary,
    diversity,
    filter_leaks,
    parse_component,
    validate,
)


def _write(directory: Path, name: str, body: str, *, version: int = 1,
           editable: bool = True) -> Path:
    path = directory / f"{name}.md"
    path.write_text(
        f"---\ncomponent: {name}\nversion: {version}\neditable: "
        f"{'true' if editable else 'false'}\n---\n{body}\n",
        encoding="utf-8",
    )
    return path


def _tree(directory: Path) -> PromptTree:
    components = {}
    for name in COMPONENT_ORDER:
        path = directory / f"{name}.md"
        components[name] = parse_component(path)
    return PromptTree(components=components)


class TestShippedComponents:
    """함께 배포하는 컴포넌트는 계약을 지켜야 한다."""

    def test_shipped_components_are_valid(self):
        tree = PromptTree.load()
        assert validate(tree) == []

    def test_shipped_components_keep_output_contract(self):
        tree = PromptTree.load()
        body = tree.components["format"].body
        for token in ("VERDICT:", "ENGINE:", "ADJUST:"):
            assert token in body

    def test_every_component_file_exists(self):
        surface = default_surface()
        for name in COMPONENT_ORDER:
            assert surface.path_of(name).exists()
            assert surface.allows(name)


class TestValidate:
    """유효성 검사."""

    def test_missing_component_is_reported(self, tmp_path):
        tree = PromptTree.load()
        tree.components.pop("analysis")
        problems = validate(tree)
        assert any("analysis" in problem for problem in problems)

    def test_forbidden_measurement_term_is_reported(self, tmp_path):
        _write(tmp_path, "system", "Use the rubric to answer.")
        _write(tmp_path, "format", "VERDICT: x\nENGINE: y\nADJUST: a=1")
        _write(tmp_path, "context", "context")
        _write(tmp_path, "analysis", "analysis")
        problems = validate(_tree(tmp_path))
        assert any("rubric" in problem for problem in problems)

    def test_missing_output_token_is_reported(self, tmp_path):
        _write(tmp_path, "system", "system")
        _write(tmp_path, "format", "VERDICT: x")
        _write(tmp_path, "context", "context")
        _write(tmp_path, "analysis", "analysis")
        problems = validate(_tree(tmp_path))
        assert any("ADJUST:" in problem for problem in problems)

    def test_unknown_placeholder_is_reported(self, tmp_path):
        _write(tmp_path, "system", "look at {unknown_value}")
        _write(tmp_path, "format", "VERDICT: x\nENGINE: y\nADJUST: a=1")
        _write(tmp_path, "context", "context")
        _write(tmp_path, "analysis", "analysis")
        problems = validate(_tree(tmp_path))
        assert any("unknown_value" in problem for problem in problems)


class TestDiff:
    """두 트리의 차이."""

    def test_changed_component_is_counted(self, tmp_path):
        base = PromptTree.load()
        candidate = PromptTree.load()
        candidate.components["analysis"] = PromptComponent(
            name="analysis",
            version=2,
            editable=True,
            body=candidate.components["analysis"].body + "\nOne more line.\n",
        )
        summary = diff_summary(base, candidate)
        assert summary["analysis"]["modified"] is True
        assert summary["analysis"]["added"] == 1
        assert summary["analysis"]["version_after"] == 2
        assert summary["always_on_chars_delta"] > 0

    def test_unchanged_tree_has_no_difference(self):
        tree = PromptTree.load()
        summary = diff_summary(tree, PromptTree.load())
        assert summary["always_on_chars_delta"] == 0
        assert all(not summary[name]["modified"] for name in COMPONENT_ORDER)


class TestDiversity:
    """후보 프롬프트 트리 간 다양성."""

    def test_identical_trees_are_not_diverse(self):
        scores = diversity([PromptTree.load(), PromptTree.load()])
        assert scores == [1.0]

    def test_different_trees_are_diverse(self, tmp_path):
        base = PromptTree.load()
        candidate = PromptTree.load()
        candidate.components["analysis"] = PromptComponent(
            name="analysis", version=2, editable=True,
            body="Judge only the severity of the alert.\n",
        )
        scores = diversity([base, candidate])
        assert 0.0 < scores[0] < 1.0


class TestLeakGuard:
    """판정 표식이 데이터 영역에 들어가지 않게 한다."""

    def test_events_with_verdict_are_dropped(self):
        events = [
            {"id": 1, "title": "port scan"},
            {"id": 2, "title": "VERDICT: FALSE_POSITIVE already decided"},
        ]
        kept, dropped = filter_leaks(events, LEAK_MARKERS)
        assert [event["id"] for event in kept] == [1]
        assert dropped == ["FALSE_POSITIVE"]

    def test_leftover_marker_raises(self):
        with pytest.raises(PromptLeakError):
            assert_no_leak("title: MISSED_THREAT", LEAK_MARKERS)


class TestCoverageGuard:
    """잘라 낸 내용을 프롬프트가 밝힌다."""

    def test_coverage_states_shown_and_total(self):
        text = describe_coverage(
            total=312, shown=50,
            dropped_fields=("description", "metadata"), masked=12,
        )
        assert "50 of 312" in text
        assert "description, metadata" in text
        assert "12 of 50" in text

    def test_coverage_states_when_nothing_is_masked(self):
        text = describe_coverage(total=3, shown=3, dropped_fields=(), masked=0)
        assert "shown as recorded" in text
