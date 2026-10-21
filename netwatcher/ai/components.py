"""분석 프롬프트 컴포넌트 — 파일 단위로 관리되는 프롬프트 조립 단위.

프롬프트를 한 덩어리 문자열로 두지 않는다. 역할·출력 형식·문맥·판정 기준을
따로 가진 파일로 나누면 무엇이 바뀌었는지 비교할 수 있고, 출력 형식 계약과
금지 어휘를 컴포넌트 단위로 검사할 수 있다.

- ``system.md``   역할과 대상
- ``format.md``   출력 형식 계약
- ``context.md``  환경과 화이트리스트 문맥
- ``analysis.md`` 판정 기준

각 파일은 프론트매터로 ``component``·``version``·``editable`` 을 가진다.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"

# 조립 순서. 앞 컴포넌트가 뒤 컴포넌트의 문맥을 받는다.
COMPONENT_ORDER: tuple[str, ...] = ("system", "format", "context", "analysis")

# 사람이 고칠 수 있는 컴포넌트.
EDITABLE_COMPONENTS = frozenset(COMPONENT_ORDER)

# 예약 이름. 프롬프트는 읽기 전용으로만 쓴다.
RESERVED_COMPONENTS = frozenset({"guard"})

COMPONENT_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

REQUIRED_FRONTMATTER = ("component", "version", "editable")

# 출력 형식 계약. 이 토큰이 사라지면 응답을 파싱할 수 없다.
REQUIRED_OUTPUT_TOKENS = ("VERDICT:", "ENGINE:", "ADJUST:")

# 측정 어휘. 프롬프트에 들어가면 평가 설계가 노출되고 판정 기준으로 쓰인다.
FORBIDDEN_TERMS = ("grader", "rubric", "score", "fpr target")

# 데이터 영역에 남아 있으면 안 되는 표식 — 사람이 이미 내려린 판정.
LEAK_MARKERS = ("CONFIRMED_THREAT", "FALSE_POSITIVE", "MISSED_THREAT", "UNCERTAIN")

ALLOWED_PLACEHOLDERS = frozenset({"lang", "lookback_minutes", "whitelist"})

PLACEHOLDER_PATTERN = re.compile(r"\{([a-z_]+)\}")


class PromptComponentError(RuntimeError):
    """프롬프트 컴포넌트를 조립할 수 없는 상태."""


class PromptLeakError(PromptComponentError):
    """판정 표식이 데이터 영역에 남아 있다."""


@dataclass(frozen=True)
class ComponentSurface:
    """프롬프트 컴포넌트 편집 표면.

    편집 가능한 컴포넌트, 예약된(읽기 전용) 컴포넌트, 각 컴포넌트의 파일
    경로를 한 곳에 모은다. 이름 규칙은 COMPONENT_NAME_PATTERN 이 정한다.
    """

    editable: frozenset[str]
    reserved: frozenset[str]
    paths: Mapping[str, Path]

    def allows(self, name: str) -> bool:
        """사람이 이 컴포넌트를 고칠 수 있는지."""
        return name in self.editable and name not in self.reserved

    def path_of(self, name: str) -> Path:
        """컴포넌트 파일 경로를 돌려준다."""
        try:
            return self.paths[name]
        except KeyError:
            raise PromptComponentError(
                f"알 수 없는 프롬프트 컴포넌트입니다: {name}"
            ) from None


def default_surface(directory: Path | None = None) -> ComponentSurface:
    """기본 편집 표면을 만든다."""
    base = Path(directory) if directory is not None else PROMPT_DIR
    return ComponentSurface(
        editable=frozenset(EDITABLE_COMPONENTS),
        reserved=frozenset(RESERVED_COMPONENTS),
        paths={name: base / f"{name}.md" for name in COMPONENT_ORDER},
    )


@dataclass(frozen=True)
class PromptComponent:
    """프롬프트 컴포넌트 하나."""

    name: str
    version: int
    editable: bool
    body: str
    path: Path | None = None

    def render(self, sections: Mapping[str, str]) -> str:
        """자리 표시자를 채운 본문을 돌려준다."""

        def substitute(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in sections:
                raise PromptComponentError(
                    f"{self.name} 컴포넌트의 {{{key}}} 자리에 값이 없습니다"
                )
            return str(sections[key])

        return PLACEHOLDER_PATTERN.sub(substitute, self.body).strip()


@dataclass
class PromptTree:
    """프롬프트 컴포넌트 집합."""

    components: dict[str, PromptComponent]

    @classmethod
    def load(cls, directory: Path | None = None) -> "PromptTree":
        """컴포넌트 파일을 읽는다. 없는 파일은 조립을 시도하지 않고 알린다."""
        base = Path(directory) if directory is not None else PROMPT_DIR
        components: dict[str, PromptComponent] = {}
        for name in COMPONENT_ORDER:
            path = base / f"{name}.md"
            if not path.exists():
                raise PromptComponentError(f"프롬프트 컴포넌트 {path} 가 없습니다")
            components[name] = parse_component(path)
        return cls(components=components)

    def body(self) -> str:
        """컴포넌트 전체를 이어 붙인 원문."""
        return "\n\n".join(
            self.components[name].body for name in COMPONENT_ORDER if name in self.components
        )

    def render(
        self,
        sections: Mapping[str, str],
        *,
        data: str,
        format_override: str | None = None,
    ) -> str:
        """컴포넌트를 조립한다.

        ``format_override`` 를 주면 format 컴포넌트 자리를 대신한다 — 구조화
        응답을 요구하는 공급자는 JSON 계약을 따로 붙인다.
        """
        parts: list[str] = []
        for name in COMPONENT_ORDER:
            if name == "format" and format_override is not None:
                parts.append(format_override.strip())
                continue
            component = self.components.get(name)
            if component is None:
                raise PromptComponentError(f"{name} 컴포넌트가 없습니다")
            parts.append(component.render(sections))
        parts.append(data.strip())
        return "\n\n".join(parts)


def parse_component(path: Path) -> PromptComponent:
    """컴포넌트 파일을 읽는다. 프론트매터가 없거나 형식이 틀리면 알린다."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise PromptComponentError(f"{path.name} 에 프론트매터가 없습니다")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise PromptComponentError(f"{path.name} 의 프론트매터가 닫히지 않았습니다")
    front, body = parts[1], parts[2]

    meta: dict[str, str] = {}
    for line in front.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            raise PromptComponentError(
                f"{path.name} 프론트매터 줄이 잘못됐습니다: {stripped}"
            )
        key, value = stripped.split(":", 1)
        meta[key.strip()] = value.strip()

    missing = [key for key in REQUIRED_FRONTMATTER if key not in meta]
    if missing:
        raise PromptComponentError(
            f"{path.name} 프론트매터에 {', '.join(missing)} 가 없습니다"
        )
    try:
        version = int(meta["version"])
    except ValueError:
        raise PromptComponentError(
            f"{path.name} 의 version 은 정수여야 합니다"
        ) from None
    editable = meta["editable"].strip().lower() in ("true", "1", "yes")
    return PromptComponent(
        name=meta["component"],
        version=version,
        editable=editable,
        body=body.strip(),
        path=path,
    )


def validate(tree: PromptTree, surface: ComponentSurface | None = None) -> list[str]:
    """컴포넌트 트리의 문제를 목록으로 돌려준다. 문제가 없으면 빈 목록."""
    problems: list[str] = []
    editable = surface.editable if surface is not None else EDITABLE_COMPONENTS
    reserved = surface.reserved if surface is not None else RESERVED_COMPONENTS
    for name in COMPONENT_ORDER:
        component = tree.components.get(name)
        if component is None:
            problems.append(f"{name} 컴포넌트가 없습니다")
            continue
        if not COMPONENT_NAME_PATTERN.match(component.name):
            problems.append(f"{name} 컴포넌트 이름 규칙을 어깁니다: {component.name}")
        if component.name != name:
            problems.append(f"{name} 파일의 component 값이 {component.name} 입니다")
        if component.version < 1:
            problems.append(f"{name} 컴포넌트 version 은 1 이상이어야 합니다")
        if name in editable and not component.editable:
            problems.append(f"{name} 컴포넌트는 수정 가능해야 합니다 (editable: true)")
        if name in reserved and component.editable:
            problems.append(f"{name} 컴포넌트는 수정할 수 없습니다 (editable: false)")
        lowered = component.body.lower()
        for term in FORBIDDEN_TERMS:
            if term in lowered:
                problems.append(f"{name} 컴포넌트에 금지 어휘가 있습니다: {term}")
        for key in PLACEHOLDER_PATTERN.findall(component.body):
            if key not in ALLOWED_PLACEHOLDERS:
                problems.append(f"{name} 컴포넌트에 알 수 없는 자리 표시자가 있습니다: {{{key}}}")

    format_component = tree.components.get("format")
    if format_component is not None:
        for token in REQUIRED_OUTPUT_TOKENS:
            if token not in format_component.body:
                problems.append(f"format 컴포넌트에 출력 계약 토큰이 없습니다: {token}")
    return problems


def diff_summary(base: PromptTree, candidate: PromptTree) -> dict:
    """두 컴포넌트 트리의 차이를 요약한다.

    컴포넌트별 추가·제거 줄 수와, 항상 켜지는 문자 수의 델타를 돌려준다.
    """
    summary: dict[str, object] = {}
    for name in COMPONENT_ORDER:
        base_component = base.components.get(name)
        candidate_component = candidate.components.get(name)
        base_body = base_component.body if base_component else ""
        candidate_body = candidate_component.body if candidate_component else ""
        added = removed = 0
        for line in difflib.unified_diff(
            base_body.splitlines(), candidate_body.splitlines(), lineterm=""
        ):
            if line.startswith("+++") or line.startswith("---"):
                continue
            if line.startswith("+"):
                added += 1
            elif line.startswith("-"):
                removed += 1
        summary[name] = {
            "added": added,
            "removed": removed,
            "modified": base_body != candidate_body,
            "version_before": base_component.version if base_component else 0,
            "version_after": candidate_component.version if candidate_component else 0,
        }
    summary["always_on_chars_delta"] = len(candidate.body()) - len(base.body())
    return summary


def diversity(trees: Sequence[PromptTree]) -> list[float]:
    """트리 쌍의 line-Jaccard 유사도. 1 이면 같은 프롬프트다."""
    scores: list[float] = []
    for index in range(len(trees)):
        for other in range(index + 1, len(trees)):
            scores.append(
                _jaccard(
                    trees[index].body().splitlines(),
                    trees[other].body().splitlines(),
                )
            )
    return scores


def _jaccard(left: Sequence[str], right: Sequence[str]) -> float:
    left_set = {line.strip() for line in left if line.strip()}
    right_set = {line.strip() for line in right if line.strip()}
    union = left_set | right_set
    if not union:
        return 1.0
    return len(left_set & right_set) / len(union)


def filter_leaks(
    events: Sequence[Mapping],
    markers: Iterable[str] = LEAK_MARKERS,
) -> tuple[list[dict], list[str]]:
    """표식이 들어 있는 이벤트를 데이터 영역에서 뺀다.

    판정 표식이 이벤트에 남아 있으면 분석기가 이미 내려진 판정을 보고한다.
    뺀 표식은 함께 돌려준다 — 무엇이 빠졌는지 프롬프트에 적는다.
    """
    active = [marker for marker in markers if marker]
    kept: list[dict] = []
    dropped: list[str] = []
    for event in events:
        text = json.dumps(event, ensure_ascii=False, default=str)
        hit = next((marker for marker in active if marker in text), None)
        if hit is None:
            kept.append(dict(event))
        else:
            dropped.append(hit)
    return kept, dropped


def assert_no_leak(text: str, markers: Iterable[str] = LEAK_MARKERS) -> None:
    """데이터 영역에 판정 표식이 남아 있으면 알린다."""
    for marker in markers:
        if marker and marker in text:
            raise PromptLeakError(f"데이터 영역에 판정 표식이 남았습니다: {marker}")


def describe_coverage(
    *,
    total: int,
    shown: int,
    dropped_fields: Sequence[str],
    masked: int,
) -> str:
    """프롬프트에 무엇이 빠졌는지 명시한다.

    잘라 낸 항목이 무엇인지 말하지 않으면 분석기는 빠진 정보를 놓친 채
    판정한다. 사설 주소 판단에 쓰는 필드가 가려졌다면 그것도 함께 밝힌다.
    """
    lines = ["DATA COVERAGE:"]
    lines.append(f"- Events shown: {shown} of {total} in the lookback window.")
    if dropped_fields:
        lines.append(f"- Fields not included: {', '.join(dropped_fields)}.")
    if masked:
        lines.append(
            f"- {masked} of {shown} source addresses are replaced with host labels. "
            "Internal versus external address judgement is not possible from "
            "these labels."
        )
    else:
        lines.append("- Source addresses are shown as recorded.")
    return "\n".join(lines)
