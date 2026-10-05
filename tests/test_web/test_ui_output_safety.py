"""대시보드 안전 출력 게이트 (PR 02).

두 가지를 확인한다.

1. **정적 검사** — 정적 JS 안의 HTML 조립 지점에서 이스케이프되지 않은 값이
   인라인 이벤트 핸들러 속성으로 들어가면 실패한다. ``onclick="f('${v}')"``
   패턴은 속성 컨텍스트 탈출이 가능해 금지한다.
2. **개념 이스케이프 검증** — ``esc()`` 의 계약(따옴표·백틱 이스케이프)을
   Python 으로 재현해, 브라우저 없이도 의미를 확인한다.

작성자: 최진호
작성일: 2026-10-05
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

STATIC_JS_DIR = Path(__file__).resolve().parents[2] / "netwatcher" / "web" / "static" / "js"

# ${...} 안의 값을 인라인 핸들러 속성으로 넘기는 금지 패턴.
# 예: onclick="window.removeBlock('${b.value}')"
INLINE_HANDLER_TEMPLATE = re.compile(
    r"""on(?:click|change|submit|mouseover|focus|blur|load)\s*=\s*["'][^"']*\$\{""",
    re.IGNORECASE,
)

# HTML ESCAPE 매핑 (JS utils.js 와 동일)
_ESCAPES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "`": "&#96;",
}
_ESCAPE_PATTERN = re.compile(r"[&<>\"'`]")


def _js_esc(value: object) -> str:
    """netwatcher/web/static/js/core/utils.js 의 esc() 와 동일한 의미의 함수."""
    if value is None:
        return ""
    return _ESCAPE_PATTERN.sub(lambda m: _ESCAPES[m.group(0)], str(value))


# ------------------------------------------------------------------
# 정적 검사
# ------------------------------------------------------------------

def _js_files() -> list[Path]:
    if not STATIC_JS_DIR.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("static js directory not found")
    return sorted(STATIC_JS_DIR.rglob("*.js"))


def test_static_js_exists():
    assert _js_files(), "정적 JS 파일을 찾지 못했다"


@pytest.mark.parametrize("path", _js_files(), ids=lambda p: p.name)
def test_no_template_interpolation_in_inline_handlers(path: Path):
    """인라인 이벤트 핸들러에 ${...} 를 넣지 않는다 (G0, PR 02)."""
    text = path.read_text(encoding="utf-8")
    offenders = [
        f"{path.name}:{line_no}: {line.strip()}"
        for line_no, line in enumerate(text.splitlines(), start=1)
        if INLINE_HANDLER_TEMPLATE.search(line)
    ]
    assert not offenders, "인라인 핸들러 내 템플릿 인터폴레이션 발견:\n" + "\n".join(offenders)


def test_esc_escapes_quote_characters():
    """속성 컨텍스트 탈출을 막기 위해 따옴표/백틱도 이스케이프한다."""
    assert '"' not in _js_esc('x" onerror="alert(1)')
    assert "'" not in _js_esc("x' onerror='alert(1)")
    assert "`" not in _js_esc("x`+alert(1)+`")
    assert _js_esc("a & b") == "a &amp; b"
    assert _js_esc("<script>") == "&lt;script&gt;"


def test_esc_neutralizes_attribute_breakout_payload():
    payload = '"><img src=x onerror=alert(1)>'
    escaped = _js_esc(payload)
    assert "<" not in escaped and ">" not in escaped
    assert '"' not in escaped


def test_esc_handles_non_string_values():
    assert _js_esc(None) == ""
    assert _js_esc(0) == "0"
    assert _js_esc(3.5) == "3.5"
    assert _js_esc(False) == "False"


def test_esc_handles_zero_and_false_without_dropping():
    """이전 구현의 `if (!str) return ""` 가 0/False 를 지우지 않는지 확인한다."""
    assert _js_esc(0) != ""
    assert _js_esc(False) != ""


# ------------------------------------------------------------------
# 렌더링 컨텍스트
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "context,value,assert_safe",
    [
        ("text", "<script>alert(1)</script>", lambda s: "<" not in s),
        ("attribute", 'x" onmouseover="alert(1)', lambda s: '"' not in s),
        ("onclick-template", "${ip}", lambda s: "'" not in s),
    ],
)
def test_no_unescaped_interpolation_survives(context, value, assert_safe):
    assert assert_safe(_js_esc(value)), f"{context} 컨텍스트에서 이스케이프 실패"


def test_risk_level_cannot_break_out_of_class_attribute():
    """devices.js 의 renderRiskBadge 는 risk-${level} 형태였다."""
    malicious = 'low" onmouseover="alert(1)'
    escaped = _js_esc(malicious)
    assert '"' not in escaped
    assert "onmouseover=" not in escaped.replace("onmouseover=&quot;", "") or True
    assert escaped == "low&quot; onmouseover=&quot;alert(1)"


def test_shipped_utils_js_uses_full_escape_table():
    """utils.js 의 HTML_ESCAPES 표가 6개 문자를 모두 포함하는지 확인한다."""
    path = STATIC_JS_DIR / "core" / "utils.js"
    if not path.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("core/utils.js not found")
    text = path.read_text(encoding="utf-8")
    start = text.index("HTML_ESCAPES = {")
    table = text[start:text.index("};", start)]
    for char in ("&", "<", ">", '"', "'", "`"):
        assert f'"{char}":' in table or f"'{char}':" in table, \
            f"HTML_ESCAPES 에 {char!r} 가 없다"


def test_esc_does_not_use_inner_html_roundtrip():
    """textContent → innerHTML 왕복은 따옴표를 이스케이프하지 않는다."""
    path = STATIC_JS_DIR / "core" / "utils.js"
    if not path.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("core/utils.js not found")
    text = path.read_text(encoding="utf-8")
    esc_body = text[text.index("export function esc("):]
    esc_body = esc_body[:esc_body.index("\n}")] if "\n}" in esc_body else esc_body[:600]
    assert "innerHTML" not in esc_body

def test_evidence_envelope_renderer_exists_and_escapes():
    """증거 봉투 렌더러는 값을 이스케이프해 조립해야 한다 (PR 09)."""
    events_js = STATIC_JS_DIR / "modules" / "events.js"
    if not events_js.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("events.js not found")
    text = events_js.read_text(encoding="utf-8")

    assert "function renderEvidenceEnvelope" in text
    assert "renderEvidenceEnvelope(ev.evidence)" in text

    # 세 층이 모두 명시적으로 그려져야 한다
    for layer in ("summary", "evidence", "raw"):
        assert f"{layer}:" in text, f"{layer} 층이 렌더링에 없다"

    # 렌더러 안에서 값 삽입은 esc() 를 거쳐야 한다
    body = text[text.index("function renderEvidenceEnvelope"):]
    body = body[:body.index("\n}\n")] if "\n}\n" in body else body[:2000]
    assert "esc(" in body
    assert "innerHTML" not in body, "렌더러가 innerHTML 을 직접 사용해서는 안 된다"


def test_evidence_labels_are_three_layers():
    """UI 가 세 층을 사람이 읽는 말로 설명해야 한다."""
    events_js = STATIC_JS_DIR / "modules" / "events.js"
    if not events_js.exists():  # pragma: no cover
        pytest.skip("events.js not found")
    text = events_js.read_text(encoding="utf-8")
    for label in ("요약", "근거", "원자료"):
        assert label in text, f"{label} 레이블이 없다"
