"""관측 범위 / 제안 승인 UI 테스트 (PR 11).

대시보드는 브라우저가 없으면 실행되지 않는다. 그래서 이 테스트는 두 층으로
나눈다.

1. **Node 로 실제 렌더러를 실행한다** — governance.js 의 렌더 경로가
   위반/정체/실패 상태를 있는 그대로 드러내는지 확인한다.
2. **정적 계약 검사** — 탭·라우팅·스타일·i18n 키가 실제로 존재하는지 확인한다.

Node 가 없으면 렌더러 검사는 skip 되며, 정적 검사는 항상 돈다.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "netwatcher" / "web" / "static"
GOV_JS = STATIC / "js" / "modules" / "governance.js"

requires_node = pytest.mark.skipif(
    shutil.which("node") is None, reason="node 없음 — 렌더러 실행 검사 생략"
)


def _extract_render_fn(src: str, name: str) -> str:
    start = src.index(f"function {name}(")
    depth = 0
    i = src.index("{", start)
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
    raise AssertionError(f"{name} 의 끝을 찾지 못했다")


def _run_node(body: str) -> dict:
    """Node 로 JS 를 실행하고 JSON 으로 돌려받는다."""
    script = STATIC / "js" / "core" / "utils.js"
    utils = script.read_text(encoding="utf-8")
    esc_decl = utils[
        utils.index("var HTML_ESCAPES"):utils.index("export function formatTime")
    ].replace("export function esc", "function esc")

    # 실제 렌더러와 피드 상태·위반·안내 하위 렌더러를 함께 실행한다.
    gov = GOV_JS.read_text(encoding="utf-8")
    fn = _extract_render_fn(gov, "renderSupportProfile")
    inner = _extract_render_fn(gov, "renderViolations")
    clean = _extract_render_fn(gov, "renderCleanNotice")
    sources = _extract_render_fn(gov, "renderFeedSources")

    code = esc_decl + "\n" + inner + "\n" + clean + "\n" + sources + "\n" + fn + textwrap.dedent(f"""
        const cases = {body};
        // 실제 렌더러를 통과시킨 결과를 돌려준다
        const rendered = cases.map((c) => {{
            const box = {{ innerHTML: "" }};
            renderSupportProfile(c, box);
            return box.innerHTML;
        }});
        console.log(JSON.stringify(rendered));
    """)
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", code],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------
# 1. 렌더러 실행
# ------------------------------------------------------------------

@requires_node
def test_support_profile_renders_violations_prominently():
    payload = {
        "profile": "limited",
        "enforcement_backends": ["iptables"],
        "violations": [{
            "code": "SUP-002", "path": "response.backend",
            "message": "nftables 미구현", "remediation": "iptables 사용",
        }],
        "feeds": None,
    }
    out = _run_node(f"[{json.dumps(payload)}]")[0]

    assert "SUP-002" in out
    assert "response.backend" in out
    assert "nftables 미구현" in out
    assert "이 상태로는 배포하지 마세요" in out


@requires_node
def test_clean_profile_does_not_claim_enforcement_certification():
    payload = {
        "profile": "limited",
        "enforcement_backends": ["iptables"],
        "violations": [],
        "feeds": None,
    }
    out = _run_node(f"[{json.dumps(payload)}]")[0]

    # 계약 통과를 enforcement 통과로 오인하지 않아야 한다
    assert "운영 검증을 통과했다는 뜻이 아니다" in out
    assert "위반 0건" in out or "0건" in out


@requires_node
def test_stale_feed_is_shown_as_stale():
    payload = {
        "profile": "limited",
        "enforcement_backends": ["iptables"],
        "violations": [],
        "feeds": {
            "status": "stale", "age_hours": 48.5, "blocked_ips": 0,
            "blocked_domains": 0,
        },
    }
    out = _run_node(f"[{json.dumps(payload)}]")[0]

    assert "stale" in out
    assert "48.5" in out
    # 지표 0건이 정체 상태임을 드러내야 한다
    assert "0 IP" in out


@requires_node
def test_never_updated_feed_is_explicit():
    payload = {
        "profile": "limited", "enforcement_backends": ["iptables"],
        "violations": [],
        "feeds": {
            "status": "stale", "age_hours": None, "blocked_ips": 0,
            "blocked_domains": 0,
        },
    }
    out = _run_node(f"[{json.dumps(payload)}]")[0]
    assert "성공한 갱신 기록 없음" in out


@requires_node
def test_unknown_feed_counts_are_not_shown_as_zero():
    payload = {"profile": "limited", "violations": [],
        "feeds": {"status": "unknown", "age_hours": None,
                  "blocked_ips": None, "blocked_domains": None}}
    out = _run_node(f"[{json.dumps(payload)}]")[0]
    assert "확인 불가" in out and "— IP" in out
    assert "0 IP" not in out


@requires_node
def test_feed_counts_are_escaped():
    payload = {
        "profile": "<img src=x onerror=alert(1)>",
        "enforcement_backends": ["iptables"],
        "violations": [],
        "feeds": None,
    }
    out = _run_node(f"[{json.dumps(payload)}]")[0]
    assert "<img" not in out
    assert "&lt;img" in out


def _run_observation_node(body: str) -> list[str]:
    """관측 패널 렌더러를 Node 로 실행한다."""
    script = STATIC / "js" / "core" / "utils.js"
    utils = script.read_text(encoding="utf-8")
    esc_decl = utils[
        utils.index("var HTML_ESCAPES"):utils.index("export function formatTime")
    ].replace("export function esc", "function esc")

    gov = GOV_JS.read_text(encoding="utf-8")
    fn = _extract_render_fn(gov, "renderObservation")
    # 모듈 레벨 상수도 렌더 경로의 입력이다
    labels = gov[gov.index("const OBS_STATE_LABEL"):gov.index("};", gov.index("const OBS_STATE_LABEL")) + 2]

    code = esc_decl + "\n" + labels + "\n" + fn + textwrap.dedent(f"""
        const cases = {body};
        const rendered = cases.map((c) => {{
            const box = {{ innerHTML: "" }};
            renderObservation(c, box);
            return box.innerHTML;
        }});
        console.log(JSON.stringify(rendered));
    """)
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", code],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


@requires_node
def test_stale_observation_is_shown_as_stale_not_healthy():
    """센서가 죽었는데 '관측됨' 으로 보이면 안 된다."""
    payload = {
        "state": "stale", "sensor_id": "h/lo", "reasons": ["heartbeat 가 5회 연속 누락"],
        "observed_traffic": 0, "heartbeat_missed_beats": 5, "queue_age_seconds": None,
        "stages": {}, "loss": {"per_stage": {}, "link_loss": {"status": "unknown",
                    "reason": "NIC·스위치 손실은 이 센서에서 측정할 수 없다"}},
        "unsupported_measurements": ["nic_drop"],
        "interpretation": {"message": "센서가 살아 있는지 확인되지 않는다.", "cautions": []},
    }
    out = _run_observation_node(f"[{json.dumps(payload)}]")[0]

    assert 'data-obs-state="stale"' in out
    assert "관측 신호 없음" in out
    assert "heartbeat 가 5회 연속 누락" in out


@requires_node
def test_zero_traffic_is_not_rendered_as_healthy():
    obs = {
        "state": "observed", "sensor_id": "h/lo",
        "reasons": ["관측된 트래픽이 0 이다 — 이것만으로는 장애로 판정하지 않는다"],
        "observed_traffic": 0, "heartbeat_missed_beats": 0, "queue_age_seconds": None,
        "stages": {}, "loss": {"per_stage": {}, "link_loss": {"status": "unknown"}},
        "unsupported_measurements": ["nic_drop"],
        "interpretation": {"message": "관측 창이 온전하다.",
            "cautions": ["관측된 트래픽이 0 이다. 이것만으로 장애를 선언하지 않는다."]},
    }
    out = _run_observation_node(f"[{json.dumps(obs)}]")[0]

    # 0 이라도 "문제가 없다" 로 읽히지 않게 근거를 같은 화면에 둔다
    assert "관측된 트래픽이 0 이다" in out
    assert "장애를 선언하지 않는다" in out


@requires_node
def test_kernel_drop_is_not_presented_as_app_loss():
    obs = {
        "state": "partial", "sensor_id": "h/lo", "reasons": ["input_queue 단계에서 25% 가 유실"],
        "observed_traffic": 100, "heartbeat_missed_beats": 0, "queue_age_seconds": 3.1,
        "stages": {"input_queue": {"received": 100, "accepted": 0, "suppressed": 0,
                                   "dropped_app": 25, "dropped_kernel": 400}},
        "loss": {"per_stage": {"input_queue": {
                    "received": 100, "app_dropped": 25, "kernel_dropped": 400,
                    "suppressed": 0, "app_loss_ratio": 0.25, "comparable": True}},
                 "link_loss": {"status": "unknown", "reason": "링크 손실은 측정되지 않는다"},
                 "warning": "전체 손실률로 합산하지 않는다"},
        "unsupported_measurements": ["nic_drop"],
        "interpretation": {"message": "관측 창이 온전하지 않다.", "cautions": []},
    }
    out = _run_observation_node(f"[{json.dumps(obs)}]")[0]

    assert "25.00%" in out
    assert "400" in out
    assert "앱 손실 아님" in out
    assert "전체 손실률로 합산하지 않는다" in out


@requires_node
def test_missing_ratio_shows_reason_not_zero_percent():
    """분모가 없으면 0% 가 아니라 왜 없는지를 보여준다."""
    obs = {
        "state": "observed", "sensor_id": "h/lo", "reasons": ["관측 창에 이상이 없다"],
        "observed_traffic": 10, "heartbeat_missed_beats": 0, "queue_age_seconds": None,
        "stages": {"db": {"received": 0, "accepted": 0, "suppressed": 0,
                          "dropped_app": 0, "dropped_kernel": 0}},
        "loss": {"per_stage": {"db": {
                    "received": 0, "app_dropped": 0, "kernel_dropped": 0, "suppressed": 0,
                    "app_loss_ratio": None, "comparable": False,
                    "unknown_reason": "분모(수신)가 없어 백분율을 계산할 수 없다"}},
                 "link_loss": {"status": "unknown", "reason": "링크 손실은 측정되지 않는다"},
                 "warning": "전체 손실률로 합산하지 않는다"},
        "unsupported_measurements": ["nic_drop"],
        "interpretation": {"message": "관측 창이 온전하다.", "cautions": []},
    }
    out = _run_observation_node(f"[{json.dumps(obs)}]")[0]

    assert "분모(수신)가 없어" in out
    assert "0.00%" not in out


@requires_node
def test_observation_fields_are_escaped():
    obs = {
        "state": "<img src=x onerror=alert(1)>", "sensor_id": "<b>s</b>",
        "reasons": ["<script>bad()</script>"], "observed_traffic": 1,
        "heartbeat_missed_beats": 0, "queue_age_seconds": None,
        "stages": {}, "loss": {"per_stage": {}, "link_loss": {"status": "unknown"}},
        "unsupported_measurements": [], "interpretation": {"message": "m", "cautions": []},
    }
    out = _run_observation_node(f"[{json.dumps(obs)}]")[0]

    assert "<img" not in out
    assert "<script>" not in out
    assert "&lt;img" in out


# ------------------------------------------------------------------
# 2. 정적 계약
# ------------------------------------------------------------------

def test_governance_module_exists():
    assert GOV_JS.exists()


def test_tab_is_registered():
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="governance"' in index
    assert 'id="tab-governance"' in index


def test_module_is_wired_into_app():
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    assert "from './modules/governance.js'" in app
    assert 'target === "governance"' in app


def test_module_uses_safe_output_helpers():
    src = GOV_JS.read_text(encoding="utf-8")
    assert "esc(" in src
    # 인라인 핸들러에 템플릿 인터폴레이션을 넣지 않는다 (G0-3)
    assert not re.search(r"""onclick\s*=\s*["'][^"']*\$\{""", src, re.IGNORECASE)


def test_proposal_actions_do_not_inline_handlers():
    """승인/거절은 data 속성 + 리스너로 처리한다."""
    src = GOV_JS.read_text(encoding="utf-8")
    assert "data-approve=" in src
    assert "data-reject=" in src
    assert "onclick" not in src


def test_failed_apply_is_shown_not_hidden():
    """승인됐지만 반영 실패인 경우를 성공으로 표시하지 않는다."""
    src = GOV_JS.read_text(encoding="utf-8")
    assert "tp('apply_failed')" in src
    import json
    for language in ('ko', 'en'):
        messages = json.loads((STATIC / 'locales' / language / 'translation.json').read_text())
        assert messages['console']['proposals']['apply_failed']
    assert "proposal-failed" in src
    assert "tp('applied')" in src


def test_approval_requires_confirmation():
    src = GOV_JS.read_text(encoding="utf-8")
    assert "confirm(" in src


def test_uses_existing_toast_severities():
    """스타일시트에 실제로 정의된 severity 만 쓴다."""
    css = (STATIC / "css" / "style.css").read_text(encoding="utf-8")
    src = GOV_JS.read_text(encoding="utf-8")
    used = set(re.findall(r'showToast\([^;]*?["\'](info|warning|critical|error|success)["\']', src))
    # showToast 호출부에서 마지막 인자를 뽑는다
    used |= set(re.findall(r'"(info|warning|critical|error|success)"\s*\)\s*;', src))
    defined = set(re.findall(r"\.toast\.toast-(\w+)", css))
    for severity in used:
        assert severity in defined, (
            f"toast-{severity} 스타일이 없다 (정의됨: {sorted(defined)})"
        )


def test_styles_exist():
    css = (STATIC / "css" / "style.css").read_text(encoding="utf-8")
    for cls in (".scope-summary", ".scope-violations", ".proposal-failed", ".scope-clean"):
        assert cls in css, f"{cls} 스타일이 없다"


def test_i18n_keys_exist():
    for locale in ("ko", "en"):
        path = STATIC / "locales" / locale / "translation.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "governance" in data.get("tabs", {}), f"{locale} 에 tabs.governance 가 없다"


def test_observation_is_wired_to_dashboard():
    """관측 API 가 라우터에 등록되고, 탭이 실제로 로드해야 한다."""
    server = Path(__file__).resolve().parents[2] / "netwatcher" / "web" / "server.py"
    assert "create_observation_router" in server.read_text(encoding="utf-8")

    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'id="observation-box"' in index

    app_js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    assert "loadObservation" in app_js


def test_observation_styles_exist():
    css = (STATIC / "css" / "style.css").read_text(encoding="utf-8")
    for cls in (".scope-reasons", ".scope-loss", ".scope-unmeasured", ".scope-unknown"):
        assert cls in css, f"{cls} 스타일이 없다"


def test_support_profile_endpoint_is_registered():
    server = Path(__file__).resolve().parents[2] / "netwatcher" / "web" / "server.py"
    assert "/api/support-profile" in server.read_text(encoding="utf-8")
