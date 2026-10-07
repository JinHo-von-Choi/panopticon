/**
 * NetWatcher Governance Module (PR 11)
 *
 * 계획서의 관측 범위(observation scope) 전제를 화면으로 옮긴 곳이다.
 * 여기서 두 가지를 한눈에 확인한다.
 *
 * 1. **무엇을 하는 도구인가** — 지원 프로필, 검증된 enforcement 백엔드,
 *    위반 목록, 위협 피드 신선도. "차단이 실제로 적용된다" 는 잘못된 믿음을
 *    이 화면이 바로잡는다.
 * 2. **무엇을 바꿀 수 있는가** — 대기 중인 설정 제안과 승인/거절.
 *    승인은 곧 설정 쓰기이므로 실패·사유를 있는 그대로 보여준다.
 *
 * 판단을 숨기는 화면은 장식이다. 위반이 있으면 눈에 띄게 드러낸다.
 */

import { authFetch, canAnalyze, canConfigure } from '../core/api.js';
import { esc, escAttr, formatTime, showToast } from '../core/utils.js';

function containTables(box) {
    box.querySelectorAll('.scope-table').forEach(table => {
        if (table.parentElement.classList.contains('scope-table-scroll')) return;
        const wrapper = document.createElement('div');
        wrapper.className = 'scope-table-scroll';
        wrapper.tabIndex = 0;
        table.before(wrapper);
        wrapper.appendChild(table);
    });
}

/* ── 지원 프로필 ──────────────────────────────────────────────── */

export async function loadSupportProfile() {
    const box = document.getElementById("support-profile-box");
    if (!box) return;
    box.innerHTML = '<div class="empty-state">Loading support profile…</div>';

    try {
        const resp = await authFetch("/api/support-profile");
        if (!resp || !resp.ok) throw new Error("HTTP " + (resp ? resp.status : "?"));
        renderSupportProfile(await resp.json(), box);
        containTables(box);
    } catch (e) {
        box.textContent = "";
        const div = document.createElement("div");
        div.className = "empty-state";
        div.textContent = "지원 프로필을 불러오지 못했습니다: " + (e.message || e);
        box.appendChild(div);
    }
}

function renderSupportProfile(data, box) {
    const violations = data.violations || [];
    const feeds = data.feeds || null;

    box.innerHTML = `
        <div class="scope-summary" data-status="${violations.length ? "warn" : "ok"}">
            <div class="scope-summary-row">
                <span class="scope-label">지원 프로필</span>
                <span class="scope-value" data-value="profile">${esc(data.profile || "-")}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">enforcement 백엔드</span>
                <span class="scope-value" data-value="enforcement">${esc((data.enforcement_backends || []).join(", ") || "없음")}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">위반</span>
                <span class="scope-value" data-value="violations">${violations.length}건</span>
            </div>
            ${feeds ? `
            <div class="scope-summary-row">
                <span class="scope-label">위협 피드</span>
                <span class="scope-value" data-value="feeds"
                      data-feed-status="${esc(feeds.status || "unknown")}">
                    ${esc(feeds.status || "unknown")}
                    ${feeds.age_hours !== null && feeds.age_hours !== undefined
                        ? ` (${esc(String(feeds.age_hours))}시간 전)`
                        : " (한 번도 갱신 안 됨)"}
                </span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">지표</span>
                <span class="scope-value">${esc(String(feeds.blocked_ips || 0))} IP /
                    ${esc(String(feeds.blocked_domains || 0))} 도메인</span>
            </div>` : ""}
        </div>
        ${violations.length ? renderViolations(violations) : renderCleanNotice()}
        ${data.profile_note ? `<div class="scope-note">${esc(data.profile_note)}</div>` : ""}
    `;
}

function renderViolations(violations) {
    // 위반은 숨기지 않는다 — 무엇이 지원 범위 밖인지 알아야 배포 여부를 정할 수 있다
    const rows = violations.map(v => `
        <tr>
            <td><code>${esc(v.code || "-")}</code></td>
            <td><code>${esc(v.path || "-")}</code></td>
            <td>${esc(v.message || "-")}</td>
            <td>${esc(v.remediation || "-")}</td>
        </tr>
    `).join("");

    return `
        <div class="scope-violations">
            <h4>지원 계약 위반 — 이 상태로는 배포하지 마세요</h4>
            <table class="scope-table">
                <thead><tr><th>코드</th><th>경로</th><th>내용</th><th>조치</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function renderCleanNotice() {
    // 통과를 enforcement 통과로 오인하지 않도록 문구를 구분한다
    return `
        <div class="scope-clean">
            지원 계약 위반 없음.
            <strong>이는 차단·승인 기능이 운영 검증을 통과했다는 뜻이 아니다.</strong>
            게이트 결과는 별도로 확인해야 한다.
        </div>
    `;
}

/* ── 제안 승인 큐 ────────────────────────────────────────────── */

const tp = (key, options = {}) => window.i18next.t('console.proposals.' + key, options);
let proposals = [];
let validationRequired = false;
window.addEventListener("proposal-validation-attached", loadProposals);

export async function loadProposals() {
    const body = document.getElementById("proposals-body");
    const count = document.getElementById("proposals-count");
    if (!body) return;

    try {
        const resp = await authFetch("/api/proposals");
        if (!resp || !resp.ok) throw new Error("HTTP " + (resp ? resp.status : "?"));
        const data = await resp.json();
        proposals = data.proposals || [];
        validationRequired = data.validation_required === true;
        if (count) count.textContent = tp('pending_count', {count: data.pending ?? 0});

        if (!proposals.length) {
            body.innerHTML = `<tr><td colspan="7" class="empty-state">${esc(tp('empty'))}</td></tr>`;
            return;
        }

        body.innerHTML = proposals.map(renderProposalRow).join("");

        body.querySelectorAll("[data-approve]").forEach(btn => {
            btn.addEventListener("click", () => decide(btn.dataset.approve, "approve"));
        });
        body.querySelectorAll("[data-validate]").forEach(btn => {
            btn.addEventListener("click", () => window.dispatchEvent(new CustomEvent("proposal-validation", {
                detail: proposals.find(p => String(p.id) === btn.dataset.validate),
            })));
        });
        body.querySelectorAll("[data-reject]").forEach(btn => {
            btn.addEventListener("click", () => decide(btn.dataset.reject, "reject"));
        });
    } catch (e) {
        body.textContent = "";
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 7;
        td.className = "empty-state";
        td.textContent = tp('load_failed') + ': ' + (e.message || e);
        tr.appendChild(td);
        body.appendChild(tr);
    }
}

function renderProposalRow(p) {
    const pending = p.status === "pending";
    const params = Object.entries(p.params || {})
        .map(([k, v]) => `${k}=${v}`)
        .join(", ");

    // 적용 실패를 성공으로 보여주지 않는다
    let statusCell = esc(tp('status.' + p.status));
    if (p.status === "failed" || p.applied === false) {
        statusCell = `<span class="proposal-failed">${esc(tp('apply_failed'))}</span>`;
    } else if (p.applied === true) {
        statusCell = `<span class="proposal-applied">${esc(tp('applied'))}</span>`;
    }

    const evidence = p.validation_runs || {};
    const validated = Boolean(evidence.normal_run_id && evidence.attack_run_id);
    const actions = pending
        ? `${canAnalyze() ? `<button class="btn-detail" data-validate="${escAttr(p.id)}">${esc(tp('validate'))}</button>` : ''}
           ${canConfigure() ? `<button class="btn-detail" data-approve="${escAttr(p.id)}" ${validationRequired && !validated ? `disabled title="${escAttr(tp('validation_required'))}"` : ''}>${esc(tp('approve'))}</button>
           <button class="btn-detail" data-reject="${escAttr(p.id)}">${esc(tp('reject'))}</button>` : ''}
           ${validated ? `<span>${esc(tp('feature_comparison'))} #${esc(evidence.normal_run_id)} / #${esc(evidence.attack_run_id)}</span>` : ''}`
        : `<span class="proposal-decided-by">${esc(p.decided_by || "-")}</span>`;

    const err = p.apply_error
        ? `<div class="proposal-error">${esc(p.apply_error)}</div>`
        : "";

    return `
        <tr>
            <td>${esc(p.id)}</td>
            <td><code>${esc(p.engine)}</code></td>
            <td>${esc(params)}</td>
            <td>${esc(p.source)}</td>
            <td>${statusCell}${err}</td>
            <td>${esc(formatTime(p.created_at))}</td>
            <td>${actions}</td>
        </tr>
    `;
}

async function decide(id, action) {
    if (action === "approve") {
        // 승인은 설정 쓰기다 — 오탐으로 임계값이 무너질 수 있으므로 한 번 더 확인한다
        const ok = window.confirm(
            tp('confirm')
        );
        if (!ok) return;
    }

    try {
        const resp = await authFetch(`/api/proposals/${encodeURIComponent(id)}/${action}`, {
            method: "POST",
            body: JSON.stringify({ note: "" }),
        });
        const data = resp && resp.ok ? await resp.json() : null;

        if (resp && resp.ok && data && data.status === "failed") {
            // 승인됐지만 반영은 실패했다 — 성공으로 알리지 않는다
            showToast(
                tp('apply_failed'),
                (data.error || tp('apply_failed')) + " (id=" + id + ")",
                "warning"
            );
        } else if (resp && resp.ok) {
            showToast(action === 'approve' ? tp('applied') : tp('status.rejected'), `#${id}`, "info");
        } else {
            const detail = resp ? await resp.text() : "";
            showToast(tp('load_failed'), detail || tp('load_failed'), "critical");
        }
    } catch (e) {
        showToast(tp('load_failed'), e.message || String(e), "critical");
    }
    loadProposals();
}

/* ── 관측 범위 (observation scope) ────────────────────────────── */

const OBS_STATE_LABEL = {
    observed: "관측됨",
    partial:  "부분 관측",
    stale:    "관측 신호 없음 (stale)",
    unknown:  "알 수 없음 (unknown)",
};

/**
 * 관측 상태를 불러온다.
 *
 * 이 화면의 존재 이유는 한 문장이다.
 * "경보가 없다" 를 "문제가 없다" 로 읽지 못하게 한다.
 * 그래서 상태값만 크게 보여주고, 판단 근거(reasons)와
 * 측정하지 못한 항목을 같은 화면에 함께 둔다.
 */
export async function loadObservation() {
    const box = document.getElementById("observation-box");
    if (!box) return;
    box.innerHTML = '<div class="empty-state">Loading observation scope…</div>';

    try {
        const resp = await authFetch("/api/observation");
        if (!resp || !resp.ok) throw new Error("HTTP " + (resp ? resp.status : "?"));
        renderObservation(await resp.json(), box);
        containTables(box);
    } catch (e) {
        box.textContent = "";
        const div = document.createElement("div");
        // 조회 실패를 "관측 이상 없음" 으로 보여주면 안 된다
        div.className = "scope-unknown";
        div.textContent = "관측 상태를 알 수 없습니다: " + (e.message || e);
        box.appendChild(div);
    }
}

function renderObservation(data, box) {
    const state = data.state || "unknown";
    const status = state === "observed" ? "ok" : (state === "partial" ? "warn" : "bad");
    const stages = data.stages || {};
    const loss = data.loss || {};
    const perStage = loss.per_stage || {};
    const unsupported = data.unsupported_measurements || [];
    const inter = data.interpretation || {};

    const stageRows = Object.keys(stages).map(name => {
        const c = stages[name] || {};
        const l = perStage[name] || {};
        // 백분율이 없으면 숫자 대신 왜 없는지를 보여준다
        const ratio = l.app_loss_ratio === null || l.app_loss_ratio === undefined
            ? esc(l.unknown_reason || "비교 불가")
            : (l.app_loss_ratio * 100).toFixed(2) + "%";
        const kernel = (c.dropped_kernel || 0) > 0
            ? `${esc(String(c.dropped_kernel))} <span class="scope-nowrap">(앱 손실 아님)</span>`
            : "0";
        return `
            <tr>
                <td><code>${esc(name)}</code></td>
                <td>${esc(String(c.received || 0))}</td>
                <td>${esc(String(c.accepted || 0))}</td>
                <td>${esc(String(c.suppressed || 0))}</td>
                <td>${esc(String(c.dropped_app || 0))}</td>
                <td>${kernel}</td>
                <td>${ratio}</td>
            </tr>`;
    }).join("");

    box.innerHTML = `
        <div class="scope-summary" data-status="${escAttr(status)}">
            <div class="scope-summary-row">
                <span class="scope-label">관측 상태</span>
                <span class="scope-value" data-value="obs-state"
                      data-obs-state="${escAttr(state)}">${esc(OBS_STATE_LABEL[state] || state)}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">센서</span>
                <span class="scope-value">${esc(data.sensor_id || "-")}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">관측 트래픽</span>
                <span class="scope-value">${esc(String(data.observed_traffic || 0))} 패킷</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">heartbeat 누락</span>
                <span class="scope-value">${data.heartbeat_missed_beats === null
                    ? "한 번도 없음"
                    : esc(String(data.heartbeat_missed_beats)) + "회"}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">알림 큐 체류</span>
                <span class="scope-value">${data.queue_age_seconds === null
                    || data.queue_age_seconds === undefined
                    ? "없음"
                    : esc(String(data.queue_age_seconds)) + "초"}</span>
            </div>
        </div>

        <div class="scope-reasons">
            <h4>판정 근거</h4>
            <ul>
                ${(data.reasons || []).map(r => `<li>${esc(r)}</li>`).join("")
                  || "<li>근거 없음</li>"}
            </ul>
        </div>

        ${inter.message ? `<div class="scope-note">${esc(inter.message)}</div>` : ""}

        <div class="scope-loss">
            <h4>단계별 계측</h4>
            <p class="scope-hint">
                커널 drop 과 앱 drop 은 합산하지 않습니다. 분모와 원인이 다릅니다.
                손실률은 같은 단계 · 같은 시간창의 분모가 있을 때만 계산합니다.
            </p>
            <table class="scope-table">
                <thead><tr>
                    <th>단계</th><th>수신</th><th>처리</th><th>억제</th>
                    <th>앱 drop</th><th>커널 drop</th><th>앱 손실률</th>
                </tr></thead>
                <tbody>${stageRows}</tbody>
            </table>
        </div>

        <div class="scope-unmeasured">
            <h4>측정하지 못한 것</h4>
            <ul>
                <li>${esc((loss.link_loss || {}).reason || "링크 손실 측정 불가")}</li>
                ${unsupported.map(u => `<li><code>${esc(u)}</code></li>`).join("")}
            </ul>
            <p class="scope-hint">
                없는 지표를 만들지 않습니다. 이 항목은 <code>unknown</code> 입니다.
            </p>
        </div>

        ${(inter.cautions || []).map(c => `<div class="scope-note">${esc(c)}</div>`).join("")}
        <div class="scope-note">${esc(loss.warning || "")}</div>
    `;
}

window.i18next?.on('languageChanged', () => {
    if (document.getElementById('tab-governance')?.classList.contains('active')) loadProposals();
});
