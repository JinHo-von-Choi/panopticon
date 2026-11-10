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

import { L } from '../core/utils.js';
import { authFetch, canAnalyze, canConfigure, getAuthToken } from '../core/api.js';
import { emptyStateAttrs, esc, escAttr, formatTime, markEmptyState, showToast, formatBytes } from '../core/utils.js';
import {featureEnabled} from '../core/capabilities.js';
import {loadRemoteProposals} from './proposals.js';

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
let supportRequest = 0;
window.addEventListener('nw-session-ended', () => {
    supportRequest++;
    document.getElementById('support-profile-box')?.replaceChildren();
});

export async function loadSupportProfile() {
    const box = document.getElementById("support-profile-box");
    if (!box) return;
    const request = ++supportRequest, token = getAuthToken();
    const current = () => request === supportRequest && token === getAuthToken();
    box.innerHTML = '<div class="empty-state">' + esc(window.i18next.t('console.shell.loading')) + '</div>';

    try {
        const resp = await authFetch("/api/support-profile");
        if (!resp || !resp.ok) throw new Error("HTTP " + (resp ? resp.status : "?"));
        const data = await resp.json();
        if (!current()) return;
        renderSupportProfile(data, box);
        containTables(box);
    } catch (e) {
        if (!current()) return;
        box.textContent = "";
        const div = document.createElement("div");
        div.className = "empty-state";
        markEmptyState(div, 'failed');
        div.textContent = (L('지원 프로필을 불러오지 못했습니다:') + " ") + (e.message || e);
        box.appendChild(div);
    }
}

function renderSupportProfile(data, box) {
    const violations = data.violations || [];
    const feeds = data.feeds || null;

    box.innerHTML = `
        <div class="scope-summary" data-status="${violations.length ? "warn" : "ok"}">
            <div class="scope-summary-row">
                <span class="scope-label">${L('지원 프로필')}</span>
                <span class="scope-value" data-value="profile">${esc(window.i18next.t('console.shell.profile_' + data.profile, {defaultValue: data.profile || "-"}))}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${esc(window.i18next.t('console.shell.enforcement'))}</span>
                <span class="scope-value" data-value="enforcement">${esc((data.enforcement_backends || []).join(", ") || window.i18next.t('console.shell.none'))}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${L('위반')}</span>
                <span class="scope-value" data-value="violations">${violations.length}${L('건')}</span>
            </div>
            ${feeds ? `
            <div class="scope-summary-row">
                <span class="scope-label">${L('위협 피드')}</span>
                <span class="scope-value" data-value="feeds"
                      data-feed-status="${esc(feeds.status || "unknown")}">
                    ${esc(({ok: L('최신'), stale: L('갱신 지연'), degraded: L('일부 피드 확인 필요'), unknown: L('확인 불가'), unconfigured: L('연결 안 됨')})[feeds.status] || L('확인 불가'))}
                    ${feeds.age_hours !== null && feeds.age_hours !== undefined
                        ? ` (${esc(String(feeds.age_hours))}${L('시간 전)')}`
                        : (['ok', 'stale'].includes(feeds.status) ? (" " + L('(성공한 갱신 기록 없음)')) : "")}
                </span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${L('지표')}</span>
                <span class="scope-value">${esc(Number.isSafeInteger(feeds.blocked_ips) ? String(feeds.blocked_ips) : '—')} IP /
                    ${esc(Number.isSafeInteger(feeds.blocked_domains) ? String(feeds.blocked_domains) : '—')} ${L('도메인')}</span>
            </div>` : ""}
        </div>
        ${renderFeedSources(feeds)}
        ${violations.length ? renderViolations(violations) : renderCleanNotice()}
        ${data.profile_note ? `<div class="scope-note">${esc(data.profile_note)}</div>` : ""}
    `;
}

function renderFeedSources(feeds) {
    if (!Array.isArray(feeds?.sources) || !feeds.sources.length) return '';
    const labels = {ok:L('최신'), stale:L('갱신 지연'), unknown:L('성공 시각 확인 불가')};
    const outcomes = {downloaded:L('다운로드'), cached:L('캐시 사용'), failed:L('실패')};
    return `<table class="scope-table" id="feed-source-status"><thead><tr>
        <th>${L('피드')}</th><th>${L('상태')}</th><th>${L('마지막 성공')}</th><th>${L('최근 결과')}</th></tr></thead><tbody>
        ${feeds.sources.map(source => `<tr><td>${esc(source.name)}</td><td>${esc(labels[source.status] || L('확인 불가'))}</td>
        <td>${esc(Number.isFinite(source.last_success_epoch) ? new Date(source.last_success_epoch * 1000).toLocaleString() : '—')}</td>
        <td>${esc(outcomes[source.outcome] || L('시도 기록 없음'))}</td></tr>`).join('')}</tbody></table>`;
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
            <h4>${L('지원 조건을 벗어난 항목이 있습니다. 해결한 뒤 배포하세요.')}</h4>
            <table class="scope-table">
                <thead><tr><th>${L('코드')}</th><th>${L('경로')}</th><th>${L('내용')}</th><th>${L('조치')}</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function renderCleanNotice() {
    // 통과를 enforcement 통과로 오인하지 않도록 문구를 구분한다
    return `
        <div class="scope-clean">
            ${L('지원 조건을 벗어난 항목이 없습니다.')}
            <strong>${L('차단·승인 기능이 운영 검증을 통과했다는 뜻은 아닙니다.')}</strong>
            ${L('게이트 결과는 따로 확인하세요.')}
        </div>
    `;
}

/* ── 제안 승인 큐 ────────────────────────────────────────────── */

const tp = (key, options = {}) => window.i18next.t('console.proposals.' + key, options);
let proposals = [];
let validationRequired = false;
window.addEventListener("proposal-validation-attached", loadProposals);

export async function loadProposals() {
    if (featureEnabled('proposals_control_remote')) return loadRemoteProposals();
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
            body.innerHTML = `<tr><td colspan="7" class="empty-state" ${emptyStateAttrs('empty')}>${esc(tp('empty'))}</td></tr>`;
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
        body.querySelectorAll("[data-experience]").forEach(btn => {
            btn.addEventListener("click", () => adoptExperience(btn.dataset.experience));
        });
    } catch (e) {
        body.textContent = "";
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 7;
        td.className = "empty-state";
        markEmptyState(td, 'failed');
        td.textContent = tp('load_failed') + ': ' + (e.message || e);
        tr.appendChild(td);
        body.appendChild(tr);
    }
}

function probeSummary(p) {
    const probe = p.probe || {};
    const label = probe.candidate_label || "CAND-1";
    const reasons = (probe.reasons || []).map(r => r.code).filter(Boolean);
    if (probe.status !== "compared") {
        const reason = reasons.length ? reasons.join(", ") : "unknown";
        return `<div class="proposal-probe">${esc(tp('probe_label', {label: label}))} · ${esc(tp('probe_skipped'))} — ${esc(reason)}</div>`;
    }
    const counts = probe.counts || {};
    const parts = [tp('probe_counts', {
        added: counts.added || 0, removed: counts.removed || 0, changed: counts.changed || 0,
    })];
    if (counts.removed_unreproducible) {
        parts.push(tp('probe_unreproducible', {count: counts.removed_unreproducible}));
    }
    if (reasons.length) parts.push(tp('probe_reason', {reason: reasons.join(", ")}));
    return `<div class="proposal-probe">${esc(tp('probe_label', {label: label}))} · ${esc(parts.join(" · "))}</div>`;
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
    const comparable = (p.probe || {}).status === "compared";
    const actions = pending
        ? `${canAnalyze() ? `<button class="btn-detail" data-validate="${escAttr(p.id)}">${esc(tp('validate'))}</button>` : ''}
           ${canConfigure() ? `<button class="btn-detail" data-approve="${escAttr(p.id)}" ${validationRequired && !validated ? `disabled title="${escAttr(tp('validation_required'))}"` : ''}>${esc(tp('approve'))}</button>
           <button class="btn-detail" data-reject="${escAttr(p.id)}">${esc(tp('reject'))}</button>` : ''}
           ${validated ? `<span>${esc(tp('feature_comparison'))} #${esc(evidence.normal_run_id)} / #${esc(evidence.attack_run_id)}</span>` : ''}`
        : `<span class="proposal-decided-by">${esc(p.decided_by || "-")}</span>`;
    const adopt = canAnalyze() && comparable
        ? `<button class="btn-detail" data-experience="${escAttr(p.id)}">${esc(tp('experience_adopt'))}</button>`
        : "";

    const err = p.apply_error
        ? `<div class="proposal-error">${esc(p.apply_error)}</div>`
        : "";

    return `
        <tr>
            <td>${esc(p.id)}</td>
            <td><code>${esc(p.engine)}</code></td>
            <td>${esc(params)}${probeSummary(p)}</td>
            <td>${esc(p.source)}</td>
            <td>${statusCell}${err}</td>
            <td>${esc(formatTime(p.created_at))}</td>
            <td>${actions}${adopt}</td>
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

async function adoptExperience(id) {
    if (!canAnalyze()) return;
    try {
        const resp = await authFetch("/api/experiences", {
            method: "POST",
            body: JSON.stringify({proposal_id: Number(id)}),
        });
        if (resp && resp.ok) {
            showToast(tp('experience_adopted'), `#${id}`, "info");
        } else {
            const detail = resp ? await resp.text() : "";
            showToast(tp('experience_refused'), detail || tp('experience_refused'), "warning");
        }
    } catch (e) {
        showToast(tp('experience_refused'), e.message || String(e), "critical");
    }
    loadProposals();
}

/* ── 관측 범위 (observation scope) ────────────────────────────── */

const OBS_STATE_LABEL = {
    observed: L('관측됨'),
    partial:  L('부분 관측'),
    stale:    L('관측 신호 없음'),
    unknown:  L('알 수 없음'),
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
    box.innerHTML = '<div class="empty-state">' + esc(window.i18next.t('console.shell.loading')) + '</div>';

    try {
        const resp = await authFetch("/api/observation");
        if (!resp || !resp.ok) throw new Error("HTTP " + (resp ? resp.status : "?"));
        const data = await resp.json();
        if (data.input_mode === 'eve') {
            const storage = await authFetch('/api/input/status');
            if (storage?.ok) data.storage = (await storage.json()).storage;
        }
        renderObservation(data, box);
        containTables(box);
    } catch (e) {
        box.textContent = "";
        const div = document.createElement("div");
        // 조회 실패를 "관측 이상 없음" 으로 보여주면 안 된다
        div.className = "scope-unknown";
        markEmptyState(div, 'failed');
        div.textContent = (L('관측 상태를 알 수 없습니다:') + " ") + (e.message || e);
        box.appendChild(div);
    }
}

function renderObservation(data, box) {
    if (data.input_mode === 'eve') {
        const labels = {healthy: L('수집 연결됨'), degraded: L('수집 상태 점검 필요'), unhealthy: L('수집 확인 필요')};
        const rows = (data.sources || []).map(source => {
            const usage = (data.storage || []).find(item => item.sensor_id === source.sensor_id && item.source_id === source.source_id);
            return `<tr>
            <td>${esc(source.sensor_id)} / ${esc(source.source_id)}</td>
            <td>${esc(source.error === 'EveCapacityError' ? L('저장 한도 도달: 보존 정책 확인') : source.backlog ? L('수집 대기량 증가') : labels[source.status] || L('확인 불가'))}</td>
            <td>${esc(String(source.committed_offset ?? L('확인 불가')))}</td>
            <td>${Number.isFinite(source.pending_bytes) && source.pending_bytes >= 0 ? esc(formatBytes(source.pending_bytes)) : L('확인 불가')}</td>
            <td>${esc(String(source.gaps ?? L('확인 불가')))}</td>
            <td>${esc(String(source.rejected ?? L('확인 불가')))}</td>
            <td>${usage ? esc(String(usage.records)) + ' / ' + esc(String(usage.max_records)) : L('확인 불가')}</td>
            <td>${usage ? esc(formatBytes(usage.accounted_bytes)) + ' / ' + esc(formatBytes(usage.max_bytes)) : L('확인 불가')}</td></tr>`;
        }).join('');
        box.innerHTML = `<p class="scope-hint">${L('Suricata EVE 파일 수집. 외부 IDS의 패킷 누락과 망 전체 관측 범위는 확인되지 않습니다.')}</p>
            <div class="scope-table-scroll" tabindex="0"><table class="scope-table">
            <thead><tr><th>${L('입력')}</th><th>${L('수집 상태')}</th><th>${L('저장 위치 (바이트)')}</th><th>${L('수집 대기량')}</th><th>${L('누락 가능성 기록')}</th><th>${L('거절된 행')}</th><th>${L('보존 기록')}</th><th>${L('저장 한도')}</th></tr></thead>
            <tbody>${rows}</tbody></table></div><p class="scope-hint">${L('수집 대기량은 현재 읽는 파일에서 아직 저장하지 않은 바이트 수입니다. 다른 파일의 대기량이나 IDS의 패킷 손실은 포함하지 않습니다. 저장 한도는 실제 DB 디스크 사용량과 다릅니다. DB 서버의 디스크 여유도 별도로 확인하세요.')}</p>`;
        return;
    }
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
            ? esc(l.unknown_reason || L('비교 불가'))
            : (l.app_loss_ratio * 100).toFixed(2) + "%";
        const kernel = (c.dropped_kernel || 0) > 0
            ? `${esc(String(c.dropped_kernel))} <span class="scope-nowrap">${L('(앱 손실 아님)')}</span>`
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
                <span class="scope-label">${L('관측 상태')}</span>
                <span class="scope-value" data-value="obs-state"
                      data-obs-state="${escAttr(state)}">${esc(OBS_STATE_LABEL[state] || state)}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${L('센서')}</span>
                <span class="scope-value">${esc(data.sensor_id || "-")}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${L('관측 트래픽')}</span>
                <span class="scope-value">${esc(String(data.observed_traffic || 0))} ${L('패킷')}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${L('상태 신호 누락')}</span>
                <span class="scope-value">${data.heartbeat_missed_beats === null
                    ? L('한 번도 없음')
                    : esc(String(data.heartbeat_missed_beats)) + L('회')}</span>
            </div>
            <div class="scope-summary-row">
                <span class="scope-label">${L('알림 큐 체류')}</span>
                <span class="scope-value">${data.queue_age_seconds === null
                    || data.queue_age_seconds === undefined
                    ? L('없음')
                    : esc(String(data.queue_age_seconds)) + L('초')}</span>
            </div>
        </div>

        <div class="scope-reasons">
            <h4>${L('판정 근거')}</h4>
            <ul>
                ${(data.reasons || []).map(r => `<li>${esc(L(r))}</li>`).join("")
                  || ("<li>" + L('근거 없음') + "</li>")}
            </ul>
        </div>

        ${inter.message ? `<div class="scope-note">${esc(inter.message)}</div>` : ""}

        <div class="scope-loss">
            <h4>${L('단계별 계측')}</h4>
            <p class="scope-hint">
                ${L('커널과 앱에서 버린 수는 원인과 기준이 달라 합산하지 않습니다.')}
                ${L('손실률은 같은 단계 · 같은 시간창의 분모가 있을 때만 계산합니다.')}
            </p>
            <table class="scope-table">
                <thead><tr>
                    <th>${L('단계')}</th><th>${L('수신')}</th><th>${L('처리')}</th><th>${L('억제')}</th>
                    <th>${L('앱에서 버림')}</th><th>${L('커널에서 버림')}</th><th>${L('앱 손실률')}</th>
                </tr></thead>
                <tbody>${stageRows}</tbody>
            </table>
        </div>

        <div class="scope-unmeasured">
            <h4>${L('측정하지 못한 것')}</h4>
            <ul>
                <li>${esc((loss.link_loss || {}).reason || L('링크 손실 측정 불가'))}</li>
                ${unsupported.map(u => `<li><code>${esc(u)}</code></li>`).join("")}
            </ul>
            <p class="scope-hint">
                ${L('없는 지표를 만들지 않습니다. 이 항목은')} <code>unknown</code> ${L('입니다.')}
            </p>
        </div>

        ${(inter.cautions || []).map(c => `<div class="scope-note">${esc(c)}</div>`).join("")}
        <div class="scope-note">${esc(loss.warning || "")}</div>
    `;
}

window.i18next?.on('languageChanged', () => {
    if (document.getElementById('tab-governance')?.classList.contains('active')) loadProposals();
});
