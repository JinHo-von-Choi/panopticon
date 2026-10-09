/**
 * NetWatcher Incidents Module
 *
 * 상관 분석된 인시던트를 운영 큐로 제시한다. 좌측 목록에서 하나를 고르면
 * 우측에 킬체인 진행, 관련 엔진, 출발지 IP, 조치 버튼이 나타난다.
 */

import { authFetch, canConfigure, getAuthToken } from '../core/api.js';
import { featureEnabled } from '../core/capabilities.js';
import { esc, formatTime, showToast } from '../core/utils.js';

/** 백엔드 attack_mapping.KILL_CHAIN_ORDER와 동일한 순서를 유지한다. */
const KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
];

const STAGE_LABEL = {
    reconnaissance:       "Recon",
    resource_development: "ResDev",
    initial_access:       "Access",
    execution:            "Exec",
    persistence:          "Persist",
    privilege_escalation: "PrivEsc",
    defense_evasion:      "Evasion",
    credential_access:    "CredAcc",
    discovery:            "Discovery",
    lateral_movement:     "Lateral",
    collection:           "Collect",
    command_and_control:  "C2",
    exfiltration:         "Exfil",
    impact:               "Impact",
};

let incidents      = [];
let selectedId     = null;
let includeResolved = false;
let busy = false;
let needsRefresh = false;
let sessionEpoch = 0;
let loadAttempt = 0;
const tr = key => window.i18next.t('incidents.control.' + key);
const label = (key, options) => window.i18next.t('incidents.' + key, options);

function notice(key) {
    const node = document.getElementById('incident-control-status');
    if (node) node.textContent = key ? tr(key) : '';
}

function render() {
    const refresh = document.getElementById('btn-incidents-refresh');
    if (refresh) refresh.disabled = busy;
    const filter = document.getElementById('incidents-show-resolved');
    if (filter) filter.disabled = busy;
    renderList();
    renderDetail();
}

export async function loadIncidents() {
    if (busy) return false;
    const epoch = sessionEpoch;
    const token = getAuthToken();
    const attempt = ++loadAttempt;
    const current = () => epoch === sessionEpoch && token === getAuthToken() && attempt === loadAttempt;
    const params = new URLSearchParams();
    params.set("limit", "100");
    params.set("include_resolved", includeResolved ? "true" : "false");

    try {
        const resp = await authFetch("/api/incidents?" + params.toString());
        if (!current()) return false;
        if (!resp || !resp.ok) throw new Error('Incident list unavailable');
        const data = await resp.json();
        if (!current()) return false;
        if (!Array.isArray(data.incidents) || data.incidents.length > 100) throw new Error('Invalid incident list');
        incidents = data.incidents;
        needsRefresh = false;
        notice(canConfigure() ? '' : 'readonly');

        if (selectedId !== null && !incidents.some(i => i.id === selectedId)) {
            selectedId = null;
        }
        if (selectedId === null && incidents.length) {
            selectedId = incidents[0].id;
        }
        render();
        return true;
    } catch (e) {
        if (!current()) return false;
        incidents = [];
        selectedId = null;
        needsRefresh = true;
        notice('load_failed');
        render();
        return false;
    }
}

function renderList() {
    const list  = document.getElementById("incidents-list");
    const count = document.getElementById("incidents-count");
    if (count) count.textContent = incidents.length;
    if (!list) return;

    if (!incidents.length) {
        if (needsRefresh) {
            list.textContent = tr('load_failed');
            return;
        }
        list.innerHTML = `<div class="empty-state">${esc(label('empty'))}</div>`;
        return;
    }

    list.innerHTML = incidents.map(inc => `
        <button class="incident-item ${inc.id === selectedId ? "selected" : ""} sev-${esc(inc.severity)}"
                data-incident-id="${inc.id}">
            <div class="incident-item-head">
                <span class="severity-badge severity-${esc(inc.severity)}">${esc(inc.severity)}</span>
                ${inc.resolved ? `<span class="incident-resolved-tag">${esc(label('already_resolved'))}</span>` : ""}
            </div>
            <div class="incident-item-title">${esc(inc.title)}</div>
            <div class="incident-item-meta">
                ${esc(label('stage_count', {count:(inc.kill_chain_stages || []).length}))} ·
                ${esc(label('source_count', {count:(inc.source_ips || []).length}))} ·
                ${esc(formatTime(inc.updated_at || inc.created_at))}
            </div>
        </button>
    `).join("");

    list.querySelectorAll("[data-incident-id]").forEach(el => {
        el.addEventListener("click", () => {
            selectedId = parseInt(el.dataset.incidentId, 10);
            renderList();
            renderDetail();
        });
    });
}

function renderKillChain(stages) {
    const reached = new Set(stages || []);
    // 도달한 단계 중 가장 늦은 지점까지만 표시해 빈 단계 나열을 줄인다.
    let lastIndex = -1;
    reached.forEach(s => {
        const idx = KILL_CHAIN_ORDER.indexOf(s);
        if (idx > lastIndex) lastIndex = idx;
    });
    const visible = lastIndex < 0
        ? KILL_CHAIN_ORDER.slice(0, 4)
        : KILL_CHAIN_ORDER.slice(0, Math.min(KILL_CHAIN_ORDER.length, lastIndex + 2));

    return `<div class="killchain">` + visible.map(stage => `
        <div class="killchain-step ${reached.has(stage) ? "reached" : ""}">
            <span class="killchain-dot"></span>
            <span class="killchain-label">${esc(label('stages.' + stage, {defaultValue:STAGE_LABEL[stage] || stage}))}</span>
        </div>
    `).join("") + `</div>`;
}

function renderDetail() {
    const panel = document.getElementById("incident-detail");
    if (!panel) return;

    const inc = incidents.find(i => i.id === selectedId);
    if (!inc) {
        panel.innerHTML = `<div class="empty-state">${esc(label('select'))}</div>`;
        return;
    }

    const ips = (inc.source_ips || []).map(ip => `
        <span class="ip-chip">
            <code class="hunt-link" data-hunt-ip="${esc(ip)}" title="조사">${esc(ip)}</code>
            ${canConfigure() && featureEnabled('direct_blocks') ? `<button class="btn-chip" data-block-ip="${esc(ip)}" data-i18n="incidents.block">차단</button>` : ''}
        </span>
    `).join("") || "<span class='text-dim'>-</span>";

    const engines = (inc.engines || []).map(e => `<span class="type-tag">${esc(e)}</span>`).join(" ")
        || "<span class='text-dim'>-</span>";

    panel.innerHTML = `
        <div class="incident-detail-head">
            <span class="severity-badge severity-${esc(inc.severity)}">${esc(inc.severity)}</span>
            <h3>${esc(inc.title)}</h3>
        </div>
        <div class="incident-detail-times">
            ${esc(formatTime(inc.created_at))} → ${esc(formatTime(inc.updated_at || inc.created_at))}
            ${inc.rule ? ` · rule: <code>${esc(inc.rule)}</code>` : ""}
        </div>

        ${inc.description ? `<p class="incident-desc">${esc(inc.description)}</p>` : ""}

        <h4>${esc(label('kill_chain'))}</h4>
        ${renderKillChain(inc.kill_chain_stages)}

        <h4>${esc(label('source_ips'))}</h4>
        <div class="incident-ips">${ips}</div>

        <h4>${esc(label('engines'))}</h4>
        <div class="incident-engines">${engines}</div>

        <h4>${esc(label('related_alerts'))}</h4>
        <div class="incident-alerts">
            ${esc(label('alert_count', {count:(inc.alert_ids || []).length}))}
            ${(inc.alert_ids || []).length
                ? `<button class="btn-detail" id="incident-view-events">${esc(label('view_events'))}</button>`
                : ""}
        </div>

        <div class="incident-actions">
            ${inc.resolved
                ? `<span class="incident-resolved-tag">${esc(label('already_resolved'))}</span>`
                : `<button class="btn btn-accent" id="incident-resolve" data-i18n="incidents.resolve" ${!canConfigure() || busy || needsRefresh ? 'disabled' : ''}>${esc(window.i18next.t('incidents.resolve'))}</button>`}
        </div>
    `;

    panel.querySelector("#incident-resolve")?.addEventListener("click", () => resolveIncident(inc.id));
    panel.querySelectorAll("[data-block-ip]").forEach(btn => {
        btn.addEventListener("click", () => blockIp(btn.dataset.blockIp, inc));
    });
    panel.querySelector("#incident-view-events")?.addEventListener("click", () => {
        document.querySelector('.tab[data-tab="events"]')?.click();
    });
}

async function resolveIncident(id) {
    if (!canConfigure() || busy || needsRefresh) return;
    const epoch = sessionEpoch;
    const token = getAuthToken();
    const current = () => epoch === sessionEpoch && token === getAuthToken();
    busy = true;
    notice('pending');
    render();
    try {
        const resp = await authFetch(`/api/incidents/${id}/resolve`, { method: "POST" });
        if (!current()) return;
        if (!resp || !resp.ok) {
            needsRefresh = true;
            notice(!resp || resp.status >= 500 ? 'unknown' : 'rejected');
            return;
        }
        const result = await resp.json();
        if (!current()) return;
        if (result.status !== 'ok') throw new Error('Unconfirmed incident result');
        busy = false;
        if (await loadIncidents() && current()) showToast(tr('title'), tr('saved'), 'INFO');
    } catch (e) {
        if (!current()) return;
        needsRefresh = true;
        notice('unknown');
    } finally {
        if (current()) {
            busy = false;
            render();
        }
    }
}

async function blockIp(ip, incident) {
    if (!confirm(`${ip} 를 차단하시겠습니까?`)) return;
    try {
        const resp = await authFetch("/api/blocks", {
            method: "POST",
            body: JSON.stringify({
                ip,
                reason: `Incident #${incident.id}: ${incident.title}`,
            }),
        });
        if (resp && resp.ok) {
            showToast("Block", `${ip} 차단됨`, "INFO");
        } else {
            const err = resp ? await resp.json().catch(() => ({})) : {};
            showToast("Block", err.error || `${ip} 차단 실패`, "CRITICAL");
        }
    } catch (e) {
        console.error("Failed to block IP", e);
    }
}

export function registerIncidentListeners() {
    document.getElementById("incidents-show-resolved")?.addEventListener("change", (e) => {
        includeResolved = e.target.checked;
        selectedId = null;
        loadIncidents();
    });
    document.getElementById("btn-incidents-refresh")?.addEventListener("click", () => loadIncidents());
}

window.addEventListener('panopticon:session-ended', () => {
    sessionEpoch++;
    loadAttempt++;
    incidents = [];
    selectedId = null;
    busy = false;
    needsRefresh = true;
    notice('');
    render();
});
