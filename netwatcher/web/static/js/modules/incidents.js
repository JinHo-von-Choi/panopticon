/**
 * NetWatcher Incidents Module
 *
 * 상관 분석된 인시던트를 운영 큐로 제시한다. 좌측 목록에서 하나를 고르면
 * 우측에 킬체인 진행, 관련 엔진, 출발지 IP, 조치 버튼이 나타난다.
 */

import { authFetch } from '../core/api.js';
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

export async function loadIncidents() {
    const params = new URLSearchParams();
    params.set("limit", "100");
    params.set("include_resolved", includeResolved ? "true" : "false");

    try {
        const resp = await authFetch("/api/incidents?" + params.toString());
        if (!resp || !resp.ok) return;
        const data = await resp.json();
        incidents = data.incidents || [];

        renderList();
        if (selectedId !== null && !incidents.some(i => i.id === selectedId)) {
            selectedId = null;
        }
        if (selectedId === null && incidents.length) {
            selectedId = incidents[0].id;
        }
        renderDetail();
    } catch (e) {
        console.error("Failed to load incidents", e);
    }
}

function renderList() {
    const list  = document.getElementById("incidents-list");
    const count = document.getElementById("incidents-count");
    if (count) count.textContent = incidents.length;
    if (!list) return;

    if (!incidents.length) {
        list.innerHTML = `<div class="empty-state" data-i18n="incidents.empty">상관된 인시던트가 없습니다. 개별 이벤트는 Events 탭에서 확인하세요.</div>`;
        return;
    }

    list.innerHTML = incidents.map(inc => `
        <button class="incident-item ${inc.id === selectedId ? "selected" : ""} sev-${esc(inc.severity)}"
                data-incident-id="${inc.id}">
            <div class="incident-item-head">
                <span class="severity-badge severity-${esc(inc.severity)}">${esc(inc.severity)}</span>
                ${inc.resolved ? '<span class="incident-resolved-tag">resolved</span>' : ""}
            </div>
            <div class="incident-item-title">${esc(inc.title)}</div>
            <div class="incident-item-meta">
                ${(inc.kill_chain_stages || []).length} stages ·
                ${(inc.source_ips || []).length} src ·
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
            <span class="killchain-label">${esc(STAGE_LABEL[stage] || stage)}</span>
        </div>
    `).join("") + `</div>`;
}

function renderDetail() {
    const panel = document.getElementById("incident-detail");
    if (!panel) return;

    const inc = incidents.find(i => i.id === selectedId);
    if (!inc) {
        panel.innerHTML = `<div class="empty-state" data-i18n="incidents.select">왼쪽에서 인시던트를 선택하세요.</div>`;
        return;
    }

    const ips = (inc.source_ips || []).map(ip => `
        <span class="ip-chip">
            <code class="hunt-link" data-hunt-ip="${esc(ip)}" title="조사">${esc(ip)}</code>
            <button class="btn-chip" data-block-ip="${esc(ip)}" data-i18n="incidents.block">Block</button>
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

        <h4 data-i18n="incidents.kill_chain">Kill Chain</h4>
        ${renderKillChain(inc.kill_chain_stages)}

        <h4 data-i18n="incidents.source_ips">Source IPs</h4>
        <div class="incident-ips">${ips}</div>

        <h4 data-i18n="incidents.engines">Engines</h4>
        <div class="incident-engines">${engines}</div>

        <h4 data-i18n="incidents.related_alerts">Related Alerts</h4>
        <div class="incident-alerts">
            ${(inc.alert_ids || []).length}건
            ${(inc.alert_ids || []).length
                ? `<button class="btn-detail" id="incident-view-events">Events에서 보기</button>`
                : ""}
        </div>

        <div class="incident-actions">
            ${inc.resolved
                ? `<span class="incident-resolved-tag" data-i18n="incidents.already_resolved">해결됨</span>`
                : `<button class="btn btn-accent" id="incident-resolve" data-i18n="incidents.resolve">Resolve</button>`}
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
    try {
        const resp = await authFetch(`/api/incidents/${id}/resolve`, { method: "POST" });
        if (!resp || !resp.ok) {
            showToast("Incident", "인시던트 해결에 실패했습니다", "CRITICAL");
            return;
        }
        showToast("Incident", "인시던트를 해결 처리했습니다", "INFO");
        await loadIncidents();
    } catch (e) {
        console.error("Failed to resolve incident", e);
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
