/**
 * NetWatcher Events Module (Production Grade - No Omissions)
 */

import { authFetch, canConfigure, getCurrentUserId } from '../core/api.js';
import { esc, escAttr, formatTime, formatHexDump, showToast, renderPagination } from '../core/utils.js';
import { openEventDrawer } from '../core/detail-drawer.js';
import { whitelistData, toggleWhitelist, fetchWhitelist } from './devices.js';
import { canChangeWhitelist } from '../core/whitelist-state.js';
import { featureEnabled } from '../core/capabilities.js';
import { loadBusinessReview } from './business-review.js';
import { loadCaseWorkflow } from './case-workflow.js';
import { loadWorkSchedules } from './work-schedules.js';
import { loadEventGroup, initGroupList, initPreviousEvents } from './event-groups.js';
import { mountEvidence, resetEvidence } from './evidence.js';

var eventsPage = 0;
var eventsTotal = 0;
var livePending = 0;
var listRequest = 0;

function renderLivePending() {
    const badge = document.getElementById('events-live-pending');
    if (!badge) return;
    badge.hidden = !livePending;
    badge.textContent = window.i18next.t('console.event_context.new_pending', { count: livePending });
}

export function receiveLiveEvent(event) {
    const body = document.getElementById('events-body');
    if (!body) return;
    const filtered = ['filter-severity', 'filter-engine', 'filter-search', 'filter-since', 'filter-until', 'filter-case-owner', 'filter-case-status']
        .some(id => document.getElementById(id).value.trim());
    if (eventsPage !== 0 || filtered || document.getElementById('filter-case-unassigned')?.checked || document.getElementById('filter-case-mine')?.checked || !document.getElementById('modal-overlay').classList.contains('hidden')) {
        livePending += 1;
        renderLivePending();
        return;
    }
    if (body.querySelector('[data-event-id="' + CSS.escape(String(event.id)) + '"]')) return;
    body.insertBefore(renderEventRow(event), body.firstChild);
    const limit = parseInt(document.getElementById('filter-pagesize').value) || 100;
    while (body.children.length > limit) body.lastElementChild.remove();
    eventsTotal += 1;
    renderPagination(document.getElementById('events-pagination'), eventsPage, eventsTotal, limit, loadEvents);
}


export async function loadEvents(page = eventsPage) {
    if (featureEnabled('event_groups')) initGroupList();
    const request = ++listRequest;
    eventsPage = page;
    var sev    = document.getElementById("filter-severity").value;
    var eng    = document.getElementById("filter-engine").value;
    var search = document.getElementById("filter-search").value.trim();
    var since  = document.getElementById("filter-since").value;
    var until  = document.getElementById("filter-until").value;
    var psize  = parseInt(document.getElementById("filter-pagesize").value) || 100;

    var params = new URLSearchParams();
    params.set("limit", psize);
    params.set("offset", page * psize);
    if (sev)    params.set("severity", sev);
    if (eng)    params.set("engine", eng);
    if (search) params.set("q", search);
    if (since)  params.set("since", since + "T00:00:00.000000Z");
    if (until)  params.set("until", until + "T23:59:59.999999Z");

    if (featureEnabled('case_workflows')) {
        const status = document.getElementById('filter-case-status').value;
        const unassigned = document.getElementById('filter-case-unassigned').checked;
        const owner = document.getElementById('filter-case-owner').value.trim();
        if (status) params.set('case_status', status);
        if (document.getElementById('filter-case-mine').checked && getCurrentUserId()) params.set('case_owner_id', getCurrentUserId());
        else if (unassigned || owner) params.set('case_owner', unassigned ? '' : owner);
    }
    try {
        var resp = await authFetch("/api/events?" + params.toString());
        if (!resp || !resp.ok) return;
        var data = await resp.json();
        if (request !== listRequest) return;
        eventsTotal = data.total || 0;
        livePending = 0;
        renderLivePending();
        
        var body = document.getElementById("events-body");
        if (!body) return;
        body.innerHTML = "";
        
        if (data.events) {
            data.events.forEach(ev => body.appendChild(renderEventRow(ev)));
        }
        renderPagination(document.getElementById("events-pagination"), eventsPage, eventsTotal, psize, loadEvents);
    } catch (e) { console.error("Failed to load events", e); }
}

export async function exportEvents(format) {
    var sev    = document.getElementById("filter-severity").value;
    var eng    = document.getElementById("filter-engine").value;
    var since  = document.getElementById("filter-since").value;
    var until  = document.getElementById("filter-until").value;

    var params = new URLSearchParams();
    params.set("format", format);
    if (sev)   params.set("severity", sev);
    if (eng)   params.set("engine", eng);
    if (since) params.set("since", since + "T00:00:00.000000Z");
    if (until) params.set("until", until + "T23:59:59.999999Z");

    const search = document.getElementById('filter-search').value.trim();
    if (search) params.set('q', search);
    if (featureEnabled('case_workflows')) {
        const status = document.getElementById('filter-case-status').value;
        const unassigned = document.getElementById('filter-case-unassigned').checked;
        const owner = document.getElementById('filter-case-owner').value.trim();
        if (status) params.set('case_status', status);
        if (document.getElementById('filter-case-mine').checked && getCurrentUserId()) params.set('case_owner_id', getCurrentUserId());
        else if (unassigned || owner) params.set('case_owner', unassigned ? '' : owner);
    }
    try {
        const resp = await authFetch("/api/events/export?" + params.toString());
        if (!resp.ok) { alert("Export failed: Unauthorized"); return; }
        
        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `events_${new Date().getTime()}.${format}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (e) { alert("Export failed: " + e.message); }
}

export function renderEventRow(ev) {
    var tr = document.createElement("tr");
    tr.className = "clickable";
    var evId = ev.id || 0;
    tr.addEventListener("click", () => window.showEventDetail(evId));
    
    var title = ev.title;
    if (ev.title_key) {
        title = window.i18next.t(ev.title_key, Object.assign({}, ev.metadata || {}, {
            defaultValue: title,
            source_ip: ev.source_ip || "-",
            source_mac: ev.source_mac || "-"
        }));
    }
    
    tr.innerHTML = `
        <td>${esc(formatTime(ev.timestamp))}</td>
        <td><span class="severity-badge severity-${esc(ev.severity)}">${esc(ev.severity)}</span></td>
        <td><span class="engine-tag">${esc(ev.engine)}</span></td>
        <td>${esc(title)}</td>
        <td>${esc(ev.source_ip || ev.source_mac || "-")}</td>
        <td>${esc(ev.dest_ip || ev.dest_mac || "-")}</td>
        <td ${featureEnabled('case_workflows') ? '' : 'hidden'}>${esc(ev.case_owner || window.i18next.t('console.case_workflow.unassigned'))} · ${esc(window.i18next.t('console.case_workflow.statuses.' + (ev.case_status || 'open')))}</td>
        <td><button class="btn-detail" data-event-id="${escAttr(evId)}">Detail</button></td>
    `;
    tr.querySelector("[data-event-id]").addEventListener("click", function (e) {
        e.stopPropagation();
        window.showEventDetail(evId);
    });
    return tr;
}

let detailRequest = 0;
let selectedEvent = null;
window.addEventListener('nw-session-ended', () => {
    detailRequest++; selectedEvent = null;
    document.getElementById('modal-body')?.replaceChildren();
    document.getElementById('modal-overlay')?.classList.add('hidden');
});
const t = (key, options = {}) => window.i18next.t("console.event_context." + key, options);

window.showEventDetail = async function(eventId) {
    if (!eventId) return;
    const request = ++detailRequest;
    resetEvidence();
    selectedEvent = null;
    var modalBody = document.getElementById("modal-body");
    document.getElementById("modal-title").textContent = t("title");
    modalBody.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-dim)">Loading Event Details...</div>';
    openEventDrawer();

    try {
        await fetchWhitelist();
        var resp = await authFetch("/api/events/" + eventId);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        var data = await resp.json();
        if (request !== detailRequest || document.getElementById("modal-overlay").classList.contains("hidden")) return;
        if (data.event) {
            selectedEvent = data.event;
            renderEventDetail(data.event);
            loadDrawerObservation(request);
        }
        else modalBody.innerHTML = '<div style="padding:20px">Event not found.</div>';
    } catch (e) { if (request !== detailRequest || document.getElementById("modal-overlay").classList.contains("hidden")) return; modalBody.innerHTML = '<div style="padding:20px">Error: ' + esc(e.message) + '</div>'; }
};

async function loadDrawerObservation(request) {
    try {
        const response = await authFetch('/api/observation');
        const data = response?.ok ? await response.json() : null;
        if (request !== detailRequest || document.getElementById('modal-overlay').classList.contains('hidden')) return;
        const panel = document.getElementById('event-observation');
        if (!panel) return;
        panel.textContent = '';
        const state = document.createElement('strong');
        state.textContent = ['observed', 'partial', 'stale', 'unknown'].includes(data?.state) ? data.state : 'unknown';
        panel.appendChild(state);
        const reason = document.createElement('p');
        reason.textContent = data?.reasons?.join(' · ') || t('observation_unknown');
        panel.appendChild(reason);
    } catch (_) {
        const panel = document.getElementById('event-observation');
        if (request === detailRequest && panel) panel.textContent = t('observation_unknown');
    }
}

async function pinSelectedEvidence() {
    const event = selectedEvent;
    if (!event || !canConfigure()) return;
    const reason = window.prompt(window.i18next.t('console.evidence_pin.reason'));
    if (!reason || reason.trim().length < 3) return;
    const button = document.getElementById('event-evidence-pin');
    if (button) button.disabled = true;
    try {
        const response = await authFetch(`/api/events/${encodeURIComponent(event.id)}/evidence/pin`, {
            method: 'POST', body: JSON.stringify({hours: 24, reason: reason.trim(), enabled: true})});
        if (!response?.ok) throw new Error('Pin unavailable');
        event.pcap_availability = await response.json();
        if (selectedEvent?.id === event.id) renderEventDetail(event);
        showToast(window.i18next.t('console.evidence_pin.saved'), '', 'info');
    } catch (_) { showToast(window.i18next.t('console.evidence_pin.failed'), '', 'critical'); }
    finally { if (button) button.disabled = false; }
}

document.addEventListener('click', event => {
    if (event.target.closest('#event-evidence-pin')) pinSelectedEvidence();
});

function renderContext(ev) {
    const meta = ev.metadata || {};
    const aggregation = meta.aggregation || {};
    const count = Number.isInteger(aggregation.count) && aggregation.count > 0 ? aggregation.count : 1;
    const external = meta.external_eve;
    const pcap = meta.pcap || {};
    const state = ['pending', 'persisted', 'omitted', 'failed', 'volatile'].includes(pcap.state) ? pcap.state : 'unknown';
    let html = `<section class="event-context"><div class="console-eyebrow">${esc(t('signal'))} / #${esc(ev.id)}</div>
        <div class="event-context-count"><strong>${count.toLocaleString()}</strong><span>${esc(t('occurrences'))}</span></div>
        <div class="event-context-window"><span>${esc(formatTime(aggregation.first_seen || ev.timestamp))}</span>
        <span aria-hidden="true">→</span><span>${esc(formatTime(aggregation.last_seen || ev.timestamp))}</span></div>
        <p class="text-dim">${esc(t('representative'))}</p></section>`;
    html += `<section class="detail-section"><h3>${esc(t('asset'))}</h3><div class="detail-grid">`;
    html += row(t('source'), ev.source_mac || ev.source_ip);
    if (meta.business_context?.state === 'expected_job') {
        html += row(window.i18next.t('console.asset_context.expected_flows'),
            `${meta.business_context.role} / v${meta.business_context.context_version} / ${meta.business_context.original_severity} → INFO`);
    }
    html += row(t('role'), ev.asset_context?.status === 'confirmed' ? window.i18next.t('console.asset_context.roles.' + ev.asset_context.role) : t('role_unknown'));
    if (ev.asset_context?.reason) {
        html += row(t('reason'), window.i18next.t('console.asset_context.reasons.' + ev.asset_context.reason));
    }
    if (ev.asset_context?.scope === 'current_inventory') {
        html += row(window.i18next.t('console.asset_context.title'), window.i18next.t('console.asset_context.scope'));
    }
    html += `</div><p class="text-dim">${esc(t('relationship_unknown'))}</p></section>`;
    if (meta.baseline) {
        const baseline = meta.baseline;
        const states = ['cold_start', 'learning', 'sufficient_samples', 'restored', 'drift_suspected'];
        const state = states.includes(baseline.state) ? baseline.state : 'unknown';
        html += `<section class="detail-section"><h3>${esc(t('baseline'))}</h3><div class="detail-grid">`;
        html += row(t('state'), t('baseline_states.' + state));
        html += row(t('samples'), Number.isInteger(baseline.accepted_samples) ? baseline.accepted_samples : t('unmeasured'));
        html += `</div><p class="text-dim">${esc(t('statistical_baseline'))}</p></section>`;
    }
    if (external && typeof external === 'object' && !Array.isArray(external)) {
        const detail = external.details || {};
        html += `<section class="detail-section" id="event-eve-evidence"><h3>${esc(t('eve.title'))}</h3><div class="detail-grid">`;
        html += row(t('eve.input'), `${external.sensor_id || '-'} / ${external.source_id || '-'}`);
        html += row(t('eve.rule'), detail.signature_id);
        html += row(t('eve.original_severity'), detail.severity);
        html += row(t('eve.flow'), external.flow_id);
        html += row(t('eve.observed'), formatTime(external.observed_at));
        html += row(t('eve.offset'), external.original_ref?.offset);
        html += row('SHA256', external.original_ref?.sha256);
        html += `</div><p class="text-dim">${esc(t('eve.note'))}</p></section>`;
    } else {
        html += `<section class="detail-section"><h3>${esc(t('pcap'))}</h3><div class="detail-grid">`;
        html += htmlRow(t('state'), `<span class="evidence-layer" data-pcap-state="${state}">${esc(t('pcap_states.' + state))}</span>`);
        html += row(t('reason'), pcap.reason);
        if (state === 'persisted') {
            html += row(t('file'), String(pcap.path || '').split('/').at(-1));
            html += row('SHA256', pcap.sha256);
        }
        if (ev.pcap_availability && !featureEnabled('evidence_control_remote')) {
            html += row(t('file'), ev.pcap_availability.state);
            html += row('Review pin', ev.pcap_availability.pin_state);
            if (ev.pcap_availability.state === 'available' && canConfigure() && !featureEnabled('evidence_control_remote')) {
                html += `<button type="button" class="btn" id="event-evidence-pin">${esc(window.i18next.t('console.evidence_pin.action'))}</button>`;
            }
        }
        if (featureEnabled('evidence_control_remote')) html += '<div id="remote-evidence-control" class="evidence-controls"></div>';
        html += `</div><p class="text-dim">${esc(t('pcap_note'))}</p></section>`;
    }
    html += `<section class="detail-section"><h3>${esc(t('observation'))}</h3>
        <div id="event-observation" class="event-observation">${esc(t('observation_unknown'))}</div>
        <p class="text-dim">${esc(t('observation_note'))}</p></section>`;
    return html;
}

window.i18next?.on('languageChanged', () => {
    renderLivePending();
    if (selectedEvent && !document.getElementById('modal-overlay').classList.contains('hidden')) {
        renderEventDetail(selectedEvent);
        loadDrawerObservation(detailRequest);
    }
});

/**
 * detail-grid 한 줄. value 는 이미 안전한 HTML 조각이거나 평문이다.
 * 조각을 넘길 때는 htmlRow() 을, 평문은 row() 를 쓴다. row() 는 항상 이스케이프하므로
 * 공격자가 제어하는 값이 HTML로 해석될 경로가 생기지 않는다(PR 02).
 */
function row(label, value) {
    return `<div class="detail-label">${esc(label)}</div><div class="detail-value">${esc(value) || "-"}</div>`;
}

// ────────────────────────────────────────────────────────────────────
// 증거 봉투 (PR 09)
// ────────────────────────────────────────────────────────────────────

var EVIDENCE_LAYER_LABELS = {
    summary:  { label: "요약",   hint: "무엇이 일어났는가" },
    evidence: { label: "근거",   hint: "왜 그렇게 판단했는가" },
    raw:      { label: "원자료", hint: "무엇을 관측했는가" }
};

/**
 * 탐지 결과의 세 층(요약·근거·원자료)을 명시적으로 그린다.
 *
 * 이전에는 이 정보가 Technical Metadata JSON 안에 파묻혀 있어, 검토자가
 * "이 탐지가 검증 가능한가" 를 한눈에 알 수 없었다. 없는 층은 숨기지 않고
 * "없음" 으로 드러낸다 — 없는 근거를 지어내는 것보다 정직한 누락이 낫다.
 */
function renderEvidenceEnvelope(evidence) {
    if (!evidence || typeof evidence !== "object") return "";

    var layers = evidence.layers || {};
    var complete = evidence.status === "complete";
    var banner = complete
        ? '<div class="evidence-envelope" data-status="complete">검증 가능한 탐지 — 세 층이 모두 있습니다</div>'
        : '<div class="evidence-envelope" data-status="incomplete">검증 근거가 빠졌습니다: '
          + '<span>' + esc((evidence.missing || []).map(function (k) {
              return (EVIDENCE_LAYER_LABELS[k] || { label: k }).label;
          }).join(", ")) + '</span></div>';

    var rows = Object.keys(EVIDENCE_LAYER_LABELS).map(function (key) {
        var meta = EVIDENCE_LAYER_LABELS[key];
        var present = layers[key] === true;
        return '<div class="detail-label">' + esc(meta.label)
             + '<div class="detail-hint">' + esc(meta.hint) + '</div></div>'
             + '<div class="detail-value"><span class="evidence-layer" data-present="'
             + (present ? "yes" : "no") + '">'
             + (present ? "있음" : "없음") + '</span></div>';
    }).join("");

    return '<div class="detail-section"><h3>증거 봉투</h3>' + banner
         + '<div class="detail-grid">' + rows + '</div></div>';
}

/** 이미 구성한 HTML 조각을 그대로 넣는 경우에만 사용한다. */
function htmlRow(label, valueHtml) {
    return `<div class="detail-label">${esc(label)}</div><div class="detail-value">${valueHtml || "-"}</div>`;
}

function renderEventDetail(ev) {
    var modalTitle = document.getElementById("modal-title");
    var modalBody = document.getElementById("modal-body");
    
    var title = ev.title;
    if (ev.title_key) {
        title = window.i18next.t(ev.title_key, Object.assign({}, ev.metadata || {}, {
            defaultValue: title,
            source_ip: ev.source_ip || "-",
            source_mac: ev.source_mac || "-"
        }));
    }
    modalTitle.textContent = `[${ev.severity}] ${title}`;
    document.getElementById("modal-close-btn").setAttribute("aria-label", t("close"));

    let html = renderContext(ev);
    if (featureEnabled('event_groups')) html += '<section class="detail-section" id="event-group"></section><section class="detail-section" id="event-previous"></section>';
    if (featureEnabled('work_schedules')) html += '<section class="detail-section" id="event-work-schedules"></section>';
    if (featureEnabled('case_workflows')) html += '<section class="detail-section" id="event-case-workflow"></section>';
    if (featureEnabled('business_reviews')) html += '<section class="detail-section" id="event-business-review"></section>';
    html += '<div class="detail-section"><h3>Overview</h3><div class="detail-grid">';
    html += row("Event ID", ev.id);
    html += row("Timestamp", formatTime(ev.timestamp));
    html += row("Engine", ev.engine);
    html += htmlRow("Severity", `<span class="severity-badge severity-${esc(ev.severity)}">${esc(ev.severity)}</span>`);
    html += '</div></div>';

    // Detection Reasoning
    if (ev.severity === "WARNING" || ev.severity === "CRITICAL") {
        html += renderReasoning(ev);
    }

    // Network Info
    html += '<div class="detail-section"><h3>Network Information</h3><div class="detail-grid">';
    html += row("Source IP", ev.source_ip);
    html += htmlRow("Source MAC", `<code>${esc(ev.source_mac)}</code>`);
    html += row("Dest IP", ev.dest_ip);
    html += htmlRow("Dest MAC", `<code>${esc(ev.dest_mac)}</code>`);
    html += '</div></div>';

    // Packet Detail
    var pkt = ev.packet_info;
    if (pkt && typeof pkt === "object" && Object.keys(pkt).length > 0) {
        html += '<div class="detail-section"><h3>Packet Analysis (DPI)</h3>';
        if (pkt.layers) {
            html += '<div style="margin-bottom:12px">' + pkt.layers.map(l => `<span class="layer-badge">${esc(l)}</span>`).join("") + '</div>';
        }
        html += '<div class="detail-grid">';
        html += row("Length", Number.isInteger(pkt.length) && pkt.length >= 0 ? `${pkt.length} bytes` : t("unmeasured"));
        if (pkt.ip_ttl) html += row("TTL", pkt.ip_ttl);
        if (pkt.src_port) html += row("Src Port", pkt.src_port);
        if (pkt.dst_port) html += row("Dst Port", pkt.dst_port);
        if (pkt.tcp_flags_list) html += row("TCP Flags", pkt.tcp_flags_list.join(", "));
        if (pkt.dns_qname) html += row("DNS Query", pkt.dns_qname);
        if (pkt.http_host) html += row("HTTP Host", pkt.http_host);
        html += '</div>';
        
        if (pkt.payload_text) {
            html += '<div style="margin-top:10px"><span class="detail-label">Payload Preview:</span>';
            html += `<pre class="payload-text">${esc(pkt.payload_text)}</pre></div>`;
        }
        if (pkt.payload_hex) {
            html += '<div style="margin-top:10px"><span class="detail-label">Hex Dump:</span>';
            html += `<pre class="hex-dump">${esc(formatHexDump(pkt.payload_hex))}</pre></div>`;
        }
        html += '</div>';
    }

    // 증거 봉투: 요약 → 근거 → 원자료 (PR 09)
    html += renderEvidenceEnvelope(ev.evidence);

    // Metadata
    if (ev.metadata && Object.keys(ev.metadata).length > 0) {
        html += '<details class="detail-section event-technical"><summary>' + esc(t('technical')) + '</summary>';
        html += `<pre class="json-block">${esc(JSON.stringify(ev.metadata, null, 2))}</pre></details>`;
    }

    // Whitelist Actions
    if (ev.source_ip && canConfigure() && featureEnabled('whitelist')) {
        var isWhitelisted = (whitelistData.ips || []).includes(ev.source_ip);
        var btnText = isWhitelisted ? window.i18next.t("whitelist.remove_ip") : window.i18next.t("whitelist.add_ip");
        html += `<details class="detail-section event-technical"><summary>${esc(t("global_exception"))}</summary><p class="scope-note">${esc(t("global_exception_note"))}</p><div style="display:flex;gap:10px;margin-top:8px">`;
        html += `<button class="btn ${isWhitelisted ? 'btn-accent' : ''}" data-wl-event-ip="${escAttr(ev.source_ip)}" data-whitelist-change ${canChangeWhitelist() ? '' : 'disabled'}>
                 ${esc(btnText)} (${esc(ev.source_ip)})</button></div></details>`;
    }

    modalBody.innerHTML = html;
    if (featureEnabled('evidence_control_remote')) mountEvidence(ev.id, ev.pcap_availability, value => {ev.pcap_availability = value;});
    if (featureEnabled('event_groups')) {
        loadEventGroup(ev, modalBody.querySelector('#event-group'));
        initPreviousEvents(ev, modalBody.querySelector('#event-previous'));
    }
    const businessPanel = modalBody.querySelector('#event-business-review');
    if (featureEnabled('work_schedules')) loadWorkSchedules(ev, modalBody.querySelector('#event-work-schedules'), 0, () => loadBusinessReview(ev, businessPanel));
    if (featureEnabled('case_workflows')) loadCaseWorkflow(ev, modalBody.querySelector('#event-case-workflow'));
    if (featureEnabled('business_reviews')) loadBusinessReview(ev, modalBody.querySelector('#event-business-review'));

    var wlBtn = modalBody.querySelector("[data-wl-event-ip]");
    if (wlBtn) {
        wlBtn.addEventListener("click", function () {
            window.handleEventWhitelistToggle("ip", wlBtn.dataset.wlEventIp);
        });
    }
}

function renderReasoning(ev) {
    var meta = ev.metadata || {};
    var engine = ev.engine;
    var html = `<div class="detail-section"><h3>${esc(window.i18next.t("detail.reasoning_title", { defaultValue: "Detection Reasoning" }))}</h3>`;
    html += '<div class="reasoning-box">';

    var description = ev.description;
    if (ev.description_key) {
        description = window.i18next.t(ev.description_key, Object.assign({}, meta, {
            defaultValue: description,
            source_ip: ev.source_ip || "-",
            source_mac: ev.source_mac || "-"
        }));
    }
    html += `<div class="reasoning-desc">${esc(description)}</div>`;

    var items = [];
    var reasonLabel = window.i18next.t("detail.reason_label", { defaultValue: "판단 근거" });

    if (engine === "arp_spoof") {
        if (meta.original_mac) items.push([window.i18next.t("detail.original_mac", { defaultValue: "기존 MAC" }), meta.original_mac]);
        if (meta.new_mac) items.push([window.i18next.t("detail.new_mac", { defaultValue: "변경된 MAC" }), meta.new_mac]);
        if (meta.original_mac && meta.new_mac) items.push([reasonLabel, window.i18next.t("engines.arp_spoof.reasoning.spoof")]);
        if (meta.count) items.push([reasonLabel, window.i18next.t("engines.arp_spoof.reasoning.flood", { count: meta.count })]);
    } else if (engine === "port_scan") {
        if (meta.count) items.push(["스캔된 포트 수", meta.count]);
        if (meta.is_internal) items.push([reasonLabel, "내부망 기기의 다수 포트 접근 감지 (임계값 완화 적용됨)"]);
    } else if (engine === "dns_anomaly") {
        if (meta.qname) items.push(["Query", meta.qname]);
        if (meta.entropy) items.push(["Entropy", meta.entropy]);
    }

    if (items.length > 0) {
        html += '<div class="detail-grid" style="margin-top:12px">';
        items.forEach(item => {
            html += `<div class="detail-label">${esc(item[0])}</div><div class="detail-value">${esc(item[1])}</div>`;
        });
        html += '</div>';
    }

    html += '</div></div>';
    return html;
}

window.handleEventWhitelistToggle = async function(type, value) {
    if (!confirm(t("global_exception_confirm", { value }))) return;
    if (!await toggleWhitelist(type, value)) {
        showToast(t("global_exception"), t("write_failed"), "CRITICAL");
        return;
    }
    window.closeModal();
    showToast("Whitelist Updated", `${value} toggled`, "info");
};

export async function exportWeeklyReport() {
    const button = document.getElementById('btn-weekly-report');
    button.disabled = true;
    try {
        const response = await authFetch('/api/reports/weekly?format=csv');
        if (!response?.ok) {
            showToast(window.i18next.t('console.case_queue.' + (response?.status === 413 ? 'capacity' : 'unavailable')), 'error');
            return;
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1] || 'panopticon-weekly.csv';
        document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    } catch { showToast(window.i18next.t('console.case_queue.unavailable'), 'error'); }
    finally { button.disabled = false; }
}
