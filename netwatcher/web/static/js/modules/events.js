/**
 * NetWatcher Events Module (Production Grade - No Omissions)
 */

import { authFetch } from '../core/api.js';
import { esc, formatTime, formatHexDump, showToast, renderPagination } from '../core/utils.js';
import { whitelistData, toggleWhitelist } from './devices.js';

var eventsPage = 0;
var eventsTotal = 0;

export async function loadEvents(page) {
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

    try {
        var resp = await authFetch("/api/events?" + params.toString());
        if (!resp || !resp.ok) return;
        var data = await resp.json();
        eventsTotal = data.total || 0;
        
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
        <td><button class="btn-detail" onclick="window.showEventDetail(${evId})">Detail</button></td>
    `;
    return tr;
}

window.showEventDetail = async function(eventId) {
    if (!eventId) return;
    var modalBody = document.getElementById("modal-body");
    modalBody.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-dim)">Loading Event Details...</div>';
    document.getElementById("modal-overlay").classList.remove("hidden");

    try {
        var resp = await authFetch("/api/events/" + eventId);
        var data = await resp.json();
        if (data.event) renderEventDetail(data.event);
        else modalBody.innerHTML = '<div style="padding:20px">Event not found.</div>';
    } catch (e) { modalBody.innerHTML = '<div style="padding:20px">Error: ' + esc(e.message) + '</div>'; }
};

function row(label, value) {
    return `<div class="detail-label">${esc(label)}</div><div class="detail-value">${value || "-"}</div>`;
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

    let html = '<div class="detail-section"><h3>Overview</h3><div class="detail-grid">';
    html += row("Event ID", ev.id);
    html += row("Timestamp", formatTime(ev.timestamp));
    html += row("Engine", ev.engine);
    html += row("Severity", `<span class="severity-badge severity-${esc(ev.severity)}">${esc(ev.severity)}</span>`);
    html += '</div></div>';

    // Detection Reasoning
    if (ev.severity === "WARNING" || ev.severity === "CRITICAL") {
        html += renderReasoning(ev);
    }

    // Network Info
    html += '<div class="detail-section"><h3>Network Information</h3><div class="detail-grid">';
    html += row("Source IP", ev.source_ip);
    html += row("Source MAC", `<code>${esc(ev.source_mac)}</code>`);
    html += row("Dest IP", ev.dest_ip);
    html += row("Dest MAC", `<code>${esc(ev.dest_mac)}</code>`);
    html += '</div></div>';

    // Packet Detail
    var pkt = ev.packet_info;
    if (pkt && typeof pkt === "object" && Object.keys(pkt).length > 0) {
        html += '<div class="detail-section"><h3>Packet Analysis (DPI)</h3>';
        if (pkt.layers) {
            html += '<div style="margin-bottom:12px">' + pkt.layers.map(l => `<span class="layer-badge">${esc(l)}</span>`).join("") + '</div>';
        }
        html += '<div class="detail-grid">';
        html += row("Length", `${pkt.length} bytes`);
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

    // Metadata
    if (ev.metadata && Object.keys(ev.metadata).length > 0) {
        html += '<div class="detail-section"><h3>Technical Metadata</h3>';
        html += `<pre class="json-block">${esc(JSON.stringify(ev.metadata, null, 2))}</pre></div>`;
    }

    // Whitelist Actions
    if (ev.source_ip) {
        var isWhitelisted = (whitelistData.ips || []).includes(ev.source_ip);
        var btnText = isWhitelisted ? window.i18next.t("whitelist.remove_ip") : window.i18next.t("whitelist.add_ip");
        html += `<div class="detail-section"><h3>Exception Management</h3><div style="display:flex;gap:10px;margin-top:8px">`;
        html += `<button class="btn ${isWhitelisted ? 'btn-accent' : ''}" onclick="window.handleEventWhitelistToggle('ip', '${ev.source_ip}')">
                 ${esc(btnText)} (${ev.source_ip})</button></div></div>`;
    }

    modalBody.innerHTML = html;
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
    await toggleWhitelist(type, value);
    window.closeModal();
    showToast("Whitelist Updated", `${value} toggled`, "info");
};
