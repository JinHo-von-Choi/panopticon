/**
 * NetWatcher Devices Module (Production Grade - No Omissions)
 */

import { authFetch } from '../core/api.js';
import { esc, formatTime, formatBytes, renderPagination } from '../core/utils.js';
import { DEVICE_TYPE_MAP } from '../core/constants.js';

export var whitelistData = { ips: [], macs: [], domains: [], ip_ranges: [] };
export var devicesAll = [];
export var devicesFiltered = [];
var devicesPage = 0;
const DEVICES_PER_PAGE = 50;

export async function fetchWhitelist() {
    try {
        var resp = await authFetch("/api/whitelist");
        if (resp.ok) {
            whitelistData = await resp.json();
        }
    } catch (e) { console.error("Failed to fetch whitelist", e); }
}

export async function toggleWhitelist(type, value) {
    if (!value) return;
    try {
        var resp = await authFetch("/api/whitelist/toggle", {
            method: "POST",
            body: JSON.stringify({ type: type, value: value })
        });
        if (resp.ok) {
            await fetchWhitelist();
        }
    } catch (e) { alert("Failed to toggle whitelist: " + e.message); }
}

export async function loadDevices() {
    try {
        await fetchWhitelist();
        var resp = await authFetch("/api/devices");
        if (!resp || !resp.ok) return;
        var data = await resp.json();
        devicesAll = data.devices || [];
        
        var statDev = document.getElementById("stat-devices");
        if (statDev) statDev.textContent = devicesAll.length;
        
        filterDevices();
        renderDevicesPage(0);
    } catch (e) { console.error("Failed to load devices", e); }
}

export function filterDevices() {
    var search = (document.getElementById("devices-search")?.value || "").toLowerCase();
    var type   = document.getElementById("devices-filter-type")?.value;
    var known  = document.getElementById("devices-filter-known")?.value;

    devicesFiltered = devicesAll.filter(function (d) {
        if (type && d.device_type !== type) return false;
        if (known === "known" && !d.is_known) return false;
        if (known === "unregistered" && d.is_known) return false;
        if (search) {
            var match = (d.mac_address || "").toLowerCase().includes(search) ||
                        (d.ip_address || "").toLowerCase().includes(search) ||
                        (d.nickname || "").toLowerCase().includes(search) ||
                        (d.hostname || "").toLowerCase().includes(search) ||
                        (d.vendor || "").toLowerCase().includes(search);
            if (!match) return false;
        }
        return true;
    });
}

export function renderDevicesPage(page) {
    devicesPage = page;
    var start = page * DEVICES_PER_PAGE;
    var end = Math.min(start + DEVICES_PER_PAGE, devicesFiltered.length);
    var body = document.getElementById("devices-body");
    if (!body) return;

    body.innerHTML = "";
    for (var i = start; i < end; i++) {
        body.appendChild(renderDeviceRow(devicesFiltered[i]));
    }
    renderPagination(document.getElementById("devices-pagination"), devicesPage, devicesFiltered.length, DEVICES_PER_PAGE, renderDevicesPage);
}

function renderDeviceRow(d) {
    var tr = document.createElement("tr");
    tr.className = "clickable";
    
    var isWhitelisted = (whitelistData.macs || []).includes(d.mac_address.toLowerCase()) || 
                       (d.ip_address && (whitelistData.ips || []).includes(d.ip_address));
    
    var wlHtml = isWhitelisted ? ` <span class="known-badge" style="background:#2ed573" title="${window.i18next.t("whitelist.status_whitelisted")}">\u2713</span>` : '';
    var nickHtml = d.nickname
        ? `<span class="nickname-tag">${esc(d.nickname)}</span>${d.is_known ? ' <span class="known-badge">R</span>' : ''}${wlHtml}`
        : (d.is_known ? `<span class="known-badge">Registered</span>${wlHtml}` : wlHtml || '-');

    tr.innerHTML = `
        <td>${renderRiskBadge(d.risk_level, d.risk_score)}</td>
        <td>${renderDeviceTypeChip(d.device_type || "unknown")}</td>
        <td>${nickHtml}</td>
        <td><code>${esc(d.mac_address)}</code></td>
        <td>${d.vendor ? `<span class="vendor-tag">${esc(d.vendor)}</span>` : 'Unknown'}</td>
        <td>${esc(d.ip_address || "-")}</td>
        <td>${esc(d.hostname || "-")}</td>
        <td>${d.os_hint ? `<span class="os-tag">${esc(d.os_hint)}</span>` : "-"}</td>
        <td>${esc(formatTime(d.first_seen))}</td>
        <td>${esc(formatTime(d.last_seen))}</td>
        <td>${(d.total_packets || 0).toLocaleString()}</td>
        <td><button class="btn-detail" onclick="window.showDeviceDetail('${d.mac_address}')">Edit</button></td>
    `;
    tr.addEventListener("click", () => window.showDeviceDetail(d.mac_address));
    return tr;
}

function renderRiskBadge(level, score) {
    return `<span class="risk-badge risk-${level || "low"}">${(level || "low").toUpperCase()} (${score || 0})</span>`;
}

function renderDeviceTypeChip(type) {
    var cfg = DEVICE_TYPE_MAP[type] || DEVICE_TYPE_MAP.unknown;
    return `<span class="device-type-chip" style="color:${cfg.color};background:${cfg.bg}">${cfg.label}</span>`;
}

window.showDeviceDetail = async function(mac) {
    if (!mac) return;
    var body = document.getElementById("device-modal-body");
    body.innerHTML = '<div style="text-align:center;padding:20px">Loading...</div>';
    document.getElementById("device-modal-title").textContent = "Device Detail: " + mac;
    document.getElementById("device-modal-overlay").classList.remove("hidden");

    try {
        var resp = await authFetch("/api/devices/" + mac);
        var data = await resp.json();
        if (data.device) renderDeviceModalContent(data.device);
    } catch (e) { body.innerHTML = "Error: " + e.message; }
};

function renderDeviceModalContent(dev) {
    var body = document.getElementById("device-modal-body");
    var isWhitelisted = (whitelistData.macs || []).includes(dev.mac_address.toLowerCase());
    
    let html = `
        <form id="device-form">
            <div class="detail-section">
                <h3>Identity</h3>
                <div class="form-group">
                    <label>Nickname</label>
                    <input type="text" id="dev-nickname" class="input-search" value="${esc(dev.nickname || '')}" style="width:100%" />
                </div>
                <div class="form-group">
                    <label>Device Type</label>
                    <select id="dev-type" class="input-search" style="width:100%">
                        ${Object.keys(DEVICE_TYPE_MAP).map(t => `<option value="${t}" ${dev.device_type === t ? 'selected' : ''}>${DEVICE_TYPE_MAP[t].label}</option>`).join("")}
                    </select>
                </div>
            </div>
            <div class="detail-section">
                <h3>Technical Details</h3>
                <div class="detail-grid">
                    <div class="detail-label">MAC Address</div><div class="detail-value"><code>${dev.mac_address}</code></div>
                    <div class="detail-label">IP Address</div><div class="detail-value">${dev.ip_address || "-"}</div>
                    <div class="detail-label">Vendor</div><div class="detail-value">${dev.vendor || "-"}</div>
                    <div class="detail-label">First Seen</div><div class="detail-value">${formatTime(dev.first_seen)}</div>
                </div>
            </div>
            <div class="detail-section">
                <h3>Exception (Whitelist)</h3>
                <button type="button" class="btn ${isWhitelisted ? 'btn-accent' : ''}" onclick="window.handleWhitelistToggle('mac', '${dev.mac_address}')">
                    ${isWhitelisted ? 'Remove from Whitelist' : 'Add to Whitelist'}
                </button>
            </div>
            <div class="form-actions" style="margin-top:20px">
                <button type="submit" class="btn btn-accent" style="width:100%">Update Device Info</button>
            </div>
        </form>
    `;
    body.innerHTML = html;
}

window.handleWhitelistToggle = async function(type, value) {
    await toggleWhitelist(type, value);
    window.showDeviceDetail(value); // Refresh modal
    loadDevices(); // Refresh list
};
