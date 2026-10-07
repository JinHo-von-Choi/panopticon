/**
 * NetWatcher Devices Module (Production Grade - No Omissions)
 */

import { authFetch, canConfigure } from '../core/api.js';
import { esc, escAttr, textEl, formatTime, formatBytes, renderPagination, showToast } from '../core/utils.js';
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
            return true;
        }
        return false;
    } catch (e) { alert("Failed to toggle whitelist: " + e.message); return false; }
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

        renderInventorySummary(devicesAll);
        filterDevices();
        renderDevicesPage(0);
    } catch (e) { console.error("Failed to load devices", e); }
}

/**
 * 디바이스 목록 응답만으로 인벤토리 요약을 집계한다.
 * 전용 요약 엔드포인트를 추가하지 않는다.
 */
function renderInventorySummary(devices) {
    var el = document.getElementById("inv-summary");
    if (!el) return;

    if (!devices.length) {
        el.textContent = "";
        return;
    }

    var known        = devices.filter(function (d) { return d.is_known; }).length;
    var unregistered = devices.length - known;
    var highRisk     = devices.filter(function (d) { return (d.risk_score || 0) >= 7; }).length;

    var types = {};
    devices.forEach(function (d) {
        var t = d.device_type || "unknown";
        types[t] = (types[t] || 0) + 1;
    });
    var topTypes = Object.keys(types)
        .sort(function (a, b) { return types[b] - types[a]; })
        .slice(0, 4)
        .map(function (t) { return t + " " + types[t]; })
        .join(" · ");

    var parts = [
        "전체 " + devices.length,
        "등록 " + known,
        "미등록 " + unregistered,
    ];
    if (highRisk) parts.push("고위험 " + highRisk);
    if (topTypes) parts.push(topTypes);

    el.textContent = parts.join("  |  ");
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
    if (!devicesFiltered.length) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 12;
        cell.className = 'console-empty';
        cell.dataset.i18n = devicesAll.length ? 'console.no_device_match' : 'console.no_devices';
        cell.textContent = window.i18next.t(cell.dataset.i18n);
        row.append(cell);
        body.append(row);
    }
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
        <td><button class="btn-detail" data-mac="${esc(d.mac_address)}">Edit</button></td>
    `;
    tr.addEventListener("click", () => window.showDeviceDetail(d.mac_address));
    return tr;
}

function renderRiskBadge(level, score) {
    var safeLevel = String(level || "low").toLowerCase();
    return `<span class="risk-badge risk-${esc(safeLevel)}">${esc(safeLevel.toUpperCase())} (${esc(score || 0)})</span>`;
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
    } catch (e) {
        body.textContent = "";
        body.appendChild(textEl("Error: " + (e && e.message ? e.message : "unknown")));
    }
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
                    <div class="detail-label">MAC Address</div><div class="detail-value"><code>${esc(dev.mac_address)}</code></div>
                    <div class="detail-label">IP Address</div><div class="detail-value">${esc(dev.ip_address || "-")}</div>
                    <div class="detail-label">Vendor</div><div class="detail-value">${esc(dev.vendor || "-")}</div>
                    <div class="detail-label">First Seen</div><div class="detail-value">${esc(formatTime(dev.first_seen))}</div>
                </div>
            </div>
            <div class="detail-section">
                <h3>Exception (Whitelist)</h3>
                <button type="button" class="btn ${isWhitelisted ? 'btn-accent' : ''}" data-wl-mac="${esc(dev.mac_address)}">
                    ${isWhitelisted ? 'Remove from Whitelist' : 'Add to Whitelist'}
                </button>
            </div>
            <div class="form-actions" style="margin-top:20px">
                <button type="submit" class="btn btn-accent" style="width:100%">Update Device Info</button>
            </div>
        </form>
    `;
    body.innerHTML = html;
    renderAssetContext(body, dev);

    var wlBtn = body.querySelector("[data-wl-mac]");
    if (wlBtn) {
        wlBtn.addEventListener("click", function () {
            window.handleWhitelistToggle("mac", wlBtn.dataset.wlMac);
        });
    }
}

function renderAssetContext(body, dev) {
    const t = (key, options = {}) => window.i18next.t('console.asset_context.' + key, options);
    const panel = document.createElement('section');
    panel.className = 'detail-section asset-context-panel';
    const context = dev.asset_context || {};
    const roles = ['nas', 'backup', 'database', 'printer', 'gateway', 'pc', 'unknown'];
    panel.innerHTML = `<h3>${esc(t('title'))}</h3>
        <p>${esc(context.status === 'confirmed' ? t('confirmed', {role: t('roles.' + context.role)}) : t('unconfirmed'))}</p>
        <p class="text-dim">${esc(t('scope'))}</p>
        ${context.reason ? `<p>${esc(t('reasons.' + context.reason))}</p>` : ''}
        ${context.expires_at ? `<p>${esc(t('expires'))}: ${esc(formatTime(context.expires_at))}</p>` : ''}`;
    if (canConfigure() && dev.ip_address) {
        panel.innerHTML += `<label>${esc(t('role'))}<select class="input-search" id="asset-role">
            ${roles.map(role => `<option value="${role}" ${context.role === role ? 'selected' : ''}>${esc(t('roles.' + role))}</option>`).join('')}</select></label>
            <label>${esc(t('evidence'))}<textarea id="asset-evidence" class="input-search" maxlength="1000" rows="3"></textarea></label>
            <label>${esc(t('validity'))}<select id="asset-valid-hours" class="input-search"><option value="24">${esc(t('day'))}</option><option value="168" selected>${esc(t('week'))}</option><option value="720">${esc(t('month'))}</option></select></label>
            <label><input type="checkbox" id="asset-ownership"> ${esc(t('ownership', {ip: dev.ip_address, mac: dev.mac_address}))}</label>
            <button type="button" class="btn btn-accent" id="asset-confirm">${esc(t('save'))}</button>`;
    }
    body.querySelector('form').before(panel);
    panel.querySelector('#asset-confirm')?.addEventListener('click', async event => {
        const evidence = panel.querySelector('#asset-evidence').value.trim();
        if (!panel.querySelector('#asset-ownership').checked || evidence.length < 3) {
            showToast(t('required'), 'error'); return;
        }
        const button = event.currentTarget;
        button.disabled = true;
        try {
            const response = await authFetch('/api/devices/' + encodeURIComponent(dev.mac_address) + '/context', {
                method: 'PUT', body: JSON.stringify({role: panel.querySelector('#asset-role').value,
                    ip_address: dev.ip_address, expected_version: dev.context_version || 0,
                    valid_hours: Number(panel.querySelector('#asset-valid-hours').value),
                    ownership_confirmed: true, evidence})});
            if (!response?.ok) {
                showToast(t(response?.status === 409 ? 'conflict' : 'failed'), 'error'); return;
            }
            showToast(t('saved'), 'success');
            await window.showDeviceDetail(dev.mac_address);
        } catch (error) {
            console.error('Asset confirmation request failed', error);
            showToast(t('failed'), 'error');
        } finally { button.disabled = false; }
    });
}

window.handleWhitelistToggle = async function(type, value) {
    if (!await toggleWhitelist(type, value)) return;
    window.showDeviceDetail(value); // Refresh modal
    loadDevices(); // Refresh list
};
