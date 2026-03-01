/**
 * NetWatcher Whitelist Module
 */

import { authFetch } from '../core/api.js';
import { esc, showToast } from '../core/utils.js';

let _whitelistData = { ips: [], ip_ranges: [], macs: [], domains: [], domain_suffixes: [] };
let _filterType    = "";
let _searchQuery   = "";

export let whitelistData = _whitelistData;

export async function loadWhitelist() {
    try {
        const resp = await authFetch("/api/whitelist");
        if (!resp || !resp.ok) return;
        _whitelistData = await resp.json();
        whitelistData  = _whitelistData;
        renderWhitelistTable();
    } catch (e) { console.error("Failed to load whitelist", e); }
}

function renderWhitelistTable() {
    const tbody = document.getElementById("whitelist-body");
    if (!tbody) return;

    /** 타입별로 항목 평탄화 */
    const rows = [
        ..._whitelistData.ips.map(v          => ({ type: "ip",         value: v })),
        ..._whitelistData.ip_ranges.map(v     => ({ type: "ip_range",   value: v })),
        ..._whitelistData.macs.map(v          => ({ type: "mac",        value: v })),
        ..._whitelistData.domains.map(v       => ({ type: "domain",     value: v })),
        ..._whitelistData.domain_suffixes.map(v => ({ type: "suffix",  value: v })),
    ];

    /** 필터 적용 */
    const filtered = rows.filter(r => {
        if (_filterType && r.type !== _filterType) return false;
        if (_searchQuery && !r.value.toLowerCase().includes(_searchQuery)) return false;
        return true;
    });

    if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-dim)">No whitelist entries.</td></tr>';
        return;
    }

    tbody.innerHTML = "";
    filtered.forEach(({ type, value }) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
            `<td><span class="type-tag">${esc(type)}</span></td>` +
            `<td><code>${esc(value)}</code></td>` +
            `<td><button class="btn-detail" style="background:var(--critical)" ` +
                `onclick="window.removeWhitelistEntry('${esc(type)}','${esc(value)}')">Delete</button></td>`;
        tbody.appendChild(tr);
    });
}

export async function toggleWhitelist(type, value) {
    try {
        const resp = await authFetch("/api/whitelist/toggle", {
            method: "POST",
            body: JSON.stringify({ type, value }),
        });
        if (!resp || !resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        await loadWhitelist();
        return data.action; // "added" | "removed"
    } catch (e) {
        showToast("Error", "Failed to update whitelist", "critical");
        return null;
    }
}

window.removeWhitelistEntry = async function(type, value) {
    if (!confirm(`Remove ${value} from whitelist?`)) return;
    const action = await toggleWhitelist(type, value);
    if (action === "removed") showToast("Whitelist", `${value} removed`, "info");
};

export function registerWhitelistListeners() {
    document.getElementById("btn-add-whitelist")?.addEventListener("click", () => {
        const form = document.getElementById("whitelist-form");
        if (form) form.reset();
        const errEl = document.getElementById("wf-error");
        if (errEl) errEl.style.display = "none";
        document.getElementById("whitelist-form-overlay").classList.remove("hidden");
    });

    document.getElementById("whitelist-form-close-btn")?.addEventListener("click", _closeForm);
    document.getElementById("whitelist-form-cancel-btn")?.addEventListener("click", _closeForm);

    document.getElementById("whitelist-form-overlay")?.addEventListener("click", (e) => {
        if (e.target.id === "whitelist-form-overlay") _closeForm();
    });

    document.getElementById("wl-filter-type")?.addEventListener("change", (e) => {
        _filterType = e.target.value;
        renderWhitelistTable();
    });

    document.getElementById("wl-search")?.addEventListener("input", (e) => {
        _searchQuery = e.target.value.trim().toLowerCase();
        renderWhitelistTable();
    });

    document.getElementById("whitelist-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const type   = document.getElementById("wf-type").value;
        const value  = document.getElementById("wf-value").value.trim();
        const errEl  = document.getElementById("wf-error");

        if (!value) {
            if (errEl) { errEl.textContent = "Value is required"; errEl.style.display = "block"; }
            return;
        }

        const action = await toggleWhitelist(type, value);
        if (action) {
            _closeForm();
            showToast("Whitelist", `${value} ${action}`, "info");
        } else {
            if (errEl) { errEl.textContent = "Failed to add entry"; errEl.style.display = "block"; }
        }
    });
}

function _closeForm() {
    document.getElementById("whitelist-form-overlay").classList.add("hidden");
}
