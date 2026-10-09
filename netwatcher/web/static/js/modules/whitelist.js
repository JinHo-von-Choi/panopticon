/**
 * NetWatcher Whitelist Module
 */

import { esc, showToast, escAttr } from '../core/utils.js';
import { whitelistData, refreshWhitelist, changeWhitelist, containsWhitelist, canChangeWhitelist,
    whitelistStatus, whitelistText } from '../core/whitelist-state.js';
export { whitelistData } from '../core/whitelist-state.js';

let _filterType    = "";
let _searchQuery   = "";

export async function loadWhitelist() {
    return refreshWhitelist(true);
}

function renderWhitelistTable() {
    const state = whitelistStatus();
    const notice = document.getElementById('whitelist-control-status');
    if (notice) notice.textContent = state.message ? whitelistText(state.message) : '';
    const refresh = document.getElementById('whitelist-refresh');
    if (refresh) refresh.disabled = state.busy;
    document.querySelectorAll('[data-whitelist-change], #btn-add-whitelist, #whitelist-form button[type="submit"]').forEach(button => {
        button.disabled = !canChangeWhitelist();
    });
    const tbody = document.getElementById("whitelist-body");
    if (!tbody) return;

    /** 타입별로 항목 평탄화 */
    const rows = [
        ...whitelistData.ips.map(v          => ({ type: "ip",         value: v })),
        ...whitelistData.ip_ranges.map(v     => ({ type: "ip_range",   value: v })),
        ...whitelistData.macs.map(v          => ({ type: "mac",        value: v })),
        ...whitelistData.domains.map(v       => ({ type: "domain",     value: v })),
        ...whitelistData.domain_suffixes.map(v => ({ type: "suffix",  value: v })),
    ];

    /** 필터 적용 */
    const filtered = rows.filter(r => {
        if (_filterType && r.type !== _filterType) return false;
        if (_searchQuery && !r.value.toLowerCase().includes(_searchQuery)) return false;
        return true;
    });

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="3">${esc(whitelistText(state.loaded ? 'empty' : 'load_required'))}</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    filtered.forEach(({ type, value }) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
            `<td><span class="type-tag">${esc(type)}</span></td>` +
            `<td><code>${esc(value)}</code></td>` +
            `<td><button class="btn-detail" style="background:var(--critical)" ` +
                `data-wl-remove data-whitelist-change ${canChangeWhitelist() ? '' : 'disabled'} type="${escAttr(type)}" value="${escAttr(value)}">${esc(whitelistText('remove'))}</button></td>`;
        tr.querySelector("[data-wl-remove]")
            .addEventListener("click", () => window.removeWhitelistEntry(type, value));
        tbody.appendChild(tr);
    });
}

export async function toggleWhitelist(type, value) {
    return changeWhitelist(type, value, !containsWhitelist(type, value));
}

window.removeWhitelistEntry = async function(type, value) {
    if (!canChangeWhitelist() || !confirm(whitelistText('confirm_remove') + ' ' + value)) return;
    const action = await changeWhitelist(type, value, false);
    if (action === "removed") showToast(whitelistText('title'), whitelistText('applied'), "info");
};

export function registerWhitelistListeners() {
    window.addEventListener('nw-whitelist-updated', renderWhitelistTable);
    window.addEventListener('nw-session-ended', () => {
        _closeForm();
        renderWhitelistTable();
    });
    document.getElementById('whitelist-refresh')?.addEventListener('click', loadWhitelist);
    document.getElementById("btn-add-whitelist")?.addEventListener("click", () => {
        if (!canChangeWhitelist()) return;
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
            if (errEl) { errEl.textContent = whitelistText('value_required'); errEl.style.display = "block"; }
            return;
        }

        const action = await changeWhitelist(type, value, true);
        if (action) {
            _closeForm();
            showToast(whitelistText('title'), whitelistText('applied'), "info");
        } else {
            if (errEl) { errEl.textContent = whitelistText('unknown'); errEl.style.display = "block"; }
        }
    });
    renderWhitelistTable();
}

function _closeForm() {
    document.getElementById("whitelist-form-overlay").classList.add("hidden");
}
