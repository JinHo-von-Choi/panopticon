/**
 * NetWatcher Blocklist Module (Final Fixed)
 */

import { authFetch } from '../core/api.js';
import { esc, escAttr, formatTime, renderPagination } from '../core/utils.js';

var blPage = 0;
var blTotal = 0;
const BL_PER_PAGE = 50;

export async function loadBlocklist(page) {
    blPage = page;
    const type = document.getElementById("bl-filter-type")?.value || "";
    const source = document.getElementById("bl-filter-source")?.value || "";
    const search = document.getElementById("bl-search")?.value.trim() || "";

    const params = new URLSearchParams();
    params.set("limit", BL_PER_PAGE);
    params.set("offset", page * BL_PER_PAGE);
    if (type) params.set("entry_type", type);
    if (source) params.set("source", source);
    if (search) params.set("search", search);

    try {
        const resp = await authFetch("/api/blocklist?" + params.toString());
        if (!resp || !resp.ok) return;
        const data = await resp.json();
        if (!data || !data.entries) return;
        
        blTotal = data.total || 0;
        const body = document.getElementById("blocklist-body");
        if (!body) return;
        body.innerHTML = "";
        
        data.entries.forEach(b => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="type-tag">${esc(b.type)}</span></td>
                <td><code>${esc(b.value)}</code></td>
                <td>${esc(b.source)}</td>
                <td>${esc(b.notes || "-")}</td>
                <td>${esc(formatTime(b.created_at || new Date().toISOString()))}</td>
                <td><button class="btn-detail" style="background:var(--critical)" data-remove-type="${escAttr(b.type)}" data-remove-value="${escAttr(b.value)}">Delete</button></td>
            `;
            body.appendChild(tr);
            tr.querySelector("[data-remove-type]").addEventListener("click", () => {
                window.removeBlock(b.type, b.value);
            });
        });

        renderSummary(blTotal, data.entries.length, { type, source, search });
        renderPagination(document.getElementById("blocklist-pagination"), blPage, blTotal, BL_PER_PAGE, loadBlocklist);
    } catch (e) { console.error("Failed to load blocklist", e); }
}

/**
 * 목록 응답의 총계로 요약 줄을 채운다.
 * 별도의 통계 엔드포인트를 두지 않고 현재 조회 결과만으로 표현한다.
 */
function renderSummary(total, shown, filters) {
    const el = document.getElementById("bl-stats");
    if (!el) return;

    const active = [];
    if (filters.type)   active.push(`type=${filters.type}`);
    if (filters.source) active.push(`source=${filters.source}`);
    if (filters.search) active.push(`search="${filters.search}"`);

    const scope = active.length
        ? `필터 일치 ${total.toLocaleString()}건 (${active.join(", ")})`
        : `전체 ${total.toLocaleString()}건`;

    el.textContent = `${scope} · 현재 페이지 ${shown.toLocaleString()}건`;
}

window.removeBlock = async function(type, value) {
    if (!confirm(`Remove ${value} from blocklist?`)) return;
    try {
        // Standardized Path Param DELETE: /api/blocklist/ip/1.1.1.1
        const resp = await authFetch(`/api/blocklist/${type}/${value}`, { method: "DELETE" });
        if (resp.ok) loadBlocklist(blPage);
        else alert("Failed to delete entry");
    } catch (e) { alert("Error: " + e.message); }
};
