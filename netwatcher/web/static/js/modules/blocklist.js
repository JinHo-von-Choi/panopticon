/**
 * NetWatcher Blocklist Module (Final Fixed)
 */

import { authFetch } from '../core/api.js';
import { esc, formatTime, renderPagination } from '../core/utils.js';

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
                <td><button class="btn-detail" style="background:var(--critical)" onclick="window.removeBlock('${b.type}', '${b.value}')">Delete</button></td>
            `;
            body.appendChild(tr);
        });

        renderPagination(document.getElementById("blocklist-pagination"), blPage, blTotal, BL_PER_PAGE, loadBlocklist);
    } catch (e) { console.error("Failed to load blocklist", e); }
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
