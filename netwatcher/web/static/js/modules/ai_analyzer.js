/**
 * NetWatcher AI Analyzer Module
 */

import { authFetch } from '../core/api.js';
import { esc, formatTime, renderPagination } from '../core/utils.js';

const LOGS_PER_PAGE = 25;
let   logsPage      = 0;
let   logsTotal     = 0;
let   verdictFilter = "";

export async function initAiAnalyzerTab() {
    /** /api/ai-analyzer/status 확인 → 활성화 시 탭 표시 */
    try {
        const resp = await authFetch("/api/ai-analyzer/status");
        if (!resp || !resp.ok) return;
        const data = await resp.json();
        if (data && data.enabled) {
            const tabBtn = document.getElementById("tab-btn-ai-analyzer");
            if (tabBtn) tabBtn.style.display = "";
        }
    } catch (e) {
        // 404 또는 비활성화 → 탭 숨김 유지
    }
}

export async function loadAiAnalyzerStatus() {
    try {
        const resp = await authFetch("/api/ai-analyzer/status");
        if (!resp || !resp.ok) return;
        const data = await resp.json();
        _setText("ai-provider",     data.provider         ?? "—");
        _setText("ai-interval",     data.interval_minutes ?? "—");
        _setText("ai-lookback",     data.lookback_minutes ?? "—");
        _setText("ai-fp-threshold", data.fp_threshold     ?? "—");
    } catch (e) { /* 무시 */ }
}

export async function loadAiLogs(page) {
    logsPage = page || 0;

    let engineFilter, searchTerm;
    if (verdictFilter === "adjustment") {
        engineFilter = "ai_adjustment";
        searchTerm   = "";
    } else {
        engineFilter = "ai_analyzer";
        const verdictMap = {
            "CONFIRMED_THREAT": "AI 확인",
            "FALSE_POSITIVE":   "AI 오탐",
            "UNCERTAIN":        "AI 불확실",
        };
        searchTerm = verdictMap[verdictFilter] || "";
    }

    const params = new URLSearchParams({
        limit:  LOGS_PER_PAGE,
        offset: logsPage * LOGS_PER_PAGE,
        engine: engineFilter,
    });
    if (searchTerm) params.set("q", searchTerm);

    try {
        const resp = await authFetch("/api/events?" + params.toString());
        if (!resp || !resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        logsTotal = data.total || 0;
        renderAiLogs(data.events || []);
        renderPagination(
            document.getElementById("ai-logs-pagination"),
            logsPage, logsTotal, LOGS_PER_PAGE,
            (p) => loadAiLogs(p)
        );
    } catch (e) {
        const tbody = document.getElementById("ai-logs-body");
        if (tbody) tbody.innerHTML =
            '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">로그를 불러올 수 없습니다.</td></tr>';
    }
}

function renderAiLogs(events) {
    const tbody = document.getElementById("ai-logs-body");
    if (!tbody) return;

    if (!events.length) {
        tbody.innerHTML =
            '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No AI analyzer logs yet.</td></tr>';
        return;
    }

    let html = "";
    events.forEach(ev => {
        const meta    = ev.metadata || {};
        const verdict = meta.verdict || (ev.engine === "ai_adjustment" ? "ADJUSTMENT" : "—");

        let badgeClass = "";
        if      (verdict === "CONFIRMED_THREAT") badgeClass = "severity-CRITICAL";
        else if (verdict === "FALSE_POSITIVE")   badgeClass = "severity-WARNING";
        else if (verdict === "UNCERTAIN")        badgeClass = "severity-INFO";
        else if (verdict === "ADJUSTMENT")       badgeClass = "severity-INFO";

        let adjustText = "";
        if (meta.adjusted) {
            adjustText = JSON.stringify(meta.adjusted);
        } else if (meta.adjustments && Object.keys(meta.adjustments).length) {
            adjustText = JSON.stringify(meta.adjustments);
        }

        html +=
            `<tr>` +
            `<td>${esc(formatTime(ev.timestamp))}</td>` +
            `<td><span class="severity-badge ${badgeClass}">${esc(verdict)}</span></td>` +
            `<td>${esc(meta.original_engine || meta.engine || ev.engine || "—")}</td>` +
            `<td>${esc(ev.description || "—")}</td>` +
            `<td><code style="font-size:11px">${esc(adjustText || "—")}</code></td>` +
            `<td>${esc(meta.provider || "—")}</td>` +
            `</tr>`;
    });
    tbody.innerHTML = html;
}

export function registerAiAnalyzerListeners() {
    const filterEl = document.getElementById("ai-verdict-filter");
    if (filterEl) {
        filterEl.addEventListener("change", () => {
            verdictFilter = filterEl.value;
            loadAiLogs(0);
        });
    }
}

function _setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}
