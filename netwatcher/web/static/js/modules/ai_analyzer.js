/**
 * NetWatcher AI Analyzer Module
 */

import { authFetch, getAuthToken } from '../core/api.js';
import { esc, formatTime, renderPagination } from '../core/utils.js';

let logsPerPage = 50, logsPage = 0, logsTotal = 0, verdictFilter = "";
let epoch = 0, statusSequence = 0, logsSequence = 0, initialized = false;
let statusData = null, statusState = 'loading', logsState = 'empty', logRows = [];
const t = key => window.i18next.t('console.ai_status.' + key);
const session = () => {const currentEpoch = epoch, token = getAuthToken();return () => currentEpoch === epoch && token === getAuthToken();};

const CLI_PROVIDERS = ['copilot','claude','codex','gemini','agent'];
const HTTP_PROVIDERS = ['anthropic','openai_compatible'];

function validStatus(data) {
    const keys = ['enabled','running','state','provider','interval_minutes','lookback_minutes','fp_threshold','max_pct','consecutive_fp','health','credential'];
    if (!validHealth(data?.health)) return false;
    if (![null,'configured','missing'].includes(data?.credential)) return false;
    if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).length !== keys.length
            || keys.some(key => !Object.hasOwn(data,key)) || typeof data.enabled !== 'boolean' || typeof data.running !== 'boolean') return false;
    const numbers = ['interval_minutes','lookback_minutes','fp_threshold','max_pct'];
    if (data.state === 'unconfigured') return data.enabled === false && data.running === false
        && numbers.every(key => data[key] === null) && data.provider === null && data.credential === null
        && data.consecutive_fp && typeof data.consecutive_fp === 'object' && !Array.isArray(data.consecutive_fp) && Object.keys(data.consecutive_fp).length === 0;
    return data.enabled && ['running','stopped'].includes(data.state) && data.running === (data.state === 'running')
        && (CLI_PROVIDERS.includes(data.provider) ? data.credential === null
            : HTTP_PROVIDERS.includes(data.provider) && data.credential !== null)
        && numbers.every(key => Number.isSafeInteger(data[key]) && data[key] > 0 && data[key] <= 2147483647)
        && data.consecutive_fp && !Array.isArray(data.consecutive_fp) && typeof data.consecutive_fp === 'object'
        && Object.keys(data.consecutive_fp).length <= 64
        && Object.entries(data.consecutive_fp).every(([key,value]) => /^[a-z][a-z0-9_]{0,63}$/.test(key) && Number.isSafeInteger(value) && value >= 0 && value <= 2147483647);
}

function validHealth(health) {
    const keys = ['last_attempt_at','last_success_at','consecutive_failures','last_failure'];
    if (!health || typeof health !== 'object' || Array.isArray(health) || Object.keys(health).length !== keys.length
            || keys.some(key => !Object.hasOwn(health,key))) return false;
    const time = value => value === null || (Number.isSafeInteger(value) && value >= 0);
    return time(health.last_attempt_at) && time(health.last_success_at)
        && Number.isSafeInteger(health.consecutive_failures) && health.consecutive_failures >= 0
        && [null,'not_installed','timeout','exit_status','empty_output','error','auth','rate_limited','http_status',
            'invalid_output','credential_missing','budget_exhausted'].includes(health.last_failure);
}

function renderStatus() {
    _setText('ai-state', t(statusState));
    for (const [id,key] of [['ai-provider','provider'],['ai-interval','interval_minutes'],['ai-lookback','lookback_minutes'],['ai-fp-threshold','fp_threshold']]) {
        _setText(id, statusData?.[key] ?? '—');
    }
    // 키 값은 받지도 보여 주지도 않는다. 설정 여부만 표시한다.
    if (statusData?.credential) _setText('ai-provider', `${statusData.provider} · ${t('credential_' + statusData.credential)}`);
    // 작업이 살아 있어도 분석이 계속 실패할 수 있으므로 마지막 성공과 실패 종류를 따로 보여 준다.
    const health = statusData?.health;
    _setText('ai-last-success', !health ? '—'
        : health.last_success_at === null ? t('never') : new Date(health.last_success_at * 1000).toLocaleString());
    _setText('ai-failures', !health ? '—'
        : health.consecutive_failures === 0 ? '0'
        : `${health.consecutive_failures} (${t('failure_' + health.last_failure)})`);
}

export async function initAiAnalyzerTab() {
    const current = session();
    await loadAiAnalyzerStatus();
    if (!current()) return;
    const tab = document.getElementById('tab-btn-ai-analyzer');
    if (tab) tab.style.display = '';
}

export async function loadAiAnalyzerStatus() {
    const current = session(), sequence = ++statusSequence;
    statusData = null; statusState = 'loading'; renderStatus();
    try {
        const resp = await authFetch('/api/ai-analyzer/status');
        if (!resp?.ok) throw new Error('AI status unavailable');
        const data = await resp.json();
        if (!current() || sequence !== statusSequence) return;
        if (!validStatus(data)) throw new Error('Invalid AI status');
        statusData = data; statusState = data.state;
    } catch {
        if (!current() || sequence !== statusSequence) return;
        statusData = null; statusState = 'unknown';
    }
    if (current() && sequence === statusSequence) renderStatus();
}

export async function loadAiLogs(page) {
    const current = session(), sequence = ++logsSequence;
    logsPage = Number.isSafeInteger(page) && page >= 0 ? page : 0;
    logsState = "loading"; logRows = []; renderAiLogs([]);
    document.getElementById("ai-logs-pagination")?.replaceChildren();

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
        limit:  logsPerPage,
        offset: logsPage * logsPerPage,
        engine: engineFilter,
    });
    if (searchTerm) params.set("q", searchTerm);

    try {
        const resp = await authFetch("/api/events?" + params.toString());
        if (!resp || !resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        if (!current() || sequence !== logsSequence) return;
        if (!Number.isSafeInteger(data.total) || data.total < 0 || !Array.isArray(data.events)
                || data.events.length > logsPerPage || data.events.some(event => !event || typeof event !== 'object' || Array.isArray(event))) {
            throw new Error('Invalid AI logs');
        }
        logsTotal = data.total; logRows = data.events; logsState = logRows.length ? 'loaded' : 'empty';
        renderAiLogs(logRows);
        renderPagination(
            document.getElementById("ai-logs-pagination"),
            logsPage, logsTotal, logsPerPage,
            (p) => loadAiLogs(p)
        );
    } catch {
        if (!current() || sequence !== logsSequence) return;
        logsTotal = 0; logRows = []; logsState = 'logs_unknown'; renderAiLogs([]);
        document.getElementById('ai-logs-pagination')?.replaceChildren();
    }
}

function renderAiLogs(events) {
    const tbody = document.getElementById("ai-logs-body");
    if (!tbody) return;

    if (!events.length) {
        tbody.innerHTML =
            `<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">${esc(t(logsState))}</td></tr>`;
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
    if (initialized) return;
    initialized = true;
    window.i18next.on("languageChanged", () => {renderStatus(); renderAiLogs(logRows);});
    const filterEl = document.getElementById("ai-filter-verdict");
    if (filterEl) {
        filterEl.addEventListener("change", () => {
            verdictFilter = filterEl.value;
            loadAiLogs(0);
        });
    }

    document.getElementById("ai-filter-pagesize")?.addEventListener("change", event => {
        logsPerPage = Number(event.target.value) === 100 ? 100 : 50;
        loadAiLogs(0);
    });

    document.getElementById("btn-ai-refresh")?.addEventListener("click", () => {
        loadAiAnalyzerStatus();
        loadAiLogs(logsPage);
    });
}

function _setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

window.addEventListener('nw-session-ended', () => {
    epoch++; statusSequence++; logsSequence++;
    statusData = null; statusState = 'signed_out'; logsState = 'empty'; logRows = [];
    logsTotal = 0; logsPage = 0; verdictFilter = ''; logsPerPage = 50;
    const tab = document.getElementById('tab-btn-ai-analyzer');
    if (tab) tab.style.display = 'none';
    const filter = document.getElementById('ai-filter-verdict');
    if (filter) filter.value = '';
    const pageSize = document.getElementById('ai-filter-pagesize');
    if (pageSize) pageSize.value = '50';
    document.getElementById('ai-logs-pagination')?.replaceChildren();
    renderStatus(); renderAiLogs([]);
});
