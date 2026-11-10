/**
 * NetWatcher Dashboard Main Entry Point (Stable Production Version)
 */

import { initI18n } from './core/i18n.js';
import { getAuthToken, setAuthToken, setAuthEnabled, setAuthRequired, isAuthEnabled, authFetch, setCurrentRole, setCurrentUserId, handleUnauthorized } from './core/api.js';
import { loadEvents, renderEventRow, exportEvents, exportWeeklyReport, receiveLiveEvent } from './modules/events.js';
import { loadDevices, filterDevices, renderDevicesPage } from './modules/devices.js';
import { loadStats, loadCharts, bumpSeverityCounter } from './modules/stats.js';
import { loadEngines, populateEngineFilter } from './modules/engines.js';
import { loadBlocklist, changeBlocklist, canChangeBlocklist } from './modules/blocklist.js';
import { loadIncidents, registerIncidentListeners } from './modules/incidents.js';
import { loadDefense, registerDefenseListeners } from './modules/defense.js';
import { registerHuntListeners } from './modules/hunting.js';
import { initAiAnalyzerTab, loadAiAnalyzerStatus, loadAiLogs, registerAiAnalyzerListeners } from './modules/ai_analyzer.js';
import { loadWhitelist, registerWhitelistListeners } from './modules/whitelist.js';
import { loadSupportProfile, loadProposals, loadObservation } from './modules/governance.js';
import { closeEventDrawer, closeDeviceDrawer } from './core/detail-drawer.js';
import { initConsole, loadConsoleState } from './modules/console.js';
import { initOnboarding, loadOnboarding } from './modules/onboarding.js';
import { initOverview, loadOverview } from './modules/overview.js';
import { initReplay, loadReplay } from './modules/replay.js';
import { loadCapabilities, featureEnabled } from './core/capabilities.js';
import { initTheme } from './modules/theme.js';
import { loadTopology, registerTopologyListeners } from './modules/topology.js';
import { loadAgents, registerAgentListeners } from './modules/agents.js';
import { loadObservability, registerObservabilityListeners } from './modules/observability.js';
import { loadObservedAssets, registerObservedAssetListeners } from './modules/observed_assets.js';
import { loadCompliance, registerComplianceListeners } from './modules/compliance.js';
import { loadMitreMatrix, registerMitreListeners } from './modules/mitre.js';
import { loadUsers } from './modules/users.js';
import { formatTime, showToast } from './core/utils.js';

var ws = null;
var statsInterval = null;

async function initApp() {
    console.log("App Initializing...");
    setAuthEnabled(true);
    document.getElementById("login-overlay").classList.add("hidden");
    document.getElementById("btn-logout").style.display = getAuthToken() ? "" : "none";
    await loadCapabilities();
    showScreenTitle();

    await Promise.all([
        loadStats(),
        loadEvents(0),
        loadDevices(),
        featureEnabled('engines') ? populateEngineFilter() : Promise.resolve(),
        featureEnabled('ai-analyzer') ? initAiAnalyzerTab() : Promise.resolve()
    ]);

    connectWS();
    loadConsoleState();
    loadOnboarding();
    loadOverview();
    if (!statsInterval) statsInterval = setInterval(() => {
        if (!document.hidden) { loadStats(); loadConsoleState();
            if (document.getElementById("tab-events").classList.contains("active")) loadOverview();
        }
    }, 30000);
    seedFreshness();
    startFreshnessClock();
    openLinkedScreen();
}

/** 현재 화면 이름을 상단 바에 표시한다. */
function showScreenTitle() {
    const title = document.getElementById('console-title');
    if (title) title.textContent = document.querySelector('.tab.active')?.textContent.trim() || '';
}

/** 주소의 해시가 가리키는 화면을 연다. 이 구성에서 숨긴 화면은 열지 않는다. */
function openLinkedScreen() {
    const name = decodeURIComponent(location.hash.slice(1));
    if (!name || name === 'events') return;
    const tab = [...document.querySelectorAll('.tab[data-tab]')].find(item => item.dataset.tab === name);
    if (tab && tab.style.display !== 'none') tab.click();
}

let lastDataAt = null;
let freshnessInterval = null;

/** 실시간 경보를 받은 시각을 기록한다. */
function markDataReceived() {
    lastDataAt = Date.now();
}

/** 첫 화면의 가장 최근 경보 시각으로 시작값을 잡는다. */
function seedFreshness() {
    const latest = Date.parse(document.querySelector('#events-body tr[data-timestamp]')?.dataset.timestamp || '');
    if (!Number.isNaN(latest) && (lastDataAt === null || latest > lastDataAt)) lastDataAt = latest;
}

/** 헤더에 마지막 경보 이후 경과 시간을 표시한다. */
function startFreshnessClock() {
    const el = document.getElementById("clock");
    if (!el || freshnessInterval) return;

    const render = () => {
        const t = (key, options) => window.i18next.t('console.shell.' + key, options);
        if (lastDataAt === null) {
            el.textContent = "";
            el.title = t('no_alert');
            return;
        }
        const seconds = Math.max(0, Math.floor((Date.now() - lastDataAt) / 1000));
        const relative = new Intl.RelativeTimeFormat(window.i18next.language, { style: 'narrow', numeric: 'always' });
        const when = seconds < 60 ? relative.format(-seconds, 'second')
            : seconds < 3600 ? relative.format(-Math.floor(seconds / 60), 'minute')
            : seconds < 86400 ? relative.format(-Math.floor(seconds / 3600), 'hour')
            : relative.format(-Math.floor(seconds / 86400), 'day');
        el.textContent = t('last_alert', { when, interpolation: { escapeValue: false } });
        el.title = formatTime(lastDataAt);
    };

    render();
    freshnessInterval = setInterval(render, 1000);
}

function connectWS() {
    if (ws) ws.close();
    const token = getAuthToken();
    if (!isAuthEnabled()) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/ws/events` + (token ? `?token=${encodeURIComponent(token)}` : "");
    
    ws = new WebSocket(wsUrl);
    const connection = ws;
    let gapRefresh = null;
    ws.onopen = () => document.getElementById("connection-status").className = "status-dot connected";
    ws.onclose = event => {
        if (ws !== connection) return;
        document.getElementById("connection-status").className = "status-dot disconnected";
        if (event.code === 1008) { handleUnauthorized(); return; }
        if (isAuthEnabled()) setTimeout(connectWS, 3000);
    };
    ws.onmessage = (e) => {
        if (ws !== connection || !isAuthEnabled()) return;
        const ev = JSON.parse(e.data);
        if (ev.type === "alert") {
            receiveLiveEvent(ev);
            bumpSeverityCounter(ev.severity);
            markDataReceived();
        } else if (ev.type === 'stream_gap' && !gapRefresh) {
            showToast(window.i18next.t('console.stream_gap_title'),
                window.i18next.t('console.stream_gap_message'), 'WARNING');
            gapRefresh = Promise.allSettled([loadEvents(), loadStats(), loadConsoleState()])
                .finally(() => { gapRefresh = null; });
        }
    };
}

// Global UI Helpers
window.closeModal = closeEventDrawer;
window.closeDeviceModal = closeDeviceDrawer;

function registerListeners() {
    window.addEventListener('nw-session-ended', () => {
        if (ws) { const connection = ws; ws = null; connection.close(); }
        if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
        document.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
        document.getElementById('users-panel')?.replaceChildren();
        document.getElementById('filter-case-mine').checked = false;
        document.getElementById('filter-case-owner').disabled = false;
        document.querySelectorAll('[data-tab="users"]').forEach(button => { button.style.display = 'none'; });
        document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === 'events'));
        document.querySelectorAll('.tab-content').forEach(panel => panel.classList.toggle('active', panel.id === 'tab-events'));
    });
    registerIncidentListeners();
    registerDefenseListeners();
    registerHuntListeners();
    registerTopologyListeners();
    registerAgentListeners();
    registerObservabilityListeners();
    registerObservedAssetListeners();
    registerComplianceListeners();
    registerMitreListeners();

    // Tabs
    document.querySelectorAll(".tab").forEach(tab => {
        tab.addEventListener("click", () => {
            if (!isAuthEnabled() || tab.style.display === 'none') return;
            closeEventDrawer();
            document.querySelector('.user-menu')?.removeAttribute('open');
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            tab.classList.add("active");
            const target = tab.dataset.tab;
            document.getElementById(`tab-${target}`).classList.add("active");
            showScreenTitle();
            history.replaceState(null, '', target === 'events' ? location.pathname + location.search : '#' + target);
            
            if (target === "events")       loadEvents(0);
            if (target === "devices")      { loadDevices(); loadObservedAssets(0); }
            if (target === "users")        loadUsers();
            if (target === "topology")     loadTopology();
            if (target === "agents")       loadAgents();
            if (target === "observability") loadObservability();
            if (target === "compliance")   loadCompliance();
            if (target === "mitre")        loadMitreMatrix();
            if (target === "traffic")      loadCharts();
            if (target === "engines")      loadEngines();
            if (target === "incidents")    loadIncidents();
            if (target === "defense")      loadDefense();
            if (target === "blocklist")    loadBlocklist(0);
            if (target === "whitelist")    loadWhitelist();
            if (target === "ai-analyzer") { loadAiAnalyzerStatus(); loadAiLogs(0); }
            if (target === "governance")    { loadSupportProfile(); loadObservation();
                if (featureEnabled('proposals')) loadProposals();
                loadOnboarding();
                if (featureEnabled('replay')) loadReplay();
            }
        });
    });

    // 심각도 수치를 누르면 그 심각도만 표시한다. 다시 누르면 해제한다.
    const severityFilter = document.getElementById('filter-severity');
    const syncSeverityCards = () => document.querySelectorAll('[data-filter-severity]').forEach(card => {
        card.setAttribute('aria-pressed', String(card.dataset.filterSeverity === severityFilter.value));
    });
    severityFilter?.addEventListener('change', syncSeverityCards);
    document.querySelectorAll('[data-filter-severity]').forEach(card => card.addEventListener('click', () => {
        severityFilter.value = severityFilter.value === card.dataset.filterSeverity ? '' : card.dataset.filterSeverity;
        severityFilter.dispatchEvent(new Event('change'));
    }));

    // J/K로 목록의 이전·다음 사건을 연다.
    document.addEventListener('keydown', event => {
        if (!['j', 'k'].includes(event.key) || event.ctrlKey || event.metaKey || event.altKey) return;
        if (event.target.closest('input, select, textarea, dialog') || !document.getElementById('tab-events').classList.contains('active')) return;
        const rows = [...document.querySelectorAll('#events-body tr[data-event-row]')];
        if (!rows.length) return;
        const current = rows.findIndex(row => row.classList.contains('selected'));
        const next = current < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, current + (event.key === 'j' ? 1 : -1)));
        event.preventDefault();
        rows[next].scrollIntoView({ block: 'nearest' });
        window.showEventDetail(rows[next].dataset.eventRow);
    });

    // 설정 메뉴는 바깥을 누르거나 Esc를 누르면 닫는다.
    const userMenu = document.querySelector('.user-menu');
    document.addEventListener('click', event => { if (!event.target.closest('.user-menu')) userMenu?.removeAttribute('open'); });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') userMenu?.removeAttribute('open'); });

    let rateNoticeAt = 0;
    window.addEventListener('nw-rate-limited', () => {
        if (Date.now() - rateNoticeAt < 15000) return;
        rateNoticeAt = Date.now();
        showToast(window.i18next.t('console.shell.rate_limited_title'), window.i18next.t('console.shell.rate_limited'), 'WARNING');
    });

    // Event Filters & Refresh
    ["filter-severity", "filter-engine", "filter-pagesize", "filter-case-status", "filter-case-unassigned", "filter-case-mine"].forEach(id => {
        document.getElementById(id)?.addEventListener("change", event => {
            if (event.target.checked && id === 'filter-case-mine') document.getElementById('filter-case-unassigned').checked = false;
            if (event.target.checked && id === 'filter-case-unassigned') document.getElementById('filter-case-mine').checked = false;
            document.getElementById('filter-case-owner').disabled = document.getElementById('filter-case-mine').checked;
            loadEvents(0);
        });
    });
    ["filter-search", "filter-since", "filter-until", "filter-case-owner"].forEach(id => {
        document.getElementById(id)?.addEventListener("change", () => loadEvents(0));
    });
    document.getElementById("btn-refresh")?.addEventListener("click", () => { loadEvents(0); loadStats(); });

    document.getElementById("filter-case-unassigned")?.addEventListener("change", event => { document.getElementById("filter-case-owner").disabled = event.target.checked; });
    document.getElementById("btn-weekly-report")?.addEventListener("click", exportWeeklyReport);

    // Export Buttons
    document.getElementById("btn-export-csv")?.addEventListener("click", () => exportEvents('csv'));
    document.getElementById("btn-export-json")?.addEventListener("click", () => exportEvents('json'));
    document.getElementById("btn-export-ecs")?.addEventListener("click", () => exportEvents('ecs'));

    // Device Filters
    document.getElementById("devices-search")?.addEventListener("input", () => { filterDevices(); renderDevicesPage(0); });
    document.getElementById("devices-filter-type")?.addEventListener("change", () => { filterDevices(); renderDevicesPage(0); });
    document.getElementById("devices-filter-known")?.addEventListener("change", () => { filterDevices(); renderDevicesPage(0); });

    // Register Device Modal
    document.getElementById("btn-register-device")?.addEventListener("click", () => {
        const form = document.getElementById("device-form");
        if (form) form.reset();
        const modeEl = document.getElementById("df-mode");
        if (modeEl) modeEl.value = "register";
        const errEl = document.getElementById("df-error");
        if (errEl) errEl.style.display = "none";
        document.getElementById("device-form-title").textContent = window.i18next.t('console.shell.register_device');
        document.getElementById("device-form-overlay").classList.remove("hidden");
    });
    document.getElementById("device-form-close-btn")?.addEventListener("click", () => {
        document.getElementById("device-form-overlay").classList.add("hidden");
    });
    document.getElementById("device-form-cancel-btn")?.addEventListener("click", () => {
        document.getElementById("device-form-overlay").classList.add("hidden");
    });

    // Blocklist Filters & Forms
    document.getElementById("btn-add-blocklist")?.addEventListener("click", () => {
        if (!canChangeBlocklist()) return;
        const error = document.getElementById('bf-error');
        if (error) error.style.display = 'none';
        document.getElementById("blocklist-form-overlay").classList.remove("hidden");
    });
    document.getElementById('bl-refresh')?.addEventListener('click', () => loadBlocklist(0, true));
    document.getElementById("blocklist-form-cancel-btn")?.addEventListener("click", () => {
        document.getElementById("blocklist-form-overlay").classList.add("hidden");
    });
    document.getElementById("bl-filter-type")?.addEventListener("change", () => loadBlocklist(0));
    document.getElementById("bl-filter-source")?.addEventListener("change", () => loadBlocklist(0));
    document.getElementById("bl-search")?.addEventListener("input", () => loadBlocklist(0));

    // Whitelist
    registerWhitelistListeners();

    // AI Analyzer Filters
    registerAiAnalyzerListeners();

    // Global Submission Handler (Delegated)
    document.addEventListener("submit", async (e) => {
        // Device Info Update / Register
        if (e.target.id === "device-form") {
            e.preventDefault();
            const isRegisterOverlay = !!e.target.closest("#device-form-overlay");

            if (isRegisterOverlay) {
                const mac      = document.getElementById("df-mac").value.trim();
                const nickname = document.getElementById("df-nickname").value.trim();
                const errEl    = document.getElementById("df-error");
                if (!mac || !nickname) {
                    if (errEl) { errEl.textContent = window.i18next.t('console.shell.required_device'); errEl.style.display = "block"; }
                    return;
                }
                try {
                    const resp = await authFetch(`/api/devices/${encodeURIComponent(mac)}`, {
                        method: "POST",
                        body: JSON.stringify({ nickname, device_type: "unknown", is_known: true })
                    });
                    if (resp.ok) {
                        document.getElementById("device-form-overlay").classList.add("hidden");
                        loadDevices();
                    } else {
                        const data = await resp.json().catch(() => ({}));
                        if (errEl) { errEl.textContent = data.detail || data.error || window.i18next.t('console.shell.registration_failed'); errEl.style.display = "block"; }
                    }
                } catch (err) { console.error("Register failed", err); }
            } else {
                const macTitle = document.getElementById("device-modal-title").textContent;
                const mac      = macTitle.split(": ").pop().trim();
                const nickname = document.getElementById("dev-nickname").value.trim();
                const type     = document.getElementById("dev-type").value;
                try {
                    const resp = await authFetch(`/api/devices/${mac}`, {
                        method: "POST",
                        body: JSON.stringify({ nickname, device_type: type, is_known: true })
                    });
                    if (resp.ok) {
                        window.closeDeviceModal();
                        loadDevices();
                    }
                } catch (err) { console.error("Update failed", err); }
            }
        }

        // Blocklist Entry Add
        if (e.target.id === "blocklist-form") {
            e.preventDefault();
            const type = document.getElementById("bf-type").value;
            const value = document.getElementById("bf-value").value.trim();
            const notes = document.getElementById("bf-notes").value.trim();
            if (!value) return;
            if (await changeBlocklist(type, value, true, notes)) {
                document.getElementById("blocklist-form-overlay").classList.add("hidden");
                e.target.reset();
            }
        }

        // Login
        if (e.target.id === "login-form") {
            e.preventDefault();
            const user = document.getElementById("login-username").value;
            const pass = document.getElementById("login-password").value;
            const errEl = document.getElementById("login-error");
            try {
                const resp = await fetch("/api/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username: user, password: pass })
                });
                const data = await resp.json();
                if (resp.ok && data.token) {
                    setAuthToken(data.token);
                    const status = await authFetch("/api/auth/status");
                    const identity = status.ok ? await status.json() : {};
                    setCurrentRole(identity.role);
                    setCurrentUserId(identity.user_id);
                    initApp();
                } else {
                    errEl.textContent = data.error || window.i18next.t('console.shell.login_failed');
                }
            } catch (err) { errEl.textContent = window.i18next.t('console.shell.server_failed'); }
        }
    });

    // Global Close (Esc, Overlays)
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") { window.closeModal(); window.closeDeviceModal(); } });
    document.addEventListener("click", (e) => {
        const id = e.target.id;
        if (id === "modal-overlay" || id === "device-modal-overlay" || id === "blocklist-form-overlay") {
            window.closeModal();
            window.closeDeviceModal();
            document.getElementById("blocklist-form-overlay").classList.add("hidden");
        }
        if (e.target.closest(".modal-close") || e.target.closest(".btn-close") || e.target.id === "blocklist-form-cancel-btn") {
            window.closeModal();
            window.closeDeviceModal();
            document.getElementById("blocklist-form-overlay").classList.add("hidden");
        }
    });

    document.getElementById("btn-logout")?.addEventListener("click", () => {
        setAuthToken(null);
        location.reload();
    });
}

// --- Bootstrap ---
window.addEventListener("DOMContentLoaded", () => {
    registerListeners();
    initConsole();
    initTheme();
    initI18n(() => { showScreenTitle(); if (isAuthEnabled()) { loadEvents(); if (featureEnabled('engines')) loadEngines(); loadConsoleState(); } }).then(async () => {
        initOnboarding();
        initReplay();
        initOverview();
        let token = getAuthToken();
        const returnUrl = new URL(window.location.href);
        const oidcResult = returnUrl.searchParams.get('oidc');
        if (oidcResult) {
            returnUrl.searchParams.delete('oidc');
            window.history.replaceState(null, '', returnUrl.pathname + returnUrl.search + returnUrl.hash);
            setAuthToken(null);
            token = null;
            if (oidcResult === 'finish') {
                try {
                    const session = await fetch('/api/auth/oidc/session', { method: 'POST', credentials: 'same-origin', cache: 'no-store' });
                    const result = session.ok ? await session.json() : null;
                    if (result && typeof result.token === 'string') {
                        setAuthToken(result.token);
                        token = result.token;
                    }
                } catch (_) { /* 로그인 화면에서 새 요청으로 다시 시작한다. */ }
            }
            if (!token) {
                const error = document.getElementById('login-error');
                error.textContent = window.i18next.t('login.sso_failed');
                error.style.display = 'block';
            }
        }
        const headers = token ? { "Authorization": `Bearer ${token}` } : {};
        try {
            const resp = await fetch("/api/auth/status", { headers });
            const data = resp.ok ? await resp.json() : null;
            document.getElementById('login-sso')?.classList.toggle('hidden', data?.oidc?.enabled !== true);

            // 인증이 꺼진 배포에서는 로그인 화면을 띄우지 않는다.
            if (data && data.enabled === false) {
                setAuthRequired(false);
                initApp();
            } else if (resp.ok && token) {
                setCurrentRole(data?.role);
                setCurrentUserId(data?.user_id);
                initApp();
            } else {
                if (token) setAuthToken(null);
                document.getElementById("login-overlay").classList.remove("hidden");
            }
        } catch (e) {
            document.getElementById("login-overlay").classList.remove("hidden");
        }
    });
});
