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
import { showToast } from './core/utils.js';

var ws = null;
var statsInterval = null;

async function initApp() {
    console.log("App Initializing...");
    setAuthEnabled(true);
    document.getElementById("login-overlay").classList.add("hidden");
    document.getElementById("btn-logout").style.display = getAuthToken() ? "" : "none";
    await loadCapabilities();

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
    startFreshnessClock();
}

let lastDataAt = null;
let freshnessInterval = null;

/** 알림 수신 시각을 기록한다. 파이프라인 생존 여부 표시의 기준점이 된다. */
function markDataReceived() {
    lastDataAt = Date.now();
}

/**
 * 헤더에 마지막 데이터 수신 후 경과 시간을 표시한다.
 * 벽시계보다 캡처 파이프라인이 살아 있는지를 알려주는 편이 유용하다.
 */
function startFreshnessClock() {
    const el = document.getElementById("clock");
    if (!el || freshnessInterval) return;

    const render = () => {
        if (lastDataAt === null) {
            el.textContent = "—";
            el.title = "아직 수신한 알림이 없습니다";
            return;
        }
        const seconds = Math.floor((Date.now() - lastDataAt) / 1000);
        if (seconds < 60)      el.textContent = `${seconds}s ago`;
        else if (seconds < 3600) el.textContent = `${Math.floor(seconds / 60)}m ago`;
        else                   el.textContent = `${Math.floor(seconds / 3600)}h ago`;
        el.title = `마지막 알림 수신: ${new Date(lastDataAt).toLocaleString()}`;
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
            if (!isAuthEnabled()) return;
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            tab.classList.add("active");
            const target = tab.dataset.tab;
            document.getElementById(`tab-${target}`).classList.add("active");
            
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
        document.getElementById("device-form-title").textContent = "Register Device";
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
                    if (errEl) { errEl.textContent = "MAC Address and Nickname are required"; errEl.style.display = "block"; }
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
                        if (errEl) { errEl.textContent = data.detail || data.error || "Registration failed"; errEl.style.display = "block"; }
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
                    errEl.textContent = data.error || "Login failed";
                }
            } catch (err) { errEl.textContent = "Server connection failed"; }
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
    initI18n(() => { if (isAuthEnabled()) { loadEvents(); loadEngines(); loadConsoleState(); } }).then(async () => {
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
