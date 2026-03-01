/**
 * NetWatcher Dashboard Main Entry Point (Stable Production Version)
 */

import { initI18n } from './core/i18n.js';
import { getAuthToken, setAuthToken, setAuthEnabled, isAuthEnabled, authFetch } from './core/api.js';
import { loadEvents, renderEventRow, exportEvents } from './modules/events.js';
import { loadDevices, filterDevices, renderDevicesPage } from './modules/devices.js';
import { loadStats, loadCharts } from './modules/stats.js';
import { loadEngines, populateEngineFilter } from './modules/engines.js';
import { loadBlocklist } from './modules/blocklist.js';
import { initAiAnalyzerTab, loadAiAnalyzerStatus, loadAiLogs, registerAiAnalyzerListeners } from './modules/ai_analyzer.js';
import { loadWhitelist, registerWhitelistListeners } from './modules/whitelist.js';

var ws = null;
var statsInterval = null;

async function initApp() {
    console.log("App Initializing...");
    setAuthEnabled(true);
    document.getElementById("login-overlay").classList.add("hidden");
    document.getElementById("btn-logout").style.display = "";

    await Promise.all([
        loadStats(),
        loadEvents(0),
        loadDevices(),
        populateEngineFilter(),
        initAiAnalyzerTab()
    ]);

    connectWS();
    if (!statsInterval) statsInterval = setInterval(loadStats, 30000);
}

function connectWS() {
    if (ws) ws.close();
    const token = getAuthToken();
    if (!token) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/ws/events?token=${token}`;
    
    ws = new WebSocket(wsUrl);
    ws.onopen = () => document.getElementById("connection-status").className = "status-dot connected";
    ws.onclose = () => {
        document.getElementById("connection-status").className = "status-dot disconnected";
        if (isAuthEnabled()) setTimeout(connectWS, 3000);
    };
    ws.onmessage = (e) => {
        const ev = JSON.parse(e.data);
        if (ev.type === "alert") {
            const body = document.getElementById("events-body");
            if (body) {
                const row = renderEventRow(ev);
                body.insertBefore(row, body.firstChild);
            }
        }
    };
}

// Global UI Helpers
window.closeModal = function() { document.getElementById("modal-overlay").classList.add("hidden"); };
window.closeDeviceModal = function() { document.getElementById("device-modal-overlay").classList.add("hidden"); };

function registerListeners() {
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
            if (target === "devices")      loadDevices();
            if (target === "traffic")      loadCharts();
            if (target === "engines")      loadEngines();
            if (target === "blocklist")    loadBlocklist(0);
            if (target === "whitelist")    loadWhitelist();
            if (target === "ai-analyzer") { loadAiAnalyzerStatus(); loadAiLogs(0); }
        });
    });

    // Event Filters & Refresh
    ["filter-severity", "filter-engine", "filter-pagesize"].forEach(id => {
        document.getElementById(id)?.addEventListener("change", () => loadEvents(0));
    });
    ["filter-search", "filter-since", "filter-until"].forEach(id => {
        document.getElementById(id)?.addEventListener("change", () => loadEvents(0));
    });
    document.getElementById("btn-refresh")?.addEventListener("click", () => { loadEvents(0); loadStats(); });

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
        document.getElementById("blocklist-form-overlay").classList.remove("hidden");
    });
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
            const errEl = document.getElementById("bf-error");

            if (!value) return;
            try {
                const resp = await authFetch(`/api/blocklist/${type}`, {
                    method: "POST",
                    body: JSON.stringify({ [type]: value, notes: notes })
                });
                if (resp.ok) {
                    document.getElementById("blocklist-form-overlay").classList.add("hidden");
                    e.target.reset();
                    loadBlocklist(0);
                } else {
                    const data = await resp.json();
                    if (errEl) {
                        errEl.textContent = data.error || "Failed to add";
                        errEl.style.display = "block";
                    }
                }
            } catch (err) { console.error("Add failed", err); }
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
    initI18n(() => { if (isAuthEnabled()) { loadEvents(0); loadEngines(); } }).then(async () => {
        const token = getAuthToken();
        if (token) {
            try {
                const resp = await fetch("/api/auth/status", { headers: { "Authorization": `Bearer ${token}` } });
                if (resp.ok) initApp();
                else { setAuthToken(null); document.getElementById("login-overlay").classList.remove("hidden"); }
            } catch (e) { document.getElementById("login-overlay").classList.remove("hidden"); }
        } else {
            document.getElementById("login-overlay").classList.remove("hidden");
        }
    });
});
