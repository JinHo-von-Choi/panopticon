/**
 * NetWatcher Stats Module (Charts - Complete Version)
 */

import { authFetch } from '../core/api.js';

var trafficChart = null;
var severityChart = null;
var protocolChart = null;
var enginesChart = null;

/**
 * 스타일시트에 정의된 디자인 토큰 값을 읽는다.
 * 차트 색상이 테마 토큰과 어긋나지 않도록 하드코딩을 대신한다.
 */
function token(name, fallback) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name);
    return value.trim() || fallback;
}

function severityColors() {
    return [
        token('--critical', '#ff4757'),
        token('--warning',  '#ffa502'),
        token('--info',     '#3498db'),
    ];
}

function seriesColors() {
    return [
        token('--chart-1', '#3498db'),
        token('--chart-2', '#9b59b6'),
        token('--chart-3', '#e67e22'),
        token('--chart-4', '#1abc9c'),
        token('--chart-5', '#f1c40f'),
    ];
}

export async function loadStats() {
    try {
        const resp = await authFetch("/api/stats/summary");
        if (!resp || !resp.ok) return;
        const data = await resp.json();

        updateCounter("stat-critical", data.severity_counts.CRITICAL);
        updateCounter("stat-warning", data.severity_counts.WARNING);
        updateCounter("stat-info", data.severity_counts.INFO);
        updateCounter("stat-packets", data.total_packets);
        updateCounter("stat-highrisk", data.high_risk_count);

        const visEl = document.getElementById("stat-visibility");
        if (visEl) {
            visEl.textContent = data.hosts_visible || "-";
            const card = document.getElementById("stat-visibility-card");
            if (card) {
                card.className = "stat-card visibility-card " + (data.visibility_level || "none");
            }
        }
        
        // 프로토콜 분포 업데이트를 위해 데이터 전달
        if (data.protocol_counts) renderProtocolChart(data.protocol_counts);
    } catch (e) { console.error("Failed to load stats", e); }
}

function abbreviate(val) {
    if (val >= 1_000_000_000) return (val / 1_000_000_000).toFixed(1).replace(/\.0$/, '') + 'B';
    if (val >= 1_000_000)     return (val / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (val >= 10_000)        return (val / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
    return (val || 0).toLocaleString();
}

function updateCounter(id, val) {
    const el = document.getElementById(id);
    if (el) {
        if (val === null || val === undefined) {
            el.textContent = '-';
            el.removeAttribute('title');
            return;
        }
        const n = val || 0;
        el.textContent = abbreviate(n);
        el.title = n.toLocaleString();
    }
}

/**
 * 실시간 알림 수신 시 심각도 카운터를 즉시 증가시킨다.
 * 30초 주기 폴링을 기다리지 않고 KPI가 스트림을 따라가게 한다.
 */
export function bumpSeverityCounter(severity) {
    const id = {
        CRITICAL: "stat-critical",
        WARNING:  "stat-warning",
        INFO:     "stat-info",
    }[severity];
    if (!id) return;
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.title.replace(/,/g, ""), 10);
    updateCounter(id, (Number.isNaN(current) ? 0 : current) + 1);
}

export async function loadCharts() {
    try {
        const [trafficResp, trendsResp] = await Promise.all([
            authFetch("/api/stats/traffic?minutes=60"),
            authFetch("/api/stats/trends?hours=24")
        ]);

        if (trafficResp.ok) {
            const data = await trafficResp.json();
            renderTrafficChart(data.traffic);
        }
        if (trendsResp.ok) {
            const data = await trendsResp.json();
            renderSeverityChart(data.by_severity);
            renderEnginesChart(data.by_engine);
        }
    } catch (e) { console.error("Failed to load charts", e); }
}

function renderTrafficChart(data) {
    const ctx = document.getElementById('chart-traffic')?.getContext('2d');
    if (!ctx) return;
    if (trafficChart) trafficChart.destroy();
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => new Date(d.timestamp).toLocaleTimeString()),
            datasets: [{
                label: 'Packets/min',
                data: data.map(d => d.total_packets),
                borderColor: token('--info', '#3498db'),
                fill: true,
                tension: 0.4
            }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function renderSeverityChart(data) {
    const ctx = document.getElementById('chart-severity')?.getContext('2d');
    if (!ctx) return;
    if (severityChart) severityChart.destroy();
    const counts = { CRITICAL: 0, WARNING: 0, INFO: 0 };
    Object.keys(data || {}).forEach(sev => { counts[sev] = data[sev]; });
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Warning', 'Info'],
            datasets: [{
                data: [counts.CRITICAL, counts.WARNING, counts.INFO],
                backgroundColor: severityColors()
            }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function renderProtocolChart(data) {
    const ctx = document.getElementById('chart-protocols')?.getContext('2d');
    if (!ctx) return;
    if (protocolChart) protocolChart.destroy();
    const labels = Object.keys(data);
    const values = Object.values(data);
    protocolChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: seriesColors()
            }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function renderEnginesChart(data) {
    const ctx = document.getElementById('chart-engines')?.getContext('2d');
    if (!ctx) return;
    if (enginesChart) enginesChart.destroy();
    const labels = Object.keys(data || {}).slice(0, 10);
    const values = Object.values(data || {}).slice(0, 10);
    enginesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alerts',
                data: values,
                backgroundColor: token('--accent', '#5f6fff')
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false
        }
    });
}
