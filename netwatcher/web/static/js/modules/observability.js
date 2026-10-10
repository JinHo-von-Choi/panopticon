/** 관측 대시보드. 모든 패널이 같은 기간과 기준 시각(as_of)을 쓴다. */
import { authFetch } from '../core/api.js';

const RANGES = { '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000 };
const REFRESH = { off: 0, '10s': 10000, '30s': 30000, '1m': 60000 };
const STORAGE = 'panopticon.observability';
// 같은 계열 색을 패널마다 다르게 쓰지 않도록 이름별로 고정한다.
const SEVERITY_TOKENS = { CRITICAL: '--critical', WARNING: '--warning', INFO: '--info' };
// 막대를 누르면 사건 목록을 같은 조건으로 연다.
const DRILLDOWN = { alerts_by_engine: 'engine', top_sources: 'search', top_destinations: 'search',
    top_techniques: 'search', eve_top_signatures: 'search' };

let catalog = null, charts = {}, sequence = 0, timer = null, registered = false, lastRange = null;
let settings = { range: '1h', refresh: '30s', hidden: [] };
const t = (key, options) => window.i18next.t(`console.observability.${key}`, options);

function load() {
    try { settings = { ...settings, ...JSON.parse(localStorage.getItem(STORAGE) || '{}') }; } catch { /* 저장소를 못 쓰면 기본값 */ }
    if (!(settings.range in RANGES)) settings.range = '1h';
    if (!(settings.refresh in REFRESH)) settings.refresh = '30s';
    if (!Array.isArray(settings.hidden)) settings.hidden = [];
}

function save() {
    try { localStorage.setItem(STORAGE, JSON.stringify(settings)); } catch { /* 저장 실패는 화면 동작에 영향 없음 */ }
}

function token(name, fallback) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function color(name, index) {
    if (SEVERITY_TOKENS[name]) return token(SEVERITY_TOKENS[name], '#3498db');
    return token(`--chart-${(index % 5) + 1}`, ['#3498db', '#9b59b6', '#e67e22', '#1abc9c', '#f1c40f'][index % 5]);
}

function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function table(headers, rows) {
    const details = element('details', 'obs-table');
    details.append(element('summary', '', t('table')));
    const tableNode = element('table', 'data-table');
    const head = element('tr');
    headers.forEach(name => head.append(element('th', '', name)));
    tableNode.append(head);
    rows.forEach(values => {
        const row = element('tr');
        values.forEach(value => row.append(element('td', '', String(value))));
        tableNode.append(row);
    });
    details.append(tableNode);
    return details;
}

// 사건 목록 기간 필터는 UTC 날짜 단위다. 드릴다운도 그 날짜 범위로 연다.
function utcDate(iso) {
    return new Date(iso).toISOString().slice(0, 10);
}

function openEvents({ engine = '', search = '', from, to }) {
    document.getElementById('filter-engine').value = engine;
    document.getElementById('filter-search').value = search;
    document.getElementById('filter-since').value = utcDate(from);
    document.getElementById('filter-until').value = utcDate(to);
    document.querySelector('.tab[data-tab="events"]')?.click();
}

function renderTimeseries(body, name, result, response) {
    const canvas = element('canvas');
    body.append(canvas);
    const labels = [...new Set(Object.values(result.series).flat().map(point => point[0]))].sort();
    const datasets = Object.entries(result.series).map(([series, points], index) => {
        const values = new Map(points);
        // 버킷에 행이 없으면 값을 만들지 않는다(null). 관측이 없던 구간을 0으로 꾸미지 않는다.
        return { label: series, data: labels.map(label => values.get(label) ?? null),
            borderColor: color(series, index), backgroundColor: color(series, index), spanGaps: false, tension: 0.2 };
    });
    charts[name] = new Chart(canvas.getContext('2d'), {
        type: 'line', data: { labels: labels.map(label => new Date(label).toLocaleString()), datasets },
        options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
            onClick: (_, elements) => {
                if (!elements.length) return;
                const start = labels[elements[0].index];
                const end = new Date(new Date(start).getTime() + response.bucket_seconds * 1000).toISOString();
                openEvents({ from: start, to: end });
            } },
    });
    body.append(table([t('time'), ...datasets.map(set => set.label)],
        labels.map((label, row) => [new Date(label).toLocaleString(), ...datasets.map(set => set.data[row] ?? '—')])));
}

function renderBars(body, name, result, response) {
    const canvas = element('canvas');
    body.append(canvas);
    const rows = result.rows;
    charts[name] = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: { labels: rows.map(row => row.label), datasets: [{ label: t(`unit.${result.unit}`), data: rows.map(row => row.value),
            backgroundColor: rows.map((row, index) => color(row.label, index)) }] },
        options: { indexAxis: result.kind === 'histogram' ? 'x' : 'y', responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            onClick: (_, elements) => {
                const field = DRILLDOWN[name];
                if (!field || !elements.length) return;
                const label = rows[elements[0].index].label;
                openEvents({ [field]: label, from: response.from, to: response.to });
            } },
    });
    body.append(table([t('label'), t(`unit.${result.unit}`)], rows.map(row => [row.label, row.value])));
}

function renderHeatmap(body, result) {
    const cells = new Map(result.cells.map(cell => [`${cell.x}:${cell.y}`, cell.value]));
    const peak = Math.max(1, ...result.cells.map(cell => cell.value));
    const grid = element('div', 'obs-heatmap');
    grid.setAttribute('role', 'img');
    grid.setAttribute('aria-label', t('heatmap_label'));
    const days = window.i18next.t('console.observability.days', { returnObjects: true });
    for (let day = 1; day <= 7; day += 1) {
        grid.append(element('span', 'obs-heatmap-day', Array.isArray(days) ? days[day - 1] : String(day)));
        for (let hour = 0; hour < 24; hour += 1) {
            const value = cells.get(`${day}:${hour}`) || 0;
            const cell = element('span', 'obs-heatmap-cell');
            cell.style.opacity = value ? String(0.15 + 0.85 * (value / peak)) : '0.05';
            cell.title = `${Array.isArray(days) ? days[day - 1] : day} ${hour}:00 — ${value}`;
            grid.append(cell);
        }
    }
    body.append(grid, table([t('day'), t('hour'), t('unit.alerts')],
        result.cells.map(cell => [Array.isArray(days) ? days[cell.x - 1] : cell.x, cell.y, cell.value])));
}

function renderPanel(name, result, response) {
    const card = document.getElementById(`obs-panel-${name}`);
    if (!card) return;
    const body = card.querySelector('.obs-body');
    charts[name]?.destroy();
    delete charts[name];
    body.replaceChildren();
    if (result.state !== 'ok') {
        body.append(element('p', 'empty-state', t(`state.${result.state}`)));
        return;
    }
    const empty = result.kind === 'timeseries' ? !Object.keys(result.series).length
        : result.kind === 'heatmap' ? !result.cells.length : !result.rows.length;
    if (empty) {
        // 조회는 성공했고 기간 안에 기록이 없는 경우다. 조회 실패와 구분해 표시한다.
        body.append(element('p', 'empty-state', t('no_data')));
        return;
    }
    if (result.kind === 'timeseries') renderTimeseries(body, name, result, response);
    else if (result.kind === 'heatmap') renderHeatmap(body, result);
    else renderBars(body, name, result, response);
}

function buildCards() {
    const grid = document.getElementById('obs-grid');
    const picker = document.getElementById('obs-panel-picker');
    grid.replaceChildren();
    picker.replaceChildren();
    for (const [name, info] of Object.entries(catalog.panels)) {
        const label = element('label', 'obs-picker-item');
        const box = element('input');
        box.type = 'checkbox';
        box.checked = !settings.hidden.includes(name);
        box.disabled = !info.supported;
        box.addEventListener('change', () => {
            settings.hidden = box.checked ? settings.hidden.filter(item => item !== name) : [...settings.hidden, name];
            save();
            buildCards();
            refresh();
        });
        label.append(box, document.createTextNode(' ' + t(`panel.${name}`)));
        picker.append(label);
        if (settings.hidden.includes(name)) continue;
        const card = element('section', 'hud-panel obs-card');
        card.id = `obs-panel-${name}`;
        card.append(element('h3', '', t(`panel.${name}`)));
        const body = element('div', 'obs-body');
        body.append(element('p', 'empty-state', info.supported ? t('loading') : t('state.unsupported')));
        card.append(body);
        grid.append(card);
    }
}

async function refresh() {
    if (!catalog) return;
    const names = Object.entries(catalog.panels)
        .filter(([name, info]) => info.supported && !settings.hidden.includes(name)).map(([name]) => name);
    const status = document.getElementById('obs-status');
    if (!names.length) { status.textContent = t('no_panels'); return; }
    const current = ++sequence;
    const to = new Date();
    const from = new Date(to.getTime() - RANGES[settings.range] * 1000);
    const params = new URLSearchParams({ panels: names.join(','), from: from.toISOString(), to: to.toISOString(),
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' });
    status.textContent = t('loading');
    try {
        const response = await authFetch('/api/observability/query?' + params);
        if (!response?.ok) throw new Error(String(response?.status));
        const body = await response.json();
        if (current !== sequence) return;
        lastRange = body;
        for (const [name, result] of Object.entries(body.panels)) renderPanel(name, result, body);
        status.textContent = t('as_of', { time: new Date(body.as_of).toLocaleString(), bucket: body.bucket_seconds });
    } catch {
        if (current !== sequence) return;
        // 이전 그래프는 지우지 않고, 마지막 성공 시각과 함께 실패를 알린다.
        status.textContent = lastRange ? t('failed_since', { time: new Date(lastRange.as_of).toLocaleString() }) : t('failed');
    }
}

function schedule() {
    clearInterval(timer);
    timer = null;
    const interval = REFRESH[settings.refresh];
    if (!interval) return;
    timer = setInterval(() => {
        const active = document.getElementById('tab-observability')?.classList.contains('active');
        if (active && !document.hidden) refresh();
    }, interval);
}

export async function loadObservability() {
    // 패널 구성은 처음 한 번만 만든다. 다시 들어올 때는 갱신만 해서, 실패해도 마지막 그래프가 남는다.
    if (catalog) {
        schedule();
        await refresh();
        return;
    }
    load();
    document.getElementById('obs-range').value = settings.range;
    document.getElementById('obs-refresh').value = settings.refresh;
    try {
        const response = await authFetch('/api/observability/panels');
        if (!response?.ok) throw new Error('panels');
        catalog = await response.json();
    } catch {
        document.getElementById('obs-status').textContent = t('failed');
        return;
    }
    buildCards();
    schedule();
    await refresh();
}

export function registerObservabilityListeners() {
    if (registered) return;
    registered = true;
    document.getElementById('obs-range')?.addEventListener('change', event => {
        settings.range = event.target.value; save(); refresh();
    });
    document.getElementById('obs-refresh')?.addEventListener('change', event => {
        settings.refresh = event.target.value; save(); schedule();
    });
    document.getElementById('obs-reload')?.addEventListener('click', () => refresh());
}
