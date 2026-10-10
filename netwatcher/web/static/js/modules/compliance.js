import { authFetch, isAuthEnabled } from '../core/api.js';

let requestId = 0;
let registered = false;
let coverage = null;
let kpis = null;
let state = '';
let gaps = null;
const t = key => window.i18next.t(`console.compliance.${key}`);
const number = value => typeof value === 'number' && Number.isFinite(value);

async function read(url) {
    const response = await authFetch(url);
    if (!response.ok) throw new Error('Compliance unavailable');
    return response.json();
}

function render() {
    document.getElementById('compliance-state').textContent = state ? t(state) : '';
    const grid = document.getElementById('compliance-kpis');
    grid.replaceChildren();
    const gauge = document.getElementById('compliance-coverage');
    const score = coverage && number(coverage.coverage_score)
        ? Math.min(1, Math.max(0, coverage.coverage_score)) * 100 : null;
    document.getElementById('compliance-coverage-score').textContent = score === null ? '—' : `${score.toFixed(1)}%`;
    document.getElementById('compliance-coverage-bar').style.width = `${score ?? 0}%`;
    if (score === null) gauge.removeAttribute('aria-valuenow');
    else gauge.setAttribute('aria-valuenow', String(score));
    renderGaps();
    if (!kpis) return;
    const format = new Intl.NumberFormat(window.i18next.language, { maximumFractionDigits: 2 });
    const cards = [
        ['alert_volume', number(kpis.alert_volume) ? format.format(kpis.alert_volume) : '—'],
        ['alert_interval', number(kpis.mean_alert_interval_seconds) ? `${format.format(kpis.mean_alert_interval_seconds)} ${t('seconds')}` : t('insufficient')],
        // FrameworkMapper's weighted controls score is the engine-based coverage estimate.
        ['engine_coverage', score === null ? '—' : `${score.toFixed(1)}%`]
    ];
    for (const [key, value] of cards) {
        const card = document.createElement('article');
        card.className = 'hud-kpi';
        const label = document.createElement('h4');
        label.className = 'hud-kpi-title';
        label.textContent = t(key);
        const metric = document.createElement('strong');
        metric.className = 'hud-kpi-score';
        metric.textContent = value;
        card.append(label, metric);
        if (key === 'engine_coverage' || key === 'alert_interval') {
            const foot = document.createElement('p');
            foot.className = 'hud-kpi-foot';
            foot.textContent = t(key === 'alert_interval' ? 'alert_interval_hint' : 'coverage_hint');
            card.append(foot);
        }
        grid.append(card);
    }
}

function renderGaps() {
    const body = document.getElementById('compliance-gaps');
    body.replaceChildren();
    document.getElementById('compliance-gap-count').textContent = gaps ? `(${gaps.length})` : '';
    document.getElementById('compliance-report').disabled = !gaps;
    for (const gap of gaps || []) {
        const row = document.createElement('tr');
        for (const value of [gap.id, gap.name, (gap.engines || []).join(', ') || '—']) {
            const cell = document.createElement('td');
            cell.textContent = String(value ?? '');
            row.append(cell);
        }
        body.append(row);
    }
}

async function downloadReport() {
    const framework = document.getElementById('compliance-framework').value;
    if (!framework) return;
    try {
        const response = await authFetch(`/api/compliance/report/${encodeURIComponent(framework)}?fmt=html&days=30`);
        if (!response.ok) throw new Error('Report unavailable');
        // 보고서는 파일로 내려받는다. 콘솔 출처에서 HTML을 열지 않는다.
        const url = URL.createObjectURL(new Blob([await response.text()], { type: 'text/html' }));
        const link = document.createElement('a');
        link.href = url; link.download = `compliance-${framework}.html`;
        document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (_) {
        state = 'report_failed'; render();
    }
}

export async function loadCompliance() {
    if (!isAuthEnabled()) return;
    const id = ++requestId;
    const select = document.getElementById('compliance-framework');
    const requested = select.value;
    state = 'loading';
    coverage = null; kpis = null; gaps = null;
    render();
    try {
        const [frameworks, metrics] = await Promise.all([
            read('/api/compliance/frameworks'), read('/api/compliance/kpis')
        ]);
        if (id !== requestId || !isAuthEnabled()) return;
        if (!Array.isArray(frameworks.frameworks) || !metrics || typeof metrics !== 'object') {
            throw new Error('Invalid compliance response');
        }
        select.replaceChildren();
        for (const framework of frameworks.frameworks) {
            if (typeof framework.id !== 'string') continue;
            select.add(new Option(framework.name || framework.id, framework.id));
        }
        select.disabled = !select.options.length;
        if (!select.options.length) {
            state = 'empty'; render(); return;
        }
        if ([...select.options].some(option => option.value === requested)) select.value = requested;
        const framework = encodeURIComponent(select.value);
        const [data, gapData] = await Promise.all([
            read(`/api/compliance/coverage/${framework}`), read(`/api/compliance/gaps/${framework}`)
        ]);
        if (id !== requestId || !isAuthEnabled()) return;
        if (!number(data.coverage_score) || !Array.isArray(gapData.gaps)) throw new Error('Invalid coverage response');
        coverage = data; kpis = metrics; gaps = gapData.gaps; state = '';
        const badge = document.getElementById('compliance-source-badge');
        badge.removeAttribute('data-i18n');
        badge.textContent = 'SNAPSHOT';
        badge.className = 'badge badge-sev badge-sev-info';
        render();
    } catch (_) {
        if (id !== requestId || !isAuthEnabled()) return;
        coverage = null; kpis = null; gaps = null; state = 'unavailable';
        const badge = document.getElementById('compliance-source-badge');
        badge.removeAttribute('data-i18n');
        badge.textContent = window.i18next.t('console.source.unchecked');
        badge.className = 'badge badge-sev badge-sev-unknown';
        render();
    }
}

export function registerComplianceListeners() {
    if (registered) return;
    registered = true;
    document.getElementById('compliance-state').removeAttribute('data-i18n');
    document.getElementById('compliance-refresh').addEventListener('click', loadCompliance);
    document.getElementById('compliance-framework').addEventListener('change', loadCompliance);
    document.getElementById('compliance-report').addEventListener('click', downloadReport);
    window.i18next.on('languageChanged', render);
    window.addEventListener('nw-session-ended', () => {
        ++requestId; coverage = null; kpis = null; gaps = null; state = 'empty'; render();
        const select = document.getElementById('compliance-framework');
        select.replaceChildren(); select.disabled = true;
        const badge = document.getElementById('compliance-source-badge');
        badge.textContent = window.i18next.t('console.source.unchecked');
        badge.className = 'badge badge-sev badge-sev-unknown';
    });
}
