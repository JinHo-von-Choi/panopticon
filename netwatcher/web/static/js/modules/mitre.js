import { authFetch, isAuthEnabled } from '../core/api.js';

const TACTICS = [
    'reconnaissance', 'initial-access', 'execution', 'persistence',
    'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
    'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'
];
let registered = false;
let requestId = 0;
let layer = null;
let state = 'pending';
let selected = null;
let origin = null;
let gaps = null;
const el = id => document.getElementById(`mitre-${id}`);
const t = (key, options) => window.i18next.t(`console.mitre.${key}`, options);
const format = value => new Intl.NumberFormat(window.i18next.language).format(value);

function techniques() {
    return (layer?.techniques || []).filter(item => item && typeof item.techniqueID === 'string'
        && /^T\d{4}(?:\.\d{3})?$/.test(item.techniqueID) && item.enabled !== false).map(item => {
        const metadata = Array.isArray(item.metadata) ? item.metadata : [];
        const name = metadata.find(entry => entry?.name === 'Technique name')?.value;
        const rawCount = metadata.find(entry => entry?.name === 'Detection count')?.value;
        // Older layers expose counts only in their generated comment, never in score.
        const legacyCount = /^Detected (\d+) time\(s\)$/.exec(item.comment || '')?.[1];
        const count = rawCount ?? legacyCount;
        const detections = /^\d+$/.test(String(count)) && Number.isSafeInteger(Number(count)) ? Number(count) : null;
        const tactic = typeof item.tactic === 'string' ? item.tactic.toLowerCase().replaceAll('_', '-') : '';
        return { id: item.techniqueID, name: typeof name === 'string' ? name : t('unknown_name'),
            tactic: [...TACTICS, 'resource-development'].includes(tactic) ? tactic : 'unassigned',
            detections, score: Number.isFinite(item.score) ? Math.min(100, Math.max(0, item.score)) : null,
            comment: typeof item.comment === 'string' ? item.comment : '' };
    });
}

function heat(item) {
    if (item.detections === null) return 0;
    return [1, 5, 20, 50, 100].filter(value => item.detections >= value).length;
}

function textNode(tag, className, value) {
    const node = document.createElement(tag);
    node.className = className;
    node.textContent = value;
    return node;
}

function renderDetail() {
    if (!selected) return;
    el('detail-title').textContent = `${selected.id} · ${selected.name}`;
    const body = el('detail-body');
    body.replaceChildren();
    for (const [label, value] of [
        ['tactic', t(`tactics.${selected.tactic}`)],
        ['frequency', selected.detections === null ? t('unknown_count') : format(selected.detections)],
        ['score', selected.score === null ? '—' : `${selected.score}/100`],
        ['comment', selected.comment || '—']
    ]) body.append(textNode('dt', '', t(label)), textNode('dd', '', value));
}

function render() {
    const grid = el('matrix-grid');
    grid.replaceChildren();
    grid.setAttribute('aria-busy', String(state === 'loading'));
    el('export').disabled = !layer;
    const items = techniques();
    const query = el('search').value.trim().toLocaleLowerCase();
    const filtered = items.filter(item => `${item.id} ${item.name} ${item.tactic} ${t(`tactics.${item.tactic}`)}`
        .toLocaleLowerCase().includes(query));
    el('state').textContent = state ? t(state) : t('summary', { shown: filtered.length, total: items.length });
    const tactics = [...TACTICS];
    if (items.some(item => item.tactic === 'resource-development')) tactics.splice(1, 0, 'resource-development');
    if (items.some(item => item.tactic === 'unassigned')) tactics.push('unassigned');
    for (const tactic of tactics) {
        const column = textNode('section', 'mitre-tactic-col', '');
        column.dataset.tactic = tactic;
        const heading = textNode('h4', '', t(`tactics.${tactic}`));
        heading.id = `mitre-tactic-${tactic}`;
        column.setAttribute('aria-labelledby', heading.id);
        column.append(heading);
        const members = filtered.filter(item => item.tactic === tactic)
            .sort((a, b) => (b.detections ?? -1) - (a.detections ?? -1) || a.id.localeCompare(b.id));
        for (const item of members) {
            const card = textNode('button', 'mitre-technique-card', '');
            card.type = 'button';
            card.dataset.technique = item.id;
            card.dataset.heat = heat(item);
            card.setAttribute('aria-haspopup', 'dialog');
            const count = item.detections === null ? t('unknown_count') : t('detections', { count: item.detections, value: format(item.detections) });
            card.append(textNode('strong', 'mitre-technique-id', item.id),
                textNode('span', 'mitre-technique-name', item.name),
                textNode('span', 'mitre-frequency', count));
            card.addEventListener('click', () => {
                if (!isAuthEnabled()) return;
                selected = item; origin = card; renderDetail(); el('detail').showModal();
            });
            column.append(card);
        }
        if (!members.length) column.append(textNode('p', 'mitre-empty', t(query ? 'no_matches' : 'no_detections')));
        grid.append(column);
    }
    renderDetail();
}

function renderGaps() {
    const body = el('gaps');
    body.replaceChildren();
    el('gap-count').textContent = gaps ? `(${gaps.length})` : `(${t('gaps_unavailable')})`;
    for (const gap of gaps || []) {
        const row = document.createElement('tr');
        for (const value of [gap.technique_id, gap.name, gap.tactic]) row.append(textNode('td', '', String(value ?? '')));
        body.append(row);
    }
}

async function loadGaps(hours, id) {
    // 미관측 기법 목록이 실패해도 매트릭스는 그대로 보여 준다.
    try {
        const response = await authFetch(`/api/hunting/coverage?hours=${hours}`);
        if (!response.ok) throw new Error('Coverage unavailable');
        const data = await response.json();
        if (id !== requestId) return;
        gaps = Array.isArray(data.gaps) ? data.gaps : null;
    } catch (_) {
        if (id === requestId) gaps = null;
    }
    if (id === requestId) renderGaps();
}

export async function loadMitreMatrix() {
    if (!isAuthEnabled()) return;
    const id = ++requestId;
    const hours = ['1', '24', '168'].includes(el('hours').value) ? el('hours').value : '24';
    el('detail').close(); selected = null;
    layer = null; state = 'loading'; render();
    loadGaps(hours, id);
    try {
        const response = await authFetch(`/api/hunting/navigator?hours=${hours}`);
        if (!response.ok) throw new Error('Navigator unavailable');
        const data = await response.json();
        if (id !== requestId || !isAuthEnabled()) return;
        if (!data || !Array.isArray(data.techniques)) throw new Error('Invalid Navigator layer');
        layer = data; state = techniques().length ? '' : 'empty'; render();
    } catch (_) {
        if (id !== requestId || !isAuthEnabled()) return;
        layer = null; state = 'unavailable'; render();
    }
}

function exportLayer() {
    if (!layer || !isAuthEnabled()) return;
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = `mitre-layer-${el('hours').value}h.json`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function registerMitreListeners() {
    if (registered) return;
    registered = true;
    el('hours').addEventListener('change', loadMitreMatrix);
    el('refresh').addEventListener('click', loadMitreMatrix);
    el('search').addEventListener('input', render);
    el('export').addEventListener('click', exportLayer);
    el('detail').addEventListener('close', () => {
        origin?.focus(); origin = null; selected = null;
    });
    window.i18next.on('languageChanged', () => { render(); renderGaps(); });
    window.addEventListener('nw-session-ended', () => {
        ++requestId; layer = null; state = 'pending'; selected = null; gaps = null; renderGaps();
        el('detail').close(); el('detail-title').textContent = ''; el('detail-body').replaceChildren();
        el('search').value = ''; render();
    });
    render();
}
