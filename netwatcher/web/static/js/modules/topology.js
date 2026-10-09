import { authFetch, isAuthEnabled } from '../core/api.js';
import { openDeviceDrawer } from '../core/detail-drawer.js';

let graph = null;
let nodes = [];
let selected = -1;
let requestId = 0;
let detailId = 0;
let frame = 0;
let registered = false;
let state = '';
const t = (key, options) => window.i18next.t(`console.topology.${key}`, options);

function setState(key) {
    state = key;
    const el = document.getElementById('topology-state');
    el.textContent = key ? t(key) : '';
    el.hidden = !key;
}

function updateCounts() {
    const el = document.getElementById('topology-counts');
    el.removeAttribute('data-i18n');
    el.textContent = graph ? t('counts', { nodes: graph.node_count ?? graph.graph.nodes.length,
        edges: graph.edge_count ?? graph.graph.links.length }) : t('counts_pending');
}

// Deterministic O(nodes + links) layout; no continuous simulation while the tab is idle.
function draw() {
    frame = 0;
    const canvas = document.getElementById('topology-canvas');
    if (!graph || !canvas.getClientRects().length) return;
    const { width, height } = canvas.getBoundingClientRect();
    if (!width || !height) return;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    const styles = getComputedStyle(document.documentElement);
    const color = name => styles.getPropertyValue(`--${name}`).trim();
    ctx.fillStyle = color('bg');
    ctx.fillRect(0, 0, width, height);
    const columns = Math.max(1, Math.ceil(Math.sqrt(graph.graph.nodes.length * width / height)));
    const rows = Math.max(1, Math.ceil(graph.graph.nodes.length / columns));
    const cellWidth = width / columns, cellHeight = height / rows;
    const radius = Math.max(2, Math.min(12, cellWidth / 5, cellHeight / 5));
    nodes = graph.graph.nodes.map((node, i) => ({ ...node,
        x: (i % columns + .5) * cellWidth, y: (Math.floor(i / columns) + .5) * cellHeight, radius }));
    const byId = new Map(nodes.map(node => [node.id, node]));
    ctx.strokeStyle = color('border');
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (const link of graph.graph.links) {
        const source = byId.get(link.source?.id ?? link.source);
        const target = byId.get(link.target?.id ?? link.target);
        if (!source || !target) continue;
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
    }
    ctx.stroke();
    for (const level of ['critical', 'warning', 'info', 'ok', 'unknown']) {
        ctx.fillStyle = color(level === 'unknown' ? 'text-faint' : level === 'ok' ? 'green' : level);
        ctx.beginPath();
        for (const node of nodes) {
            if (node.level !== level) continue;
            ctx.moveTo(node.x + radius, node.y);
            ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
        }
        ctx.fill();
    }
    ctx.fillStyle = color('text');
    ctx.font = '13px monospace';
    ctx.textAlign = 'center';
    // Dense maps keep labels on the keyboard-selected node to avoid overlapping text.
    nodes.forEach((node, i) => {
        if (cellWidth >= 115 && cellHeight >= 45 || i === selected) {
            ctx.fillText(String(node.id), node.x, Math.min(height - 5, node.y + radius + 17));
            ctx.fillText(t(`severity_${node.level}`), node.x, Math.max(13, node.y - radius - 6));
        }
    });
    if (nodes[selected]) {
        const node = nodes[selected];
        ctx.strokeStyle = color('accent');
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 4, 0, Math.PI * 2);
        ctx.stroke();
    }
}

function scheduleDraw() {
    if (!frame) frame = requestAnimationFrame(draw);
}

export async function loadTopology() {
    if (!isAuthEnabled()) return;
    const id = ++requestId;
    setState('loading');
    try {
        const [response, riskResponse] = await Promise.all([
            authFetch('/api/topology/graph'), authFetch('/api/topology/high-risk')
        ]);
        if (!response.ok || !riskResponse.ok) throw new Error('Topology unavailable');
        const [data, risks] = await Promise.all([response.json(), riskResponse.json()]);
        if (id !== requestId || !isAuthEnabled()) return;
        if (!Array.isArray(data.graph?.nodes) || !Array.isArray(data.graph?.links) || !Array.isArray(risks.devices)) {
            throw new Error('Invalid topology response');
        }
        const riskByIp = new Map(risks.devices.map(device => [device.ip, device.risk_score]));
        graph = { ...data, graph: { ...data.graph, nodes: data.graph.nodes.map(node => {
            const score = riskByIp.get(node.id) ?? node.risk_score;
            const severity = String(node.severity || '').toLowerCase();
            const level = score >= 9 ? 'critical' : score >= 7 ? 'warning'
                : ['critical', 'warning', 'info', 'ok'].includes(severity) ? severity : 'unknown';
            return { ...node, level };
        }) } };
        selected = -1;
        updateCounts();
        const badge = document.getElementById('topology-source-badge');
        badge.removeAttribute('data-i18n');
        // A GET without an explicit live provenance is a point-in-time snapshot.
        badge.textContent = String(data.source || '').toUpperCase() === 'LIVE' ? 'LIVE' : 'SNAPSHOT';
        badge.className = 'badge badge-sev badge-sev-info';
        setState(graph.graph.nodes.length ? '' : 'empty');
        scheduleDraw();
    } catch (_) {
        if (id !== requestId || !isAuthEnabled()) return;
        graph = null;
        nodes = [];
        updateCounts();
        const badge = document.getElementById('topology-source-badge');
        badge.textContent = window.i18next.t('console.source.unchecked');
        badge.className = 'badge badge-sev badge-sev-unknown';
        setState('unavailable');
    }
}

async function showDevice(ip) {
    const id = ++detailId;
    const title = document.getElementById('device-modal-title');
    const body = document.getElementById('device-modal-body');
    title.textContent = ip;
    body.textContent = t('loading');
    openDeviceDrawer();
    try {
        const response = await authFetch(`/api/topology/device/${encodeURIComponent(ip)}`);
        if (!response.ok) throw new Error('Device unavailable');
        const data = await response.json();
        if (id !== detailId || !isAuthEnabled() || title.textContent !== ip) return;
        const pre = document.createElement('pre');
        pre.style.cssText = 'white-space:pre-wrap;overflow-wrap:anywhere';
        pre.textContent = JSON.stringify(data, null, 2);
        body.replaceChildren(pre);
    } catch (_) {
        if (id === detailId && isAuthEnabled() && title.textContent === ip) body.textContent = t('unavailable');
    }
}

export function registerTopologyListeners() {
    if (registered) return;
    registered = true;
    const canvas = document.getElementById('topology-canvas');
    document.getElementById('topology-refresh').addEventListener('click', loadTopology);
    document.getElementById('topology-state').removeAttribute('data-i18n');
    canvas.addEventListener('click', event => {
        const rect = canvas.getBoundingClientRect();
        const x = event.clientX - rect.left, y = event.clientY - rect.top;
        selected = nodes.findIndex(node => Math.hypot(node.x - x, node.y - y) <= node.radius + 4);
        scheduleDraw();
        if (selected >= 0) { canvas.focus(); showDevice(nodes[selected].id); }
    });
    canvas.addEventListener('keydown', event => {
        if (!nodes.length) return;
        if (['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp'].includes(event.key)) {
            event.preventDefault();
            const step = ['ArrowLeft', 'ArrowUp'].includes(event.key) ? -1 : 1;
            selected = (selected + step + nodes.length) % nodes.length;
            canvas.setAttribute('aria-label', `${t('canvas_aria')}: ${nodes[selected].id}, ${t(`severity_${nodes[selected].level}`)}`);
            scheduleDraw();
        } else if (event.key === 'Enter' && nodes[selected]) { event.preventDefault(); showDevice(nodes[selected].id); }
    });
    new ResizeObserver(scheduleDraw).observe(canvas.parentElement);
    new MutationObserver(scheduleDraw).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    window.i18next.on('languageChanged', () => { updateCounts(); setState(state); scheduleDraw(); });
    window.addEventListener('nw-session-ended', () => {
        ++requestId; ++detailId; graph = null; nodes = []; selected = -1;
        canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
        updateCounts(); setState('empty');
        const badge = document.getElementById('topology-source-badge');
        badge.textContent = window.i18next.t('console.source.unchecked');
        badge.className = 'badge badge-sev badge-sev-unknown';
    });
}
