/** 호스트 에이전트 목록·자원·연결 이벤트 조회. 자격 증명 필드는 서버가 돌려주지 않는다. */
import { authFetch } from '../core/api.js';

// 하트비트 간격(5초)의 6배 동안 소식이 없으면 끊긴 것으로 본다.
const OFFLINE_AFTER_SECONDS = 30;
let listSequence = 0, detailSequence = 0, selected = null, nextBeforeSeq = null, registered = false;
const t = (key, options) => window.i18next.t(`console.agents.${key}`, options);

function cell(row, value) {
    const td = document.createElement('td');
    td.textContent = value ?? '—';
    row.append(td);
    return td;
}

function time(seconds) {
    return Number.isFinite(seconds) ? new Date(seconds * 1000).toLocaleString() : '—';
}

function bytes(value) {
    if (!Number.isFinite(value)) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
    return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function renderAgents(body) {
    const tbody = document.getElementById('agents-body');
    tbody.replaceChildren();
    for (const agent of body.agents) {
        const row = document.createElement('tr');
        row.tabIndex = 0;
        row.className = 'clickable';
        const online = Number.isFinite(agent.last_seen) && body.now - agent.last_seen <= OFFLINE_AFTER_SECONDS;
        const resources = agent.resources || {};
        cell(row, `${agent.hostname} (${agent.platform})`);
        cell(row, agent.last_seen === null ? t('never_seen') : t(online ? 'online' : 'offline'));
        cell(row, time(agent.last_seen));
        cell(row, Number.isFinite(agent.latency_ms) ? agent.latency_ms.toFixed(1) : '—');
        cell(row, Number.isFinite(resources.load_1) ? resources.load_1.toFixed(2) : '—');
        cell(row, Number.isFinite(resources.memory_available_bytes)
            ? `${bytes(resources.memory_available_bytes)} / ${bytes(resources.memory_total_bytes)}` : '—');
        cell(row, bytes(resources.agent_rss_bytes));
        const open = () => openAgent(agent);
        row.addEventListener('click', open);
        row.addEventListener('keydown', event => { if (event.key === 'Enter') open(); });
        tbody.append(row);
    }
    document.getElementById('agents-summary').textContent = t('summary', { total: body.total, shown: body.agents.length });
}

export async function loadAgents() {
    const sequence = ++listSequence;
    const summary = document.getElementById('agents-summary');
    summary.textContent = t('loading');
    try {
        const response = await authFetch('/api/agents?limit=200');
        if (!response?.ok) throw new Error('agents unavailable');
        const body = await response.json();
        if (sequence !== listSequence) return;
        renderAgents(body);
    } catch {
        if (sequence !== listSequence) return;
        // 조회 실패를 에이전트 0대로 보이게 하지 않는다.
        document.getElementById('agents-body').replaceChildren();
        summary.textContent = t('unavailable');
    }
}

function renderEvents(batches, append) {
    const tbody = document.getElementById('agents-events');
    if (!append) tbody.replaceChildren();
    for (const batch of batches) {
        for (const event of batch.events) {
            const row = document.createElement('tr');
            cell(row, time(event.observed_at));
            cell(row, event.kind);
            cell(row, event.local_address);
            cell(row, event.remote_address);
            cell(row, event.state);
            tbody.append(row);
        }
    }
}

async function loadEvents(append) {
    const sequence = ++detailSequence;
    const params = new URLSearchParams({ limit: '20' });
    if (append && nextBeforeSeq !== null) params.set('before_seq', String(nextBeforeSeq));
    const more = document.getElementById('agents-more');
    try {
        const response = await authFetch(`/api/agents/${encodeURIComponent(selected.agent_uuid)}/events?${params}`);
        if (!response?.ok) throw new Error('events unavailable');
        const body = await response.json();
        if (sequence !== detailSequence) return;
        renderEvents(body.batches, append);
        nextBeforeSeq = body.next_before_seq;
        more.hidden = nextBeforeSeq === null;
    } catch {
        if (sequence !== detailSequence) return;
        more.hidden = true;
        document.getElementById('agents-detail-title').textContent = t('events_unavailable');
    }
}

function openAgent(agent) {
    selected = agent;
    nextBeforeSeq = null;
    document.getElementById('agents-detail').hidden = false;
    document.getElementById('agents-detail-title').textContent = t('events_title', { host: agent.hostname });
    loadEvents(false);
}

export function registerAgentListeners() {
    if (registered) return;
    registered = true;
    document.getElementById('agents-refresh')?.addEventListener('click', () => loadAgents());
    document.getElementById('agents-more')?.addEventListener('click', () => loadEvents(true));
}
