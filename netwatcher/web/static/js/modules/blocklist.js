/** 센서의 위협 지표 목록과 명시적인 사용자 항목 변경. */
import { authFetch, canConfigure, getAuthToken } from '../core/api.js';
import { esc, escAttr, renderPagination, newRequestId, formatTime } from '../core/utils.js';
import { featureEnabled } from '../core/capabilities.js';

const size = 50;
let page = 0, sequence = 0, epoch = 0;
let loaded = false, busy = false, changing = false, failed = false;
let message = 'load_required';
const text = key => window.i18next.t('console.blocklist_control.' + key);
const versionValid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function blocklistStatus() { return {loaded, busy, failed, message}; }
export function canChangeBlocklist() { return featureEnabled('blocklist') && canConfigure() && loaded && !busy && !failed; }

function sync() {
    const status = document.getElementById('bl-status');
    if (status) status.textContent = text(message) + (canConfigure() ? '' : ' · ' + text('readonly'));
    document.querySelectorAll('#btn-add-blocklist, #blocklist-form button[type="submit"], [data-remove-type]').forEach(button => {
        button.disabled = !canChangeBlocklist();
    });
    document.querySelectorAll('#bf-type, #bf-value, #bf-notes').forEach(input => { input.disabled = !canChangeBlocklist(); });
    document.querySelectorAll('#bl-filter-type, #bl-filter-source, #bl-search').forEach(input => { input.disabled = changing; });
    document.querySelectorAll('[data-bl-details]').forEach(button => { button.disabled = !loaded || busy || failed; });
    const refresh = document.getElementById('bl-refresh');
    if (refresh) refresh.disabled = busy;
}

function validatePage(data) {
    if (!data || !Array.isArray(data.entries) || data.entries.length > size || !Number.isSafeInteger(data.total) || data.total < data.entries.length) {
        throw Error('Invalid indicator page');
    }
    for (const entry of data.entries) {
        if (!entry || !['ip', 'domain'].includes(entry.type) || typeof entry.value !== 'string' || !entry.value || entry.value.length > 253 ||
            typeof entry.source !== 'string' || !entry.source || entry.source.length > 128) throw Error('Invalid indicator');
    }
    if (featureEnabled('blocklist_control_remote') && data.control_process !== 'separate') throw Error('Sensor page unavailable');
    return data;
}

function render(data, filters) {
    const body = document.getElementById('blocklist-body');
    if (!body) return;
    body.innerHTML = '';
    for (const entry of data.entries) {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${esc(text(entry.type))}</td><td><code>${esc(entry.value)}</code></td><td>${esc(entry.source === 'Custom' ? text('custom') : entry.source)}</td><td>${entry.source === 'Custom' ? `<button class="btn-detail" data-bl-details>${esc(text('details'))}</button> <button class="btn-detail" data-remove-type="${escAttr(entry.type)}" data-remove-value="${escAttr(entry.value)}">${esc(text('remove'))}</button>` : '—'}</td>`;
        row.querySelector('[data-bl-details]')?.addEventListener('click', () => showDetails(entry.type, entry.value));
        row.querySelector('[data-remove-type]')?.addEventListener('click', () => window.removeBlock(entry.type, entry.value));
        body.appendChild(row);
    }
    const summary = document.getElementById('bl-stats');
    if (summary) summary.textContent = `${text(filters.type || filters.source || filters.search ? 'filtered' : 'total')} ${data.total.toLocaleString()} · ${text('shown')} ${data.entries.length.toLocaleString()}`;
    renderPagination(document.getElementById('blocklist-pagination'), page, data.total, size, next => loadBlocklist(next));
}

export async function loadBlocklist(next = 0, manual = false) {
    if (changing || (failed && !manual) || !featureEnabled('blocklist')) return false;
    const attempt = ++sequence, currentEpoch = epoch, token = getAuthToken();
    const current = () => attempt === sequence && epoch === currentEpoch && token === getAuthToken();
    const filters = {type:document.getElementById('bl-filter-type')?.value || '', source:document.getElementById('bl-filter-source')?.value || '', search:document.getElementById('bl-search')?.value.trim() || ''};
    const params = new URLSearchParams({limit:size, offset:next * size});
    if (filters.type) params.set('entry_type', filters.type);
    if (filters.source) params.set('source', filters.source);
    if (filters.search) params.set('search', filters.search);
    document.getElementById('bl-details')?.replaceChildren();
    busy = true; loaded = false; message = 'loading'; sync();
    try {
        const response = await authFetch('/api/blocklist?' + params);
        if (!response?.ok) throw Error('Indicator read unavailable');
        const data = validatePage(await response.json());
        if (!current()) return false;
        page = next; failed = false; loaded = true; message = 'ready'; render(data, filters);
        return true;
    } catch {
        if (!current()) return false;
        failed = true; loaded = false; message = 'read_failed';
        document.getElementById('blocklist-body')?.replaceChildren();
        document.getElementById('blocklist-pagination')?.replaceChildren();
        const summary = document.getElementById('bl-stats');
        if (summary) summary.textContent = '';
        return false;
    } finally { if (current()) { busy = false; sync(); } }
}


export async function changeBlocklist(type, value, present, notes = '') {
    if (!canChangeBlocklist() || !['ip','domain'].includes(type) || !value || typeof present !== 'boolean') return false;
    const currentEpoch = epoch, token = getAuthToken();
    const current = () => epoch === currentEpoch && token === getAuthToken();
    ++sequence; changing = busy = true; message = 'pending'; sync();
    try {
        let url = `/api/blocklist/${type}`, method = present ? 'POST' : 'DELETE';
        let body = {value, notes}, requestId = null, target = value;
        if (featureEnabled('blocklist_control_remote')) {
            const response = await authFetch('/api/blocklist/entry?' + new URLSearchParams({entry_type:type, value}));
            if (!current()) return false;
            if (!response?.ok) throw Error('Indicator snapshot unavailable');
            const snapshot = await response.json();
            if (!current()) return false;
            if (snapshot.status !== 'read' || !versionValid(snapshot.base_version) || snapshot.entry?.type !== type ||
                typeof snapshot.entry.value !== 'string' || !snapshot.entry.value || snapshot.entry.value.length > 253 || typeof snapshot.entry.present !== 'boolean') throw Error('Invalid indicator snapshot');
            target = snapshot.entry.value; requestId = newRequestId();
            url = '/api/blocklist/entry'; method = 'PUT';
            body = {request_id:requestId, base_version:snapshot.base_version, type, value:target, present, notes};
        }
        const response = await authFetch(url, {method, body:JSON.stringify(body)});
        if (!current()) return false;
        if (!response?.ok) {
            const error = Error('Indicator change unconfirmed'); error.rejected = response && response.status < 500; throw error;
        }
        const result = await response.json();
        if (!current()) return false;
        if (requestId ? result.status !== 'applied' || result.request_id !== requestId || !versionValid(result.base_version) || result.entry?.type !== type || result.entry.value !== target || result.entry.present !== present : result.ok !== true) {
            throw Error('Indicator receipt unavailable');
        }
        changing = busy = false;
        await loadBlocklist(page, true);
        return current();
    } catch (error) {
        if (!current()) return false;
        failed = true; loaded = false; message = error.rejected ? 'rejected' : 'unknown';
        const hint = document.getElementById('bf-error');
        if (hint) { hint.textContent = text(message); hint.style.display = 'block'; }
        return false;
    } finally { if (current()) { if (changing) changing = busy = false; sync(); } }
}

async function showDetails(type, value) {
    if (!loaded || busy || failed) return;
    const currentEpoch = epoch, token = getAuthToken(), attempt = sequence;
    const current = () => epoch === currentEpoch && token === getAuthToken() && attempt === sequence;
    const panel = document.getElementById('bl-details');
    if (panel) panel.textContent = text('loading');
    try {
        const response = await authFetch('/api/blocklist/entry?' + new URLSearchParams({entry_type:type, value}));
        if (!response?.ok) throw Error('Indicator details unavailable');
        const result = await response.json();
        if (!current()) return;
        const entry = result.entry;
        if (entry?.type !== type || entry.value !== value || entry.present !== true || typeof entry.notes !== 'string' ||
            entry.notes.length > 2048 || typeof entry.notes_truncated !== 'boolean' || typeof entry.created_at !== 'string' ||
            !Number.isFinite(Date.parse(entry.created_at))) throw Error('Invalid indicator details');
        if (panel) panel.textContent = `${entry.value} · ${text('registered')} ${formatTime(entry.created_at)} · ${text('notes')}: ${entry.notes || text('no_notes')}${entry.notes_truncated ? ' · ' + text('truncated') : ''}`;
    } catch {
        if (!current()) return;
        if (panel) panel.textContent = text('read_failed');
        failed = true; loaded = false; message = 'read_failed'; sync();
    }
}

window.removeBlock = async (type, value) => {
    if (!canChangeBlocklist() || !confirm(text('confirm_remove') + ' ' + value)) return;
    await changeBlocklist(type, value, false);
};

window.addEventListener('nw-session-ended', () => {
    document.getElementById('bl-details')?.replaceChildren();
    ++epoch; ++sequence; loaded = busy = changing = failed = false; message = 'load_required';
    document.getElementById('blocklist-body')?.replaceChildren();
    document.getElementById('blocklist-pagination')?.replaceChildren();
    const summary = document.getElementById('bl-stats'); if (summary) summary.textContent = '';
    document.getElementById('blocklist-form')?.reset();
    document.getElementById('blocklist-form-overlay')?.classList.add('hidden');
    sync();
});
