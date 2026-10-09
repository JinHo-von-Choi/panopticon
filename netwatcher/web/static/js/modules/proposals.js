/** 분리 센서의 제안 작성·검증·승인과 미확정 결과 처리. */
import {authFetch, canAnalyze, canConfigure, getAuthToken} from '../core/api.js';
import {esc, escAttr, formatTime, newRequestId, showToast} from '../core/utils.js';
import {featureEnabled} from '../core/capabilities.js';

const t = (key, options = {}) => window.i18next.t('console.proposal_control.' + key, options);
const tp = key => window.i18next.t('console.proposals.' + key);
const validVersion = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const canonical = value => Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
    : value && typeof value === 'object' ? '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
    : JSON.stringify(value);
let epoch = 0, sequence = 0, offset = 0, nextOffset = null, previousOffsets = [];
let rows = [], baseline = null, loaded = false, busy = false, failed = false, message = 'load_required', initialized = false;
let pendingCount = null;
const session = () => {const e = epoch, token = getAuthToken();return () => e === epoch && token === getAuthToken() && !!token;};
export function proposalStatus() {return {loaded, busy, failed, offset};}

function rowValid(row) {
    return row && Number.isSafeInteger(row.id) && row.id > 0 && row.sensor_id && validVersion(row.source_version)
        && typeof row.sensor_owner === 'string' && typeof row.params === 'object' && row.params !== null && !Array.isArray(row.params)
        && typeof row.before === 'object' && row.before !== null && !Array.isArray(row.before)
        && ['pending','approved','rejected','failed'].includes(row.status);
}

function receipt(data, id, operation, requestId = null) {
    if (!data || data.control_process !== 'separate' || !rowValid(data.proposal) || !validVersion(data.base_version)
        || data.validation_required !== true || data.proposal.id !== id
        || data.status !== (requestId ? 'applied' : 'read') || requestId && data.request_id !== requestId) {
        throw new Error(t('unconfirmed'));
    }
    const expected = {submit:'pending',validation:'pending',approve:'approved',reject:'rejected'}[operation];
    if (expected && data.proposal.status !== expected || operation === 'approve' && data.proposal.applied !== true) {
        throw new Error(t('unconfirmed'));
    }
    return data;
}

async function responseJson(response) {
    if (!response?.ok) throw new Error(t('unconfirmed'));
    return response.json();
}

function render() {
    const body = document.getElementById('proposals-body');
    if (!body) return;
    document.getElementById('proposal-control-toolbar').hidden = false;
    document.getElementById('proposal-create-form').hidden = !canAnalyze();
    document.getElementById('proposal-control-status').textContent = t(message);
    const count = document.getElementById('proposals-count');
    count.textContent = pendingCount === null ? '—' : window.i18next.t('console.proposals.pending_count', {count:pendingCount});
    document.getElementById('proposal-current-threshold').textContent = baseline?.engine?.config?.threshold ?? '—';
    const locked = !loaded || busy || failed;
    document.getElementById('proposal-create-submit').disabled = locked || !baseline || !canAnalyze();
    document.getElementById('proposal-control-refresh').disabled = busy;
    document.getElementById('proposal-page-prev').disabled = busy || previousOffsets.length === 0;
    document.getElementById('proposal-page-next').disabled = busy || nextOffset === null;
    body.innerHTML = rows.length ? rows.map(row => {
        const evidence = row.validation_runs || {};
        const validated = Boolean(evidence.normal_run_id && evidence.attack_run_id);
        const stale = row.engine === 'port_scan' && baseline && row.source_version !== baseline.base_version;
        const pending = row.status === 'pending';
        const disabled = locked ? 'disabled' : '';
        return `<tr data-proposal-id="${escAttr(row.id)}"><td>${esc(row.id)}</td><td><code>${esc(row.engine)}</code></td>
            <td>${esc(Object.entries(row.params).map(([k,v]) => `${k}=${JSON.stringify(v)}`).join(', '))}<div>${esc(row.reason || '')}</div></td>
            <td>${esc(row.source)}</td><td>${esc(tp('status.' + row.status))}${row.applied === true ? ' · ' + esc(tp('applied')) : ''}${pending && stale ? `<div>${esc(t('source_changed'))}</div>` : ''}</td>
            <td>${esc(formatTime(row.created_at))}</td><td>${pending ?
                (canAnalyze() ? `<button class="btn-detail" data-proposal-validate="${escAttr(row.id)}" ${locked || stale ? 'disabled' : ''}>${esc(tp('validate'))}</button>` : '') +
                (canConfigure() ? `<button class="btn-detail" data-proposal-approve="${escAttr(row.id)}" ${locked || stale || !validated ? 'disabled' : ''}>${esc(tp('approve'))}</button>
                 <button class="btn-detail" data-proposal-reject="${escAttr(row.id)}" ${disabled}>${esc(tp('reject'))}</button>` : '') : esc(row.decided_by || '—')}
                 ${validated ? `<div>${esc(tp('feature_comparison'))} #${esc(evidence.normal_run_id)} / #${esc(evidence.attack_run_id)}</div>` : ''}</td></tr>`;
    }).join('') : `<tr><td colspan="7" class="empty-state">${esc(loaded ? tp('empty') : t('load_required'))}</td></tr>`;
    for (const action of ['approve','reject']) {
        body.querySelectorAll(`[data-proposal-${action}]`).forEach(button => button.addEventListener('click', () => decideProposal(Number(button.dataset[action === 'approve' ? 'proposalApprove' : 'proposalReject']), action)));
    }
    body.querySelectorAll('[data-proposal-validate]').forEach(button => button.addEventListener('click', () => {
        if (locked || !canAnalyze()) return;
        const row = rows.find(row => row.id === Number(button.dataset.proposalValidate));
        window.dispatchEvent(new CustomEvent('proposal-validation', {detail:row}));
    }));
}

function initialize() {
    if (initialized) return;
    initialized = true;
    document.getElementById('proposal-control-refresh').addEventListener('click', () => loadRemoteProposals());
    document.getElementById('proposal-page-next').addEventListener('click', () => {
        if (nextOffset === null || busy) return;
        previousOffsets.push(offset); offset = nextOffset; loadRemoteProposals();
    });
    document.getElementById('proposal-page-prev').addEventListener('click', () => {
        if (!previousOffsets.length || busy) return;
        offset = previousOffsets.pop(); loadRemoteProposals();
    });
    document.getElementById('proposal-create-form').addEventListener('submit', event => {event.preventDefault();submitProposal();});
    window.i18next.on('languageChanged', () => {if (featureEnabled('proposals_control_remote') && getAuthToken()) render();});
}

export async function loadRemoteProposals() {
    initialize();
    if (busy) return;
    const current = session(), request = ++sequence;
    loaded = false; message = 'loading'; render();
    try {
        const data = await responseJson(await authFetch(`/api/proposals?limit=50&offset=${offset}`));
        if (!current() || request !== sequence) return;
        let engine = null;
        if (canAnalyze()) engine = await responseJson(await authFetch('/api/engines/port_scan'));
        if (!current() || request !== sequence) return;
        if (data.control_process !== 'separate' || data.status !== 'read' || data.validation_required !== true
            || !Array.isArray(data.proposals) || data.proposals.length > 50 || !data.proposals.every(rowValid)
            || new Set(data.proposals.map(row => row.id)).size !== data.proposals.length
            || !Number.isSafeInteger(data.pending) || data.pending < 0
            || data.next_offset !== null && (!Number.isSafeInteger(data.next_offset) || data.next_offset !== offset + data.proposals.length)
            || engine && (!validVersion(engine.base_version) || engine.engine?.name !== 'port_scan')) throw new Error(t('unconfirmed'));
        rows = data.proposals; pendingCount = data.pending; baseline = engine; nextOffset = data.next_offset;
        loaded = true; failed = false; message = 'ready';
    } catch {
        if (!current() || request !== sequence) return;
        rows = []; pendingCount = null; baseline = null; nextOffset = null; failed = true; message = 'unconfirmed';
    }
    if (current() && request === sequence) render();
}

async function latest(row) {
    const data = receipt(await responseJson(await authFetch('/api/proposals/' + row.id)), row.id, 'read');
    if (canonical(data.proposal) !== canonical(row)) throw new Error(t('changed'));
    return data;
}

async function change(operation, row, values) {
    if (!loaded || busy || failed || !canAnalyze() || ['approve','reject'].includes(operation) && !canConfigure()) return false;
    const current = session();
    busy = true; message = 'processing'; render();
    try {
        const state = operation === 'submit' ? baseline : await latest(row);
        if (!current()) return false;
        const requestId = newRequestId();
        const url = operation === 'submit' ? '/api/proposals' : `/api/proposals/${row.id}/${operation}`;
        const data = await responseJson(await authFetch(url, {method:'POST',body:JSON.stringify({
            request_id:requestId, base_version:state.base_version, ...values})}));
        if (!current()) return false;
        receipt(data, operation === 'submit' ? data.proposal?.id : row.id, operation, requestId);
        if (row && ['engine','params','reason','source','before','sensor_id','sensor_owner','source_version'].some(
            key => canonical(data.proposal[key]) !== canonical(row[key]))) throw new Error(t('unconfirmed'));
        if (operation === 'approve' && (!validVersion(data.engine_state?.base_version)
            || data.engine_state?.engine?.name !== row.engine || Object.entries(row.params).some(
                ([key,value]) => canonical(data.engine_state.engine.config?.[key]) !== canonical(value)))) throw new Error(t('unconfirmed'));
        if (operation === 'submit' && (data.proposal.engine !== values.engine || canonical(data.proposal.params) !== canonical(values.params)
            || data.proposal.source_version !== state.base_version)) throw new Error(t('unconfirmed'));
        if (operation === 'validation' && (data.proposal.validation_runs?.normal_run_id !== values.normal_run_id
            || data.proposal.validation_runs?.attack_run_id !== values.attack_run_id)) throw new Error(t('unconfirmed'));
        busy = false;
        showToast(operation === 'approve' ? tp('applied') : operation === 'reject' ? tp('status.rejected') : t('saved'), '#' + data.proposal.id, 'info');
        await loadRemoteProposals();
        return true;
    } catch {
        if (!current()) return false;
        failed = true; message = 'unconfirmed'; showToast(t('unconfirmed'), '', 'critical');
        return false;
    } finally {
        if (current()) {busy = false;render();}
    }
}

export async function submitProposal() {
    const threshold = Number(document.getElementById('proposal-threshold').value);
    if (!Number.isSafeInteger(threshold) || threshold < 5 || threshold > 100) return false;
    return change('submit', null, {engine:'port_scan',params:{threshold},reason:document.getElementById('proposal-reason').value});
}

export async function decideProposal(id, action) {
    const row = rows.find(row => row.id === id);
    if (!row || !['approve','reject'].includes(action) || !canConfigure() || busy || failed || !loaded) return false;
    if (action === 'approve' && (!row.validation_runs?.normal_run_id || !row.validation_runs?.attack_run_id
        || !window.confirm(tp('confirm')))) return false;
    return change(action, row, {note:''});
}

export async function attachRemoteValidation(proposal, normal, attack) {
    return change('validation', proposal, {normal_run_id:normal,attack_run_id:attack});
}

window.addEventListener('nw-session-ended', () => {
    epoch++; sequence++; rows = []; baseline = null; pendingCount = null; nextOffset = null;
    previousOffsets = []; offset = 0; loaded = false; busy = false; failed = false; message = 'load_required';
    document.getElementById('proposals-body')?.replaceChildren();
    document.getElementById('proposals-count')?.replaceChildren();
    document.getElementById('proposal-create-form')?.reset();
    if (document.getElementById('proposal-create-form')) document.getElementById('proposal-create-form').hidden = true;
});
