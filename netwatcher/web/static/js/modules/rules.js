/** 시그니처 규칙 조회와 명시적인 상태 변경. */
import {authFetch, canConfigure, getAuthToken} from '../core/api.js';
import {esc, escAttr, newRequestId, renderPagination} from '../core/utils.js';
import {featureEnabled} from '../core/capabilities.js';

const size = 50;
const text = key => window.i18next.t('console.rule_control.' + key);
const versionValid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
let epoch = 0, sequence = 0, page = 0;
let loaded = false, busy = false, changing = false, failed = false;
let message = 'load_required', version = null, rules = [];
export function rulesStatus() {return {loaded, busy, failed, message};}
const remote = () => featureEnabled('rules_control_remote');
const editable = () => featureEnabled('rules') && canConfigure() && loaded && !busy && !failed;

function sync() {
    const status = document.getElementById('rules-status');
    if (status) status.textContent = text(message) + (canConfigure() ? '' : ' · ' + text('readonly'));
    document.querySelectorAll('[data-rule-toggle], #btn-rules-reload').forEach(button => {button.disabled = !editable();});
    const refresh = document.getElementById('btn-rules-refresh');
    if (refresh) refresh.disabled = busy;
}

function validateRule(rule) {
    if (!rule || typeof rule.id !== 'string' || !rule.id || rule.id.length > 128 || typeof rule.name !== 'string'
            || rule.name.length > 512 || !['INFO', 'WARNING', 'CRITICAL'].includes(rule.severity)
            || typeof rule.enabled !== 'boolean' || (rule.protocol !== null && typeof rule.protocol !== 'string')) {
        throw Error('Invalid rule');
    }
}

function render(data) {
    const body = document.getElementById('rules-body');
    if (!body) return;
    body.innerHTML = rules.length ? rules.map(rule => `<tr>
        <td class="mono"><code>${esc(rule.id)}</code></td><td>${esc(rule.name)}</td>
        <td><span class="badge badge-${escAttr(rule.severity.toLowerCase())}">${esc(rule.severity)}</span></td>
        <td>${esc(rule.protocol || text('any_protocol'))}</td><td><label class="toggle-inline">
        <input type="checkbox" data-rule-toggle="${escAttr(rule.id)}" ${rule.enabled ? 'checked' : ''}
        aria-label="${escAttr(rule.name + ' · ' + text('toggle'))}"><span>${esc(text(rule.enabled ? 'enabled' : 'disabled'))}</span></label></td>
        </tr>`).join('') : `<tr><td colspan="5" class="empty-state">${esc(text('empty'))}</td></tr>`;
    body.querySelectorAll('[data-rule-toggle]').forEach(input => input.addEventListener('change', () => changeRule(input.dataset.ruleToggle, input.checked)));
    const count = document.getElementById('rules-count');
    if (count) count.textContent = data.total;
    renderPagination(document.getElementById('rules-pagination'), page, data.total, size, next => loadRules(next, true));
    sync();
}

export async function loadRules(next = page, manual = false) {
    if (changing || (failed && !manual) || !featureEnabled('rules')) return false;
    const token = getAuthToken(), session = epoch, attempt = ++sequence;
    const current = () => token === getAuthToken() && session === epoch && attempt === sequence;
    loaded = false; busy = true; message = 'loading'; sync();
    try {
        const response = await authFetch(`/api/rules?limit=${size}&offset=${next * size}`);
        if (!current()) return false;
        if (!response?.ok) throw Error('Rule list unavailable');
        const data = await response.json();
        if (!current()) return false;
        if (!Array.isArray(data.rules) || !Number.isSafeInteger(data.total) || data.total < data.rules.length
                || (remote() && (data.rules.length > size || data.control_process !== 'separate' || !versionValid(data.base_version)))) {
            throw Error('Invalid rule list');
        }
        data.rules.forEach(validateRule);
        if (new Set(data.rules.map(rule => rule.id)).size !== data.rules.length) throw Error('Duplicate rules');
        rules = remote() ? data.rules : data.rules.slice(next * size, (next + 1) * size);
        version = remote() ? data.base_version : null;
        page = next; loaded = true; failed = false; message = 'ready';
        render(data);
        return true;
    } catch (error) {
        if (!current()) return false;
        loaded = false; failed = true; message = 'read_failed'; version = null; rules = [];
        const body = document.getElementById('rules-body');
        if (body) body.replaceChildren();
        const count = document.getElementById('rules-count');
        if (count) count.textContent = '—';
        document.getElementById('rules-pagination')?.replaceChildren();
        return false;
    } finally {
        if (current()) {busy = false; sync();}
    }
}

async function change(operation, ruleId, enabled) {
    if (!editable()) return false;
    const token = getAuthToken(), session = epoch, attempt = ++sequence;
    const current = () => token === getAuthToken() && session === epoch && attempt === sequence;
    busy = true; changing = true; message = 'pending'; sync();
    let rejection = false;
    try {
        const requestId = remote() ? newRequestId() : null;
        let target = '/api/rules/reload', method = 'POST', body;
        if (remote()) {
            body = {request_id: requestId, base_version: version};
            if (operation === 'set') {target = '/api/rules/entry'; method = 'PUT'; Object.assign(body, {rule_id: ruleId, enabled});}
        } else if (operation === 'set') {
            target = `/api/rules/${encodeURIComponent(ruleId)}/toggle`; method = 'PUT'; body = {enabled};
        }
        const response = await authFetch(target, {method, ...(body ? {body: JSON.stringify(body)} : {})});
        if (!current()) return false;
        rejection = response && !response.ok && response.status < 500;
        if (!response?.ok) throw Error('Rule change unavailable');
        const data = await response.json();
        if (!current()) return false;
        if (remote()) {
            if (data.status !== 'applied' || data.request_id !== requestId || data.control_process !== 'separate'
                    || !versionValid(data.base_version) || !versionValid(data.rules_hash)) throw Error('Unconfirmed rule receipt');
            if (operation === 'set') {
                validateRule(data.rule);
                if (data.rule.id !== ruleId || data.rule.enabled !== enabled) throw Error('Wrong applied rule');
            } else if (!Number.isSafeInteger(data.total) || data.total < 0) throw Error('Invalid reload receipt');
        } else if (data.status !== 'ok' || (operation === 'set' && (data.rule_id !== ruleId || data.enabled !== enabled))) {
            throw Error('Unconfirmed local rule receipt');
        }
        busy = false; changing = false;
        await loadRules(operation === 'reload' ? 0 : page, true);
        return true;
    } catch (error) {
        if (!current()) return false;
        loaded = false; failed = true; version = null; message = rejection ? 'rejected' : 'unknown';
        return false;
    } finally {
        if (current()) {busy = false; changing = false; sync();}
    }
}

export function changeRule(ruleId, enabled) {
    if (!rules.some(rule => rule.id === ruleId) || typeof enabled !== 'boolean') return Promise.resolve(false);
    return change('set', ruleId, enabled);
}
export function reloadRules() {return change('reload');}
export function registerRulesListeners() {
    document.getElementById('btn-rules-refresh')?.addEventListener('click', () => loadRules(0, true));
    document.getElementById('btn-rules-reload')?.addEventListener('click', reloadRules);
}
window.addEventListener('nw-session-ended', () => {
    epoch++; sequence++; page = 0; loaded = busy = changing = failed = false;
    version = null; rules = []; message = 'load_required';
    document.getElementById('rules-body')?.replaceChildren();
    document.getElementById('rules-pagination')?.replaceChildren();
    const count = document.getElementById('rules-count');
    if (count) count.textContent = '—';
    sync();
});
