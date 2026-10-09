/** 목록·장치·경보 화면에서 공유하는 탐지 예외 상태. */
import { authFetch, canConfigure, getAuthToken } from './api.js';
import { featureEnabled } from './capabilities.js';
import { showToast, newRequestId } from './utils.js';

const keys = {ip:'ips', ip_range:'ip_ranges', mac:'macs', domain:'domains', suffix:'domain_suffixes'};
const empty = () => ({ips:[], ip_ranges:[], macs:[], domains:[], domain_suffixes:[]});
export let whitelistData = empty();
let version = null;
let loaded = false;
let busy = false;
let failed = false;
let epoch = 0;
let attempt = 0;
let message = 'load_required';
export const whitelistText = key => window.i18next.t('console.whitelist_control.' + key);
export function whitelistStatus() { return {loaded, busy, failed, message}; }
export function canChangeWhitelist() { return featureEnabled('whitelist') && canConfigure() && loaded && !busy && !failed; }
function notify() { window.dispatchEvent(new Event('nw-whitelist-updated')); }

window.addEventListener('nw-whitelist-updated', () => {
    document.querySelectorAll('[data-wl-event-ip], [data-wl-mac]').forEach(button => {
        const type = button.dataset.wlMac ? 'mac' : 'ip';
        const value = button.dataset.wlMac || button.dataset.wlEventIp;
        button.disabled = !canChangeWhitelist();
        button.textContent = whitelistText(containsWhitelist(type, value) ? 'remove' : 'add') + ' · ' + value;
    });
});

function validated(data) {
    const value = {};
    for (const key of Object.values(keys)) {
        if (!Array.isArray(data[key]) || data[key].some(item => typeof item !== 'string' || !item || item.length > 253)) {
            throw Error('Invalid whitelist');
        }
        value[key] = [...data[key]];
    }
    if (Object.values(value).reduce((sum, items) => sum + items.length, 0) > 1024) throw Error('Whitelist limit');
    return value;
}

export async function refreshWhitelist(manual = false) {
    if (busy || (failed && !manual) || !featureEnabled('whitelist')) return false;
    const read = ++attempt;
    const currentEpoch = epoch;
    const token = getAuthToken();
    const current = () => epoch === currentEpoch && token === getAuthToken() && read === attempt;
    try {
        const response = await authFetch('/api/whitelist');
        if (!current()) return false;
        if (!response?.ok) throw Error('Whitelist unavailable');
        const data = await response.json();
        if (!current()) return false;
        const remote = featureEnabled('whitelist_control_remote');
        if (remote && (data.control_process !== 'separate' || !/^[a-f0-9]{64}$/.test(data.base_version))) {
            throw Error('Whitelist version unavailable');
        }
        whitelistData = validated(data);
        version = remote ? data.base_version : null;
        loaded = true;
        failed = false;
        message = canConfigure() ? '' : 'readonly';
        notify();
        return true;
    } catch (error) {
        if (!current()) return false;
        loaded = false;
        failed = true;
        version = null;
        whitelistData = empty();
        message = 'load_failed';
        notify();
        return false;
    }
}

export async function changeWhitelist(type, value, present) {
    if (!canChangeWhitelist() || !keys[type] || !value || typeof present !== 'boolean') return null;
    const currentEpoch = epoch;
    const token = getAuthToken();
    const current = () => epoch === currentEpoch && token === getAuthToken();
    const remote = featureEnabled('whitelist_control_remote');
    // 변경 전 시작한 조회가 새 버전을 덮어쓰지 못하게 한다.
    ++attempt;
    busy = true;
    message = 'pending';
    notify();
    try {
        const requestId = newRequestId();
        const body = remote ? {request_id:requestId, base_version:version, type, value, present} : {type, value, present};
        const response = await authFetch(remote ? '/api/whitelist/entry' : '/api/whitelist/toggle',
            {method:remote ? 'PUT' : 'POST', body:JSON.stringify(body)});
        if (!current()) return null;
        if (!response?.ok) {
            const error = Error('Whitelist change unconfirmed');
            error.rejected = response && response.status < 500;
            throw error;
        }
        const result = await response.json();
        if (!current()) return null;
        if (remote) {
            if (result.status !== 'applied' || result.request_id !== requestId || !/^[a-f0-9]{64}$/.test(result.base_version)) {
                throw Error('Whitelist receipt unavailable');
            }
            whitelistData = validated(result.whitelist);
            version = result.base_version;
        } else {
            if (!['added','removed'].includes(result.action)) throw Error('Whitelist receipt unavailable');
            const read = await authFetch('/api/whitelist');
            if (!current()) return null;
            if (!read?.ok) throw Error('Whitelist refresh unavailable');
            const data = await read.json();
            if (!current()) return null;
            whitelistData = validated(data);
        }
        message = 'applied';
        return present ? 'added' : 'removed';
    } catch (error) {
        if (!current()) return null;
        failed = true;
        message = error.rejected ? 'rejected' : 'unknown';
        showToast(whitelistText('title'), whitelistText(message), 'warning');
        return null;
    } finally {
        if (current()) {
            busy = false;
            notify();
        }
    }
}

export function containsWhitelist(type, value) {
    return !!keys[type] && whitelistData[keys[type]].includes(['mac','domain','suffix'].includes(type) ? value.toLowerCase() : value);
}

window.addEventListener('nw-session-ended', () => {
    ++epoch;
    ++attempt;
    whitelistData = empty();
    version = null;
    loaded = busy = failed = false;
    message = 'load_required';
    notify();
});
