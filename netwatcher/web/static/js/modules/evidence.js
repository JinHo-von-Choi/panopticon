/** 분리 센서 증거의 조회·보존·제한된 다운로드. */
import {authFetch, canConfigure, getAuthToken} from '../core/api.js';
import {esc, newRequestId} from '../core/utils.js';

const text = key => window.i18next.t('console.evidence_control.' + key);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
let epoch = 0, state = null, busy = false, failed = false, panel = null, eventId = null, download = null, observer = null;
let updateEvent = null;

export function resetEvidence() {
    epoch++; download?.abort(); download = null;
    observer?.disconnect(); observer = null;
    panel?.replaceChildren();
    state = null; busy = false; failed = false; panel = null; eventId = null;
    updateEvent = null;
}
window.addEventListener('nw-session-ended', resetEvidence);

function validate(value, id) {
    if (!value || value.event_id !== id || value.control_process !== 'separate' || !hash(value.base_version)
            || !['available', 'unavailable'].includes(value.state) || !['pinned', 'unpinned', 'unknown'].includes(value.pin_state)
            || !['matched_record', 'unrecorded'].includes(value.integrity)) throw Error('Invalid evidence state');
    if (value.state === 'available' && (!Number.isSafeInteger(value.size) || value.size < 24 || value.size > 32 * 1024 * 1024
            || !hash(value.sha256) || !hash(value.file_version))) throw Error('Invalid evidence file');
    if (value.pin_state === 'pinned' && (!value.pin || !Number.isFinite(value.pin.expires_at)
            || typeof value.pin.reason !== 'string' || value.pin.reason.length > 500)) throw Error('Invalid evidence pin');
    return value;
}

function render(message = 'ready') {
    if (!panel?.isConnected) return;
    updateEvent?.(failed || busy ? {event_id: eventId, state: 'unknown', pin_state: 'unknown', control_process: 'separate'} : state);
    const available = state?.state === 'available' && !failed;
    panel.innerHTML = `<p id="evidence-control-status" role="status">${esc(text(message))}</p>
        ${state ? `<p>${esc(text(state.state))} · ${esc(text(state.pin_state))}</p>` : ''}
        ${available ? `<p class="text-dim">${esc(text(state.integrity))} · ${esc(String(state.size))} B</p>` : ''}
        ${state?.pin ? `<p>${esc(text('expires'))}: ${esc(new Date(state.pin.expires_at * 1000).toLocaleString())}</p>` : ''}
        <div class="btn-group"><button type="button" class="btn" id="evidence-refresh" ${busy ? 'disabled' : ''}>${esc(text('refresh'))}</button>
        <button type="button" class="btn" id="evidence-download" ${!available || busy ? 'disabled' : ''}>${esc(text('download'))}</button>
        ${canConfigure() ? `<button type="button" class="btn" id="evidence-change" ${!available || busy || state.pin_state === 'unknown' ? 'disabled' : ''}>${esc(text(state?.pin_state === 'pinned' ? 'release' : 'pin'))}</button>` : ''}</div>`;
    panel.querySelector('#evidence-refresh').onclick = refresh;
    panel.querySelector('#evidence-download').onclick = downloadEvidence;
    const change = panel.querySelector('#evidence-change');
    if (change) change.onclick = changePin;
}

function context() {
    const session = epoch, token = getAuthToken(), target = panel, id = eventId;
    return {id, current: () => session === epoch && token === getAuthToken() && target === panel && target?.isConnected
        && !document.getElementById('modal-overlay')?.classList.contains('hidden')};
}

export function mountEvidence(id, initial, onUpdate) {
    resetEvidence(); panel = document.getElementById('remote-evidence-control'); eventId = Number(id); updateEvent = onUpdate;
    const overlay = document.getElementById('modal-overlay');
    if (overlay) {
        observer = new MutationObserver(() => {if (overlay.classList.contains('hidden')) resetEvidence();});
        observer.observe(overlay, {attributes: true, attributeFilter: ['class']});
    }
    try {state = validate(initial, eventId); render();}
    catch {failed = true; render('read_failed');}
}

async function refresh() {
    if (busy) return;
    const operation = context(); busy = true; render('loading');
    try {
        const response = await authFetch(`/api/events/${operation.id}/evidence`);
        if (!response?.ok) throw Error('Evidence unavailable');
        const value = await response.json();
        if (!operation.current()) return;
        state = validate(value, operation.id); failed = false;
    } catch {if (operation.current()) {state = null; failed = true;}}
    finally {if (operation.current()) {busy = false; render(failed ? 'read_failed' : 'ready');}}
}

async function changePin() {
    if (busy || failed || !canConfigure() || state?.state !== 'available' || state.pin_state === 'unknown') return;
    const reason = window.prompt(text('reason'))?.trim();
    if (!reason || reason.length < 3 || reason.length > 500 || reason.includes('\0')) return;
    const operation = context(), enabled = state.pin_state !== 'pinned', requestId = newRequestId();
    busy = true; render('pending'); let rejected = false;
    try {
        const response = await authFetch(`/api/events/${operation.id}/evidence/pin`, {method: 'POST', body: JSON.stringify({
            request_id: requestId, base_version: state.base_version, enabled, hours: 24, reason})});
        rejected = response && !response.ok && response.status < 500;
        if (!response?.ok) throw Error('Evidence change unavailable');
        const value = await response.json();
        if (!operation.current()) return;
        if (value.status !== 'applied' || value.request_id !== requestId || value.control_process !== 'separate') throw Error('Unconfirmed evidence change');
        const confirmed = validate({...value.evidence, control_process: value.control_process}, operation.id);
        if (confirmed.pin_state !== (enabled ? 'pinned' : 'unpinned')) throw Error('Unexpected evidence pin');
        state = confirmed; failed = false;
    } catch {if (operation.current()) failed = true;}
    finally {if (operation.current()) {busy = false; render(failed ? (rejected ? 'rejected' : 'unknown') : 'saved');}}
}

async function downloadEvidence() {
    if (busy || failed || state?.state !== 'available') return;
    const operation = context(), expected = state, controller = new AbortController();
    download = controller; busy = true; render('downloading');
    const timer = setTimeout(() => controller.abort(), 65000);
    try {
        const response = await authFetch(`/api/events/${operation.id}/evidence/file`, {signal: controller.signal});
        if (!response?.ok || response.headers.get('X-Content-SHA256') !== expected.sha256
                || response.headers.get('Content-Length') !== String(expected.size)) throw Error('Evidence identity changed');
        const reader = response.body.getReader(), parts = []; let size = 0;
        try {
            while (true) {
                const part = await reader.read();
                if (!operation.current()) throw Error('Evidence session changed');
                if (part.done) break;
                size += part.value.byteLength;
                if (size > expected.size) throw Error('Evidence download exceeds size');
                parts.push(part.value);
            }
        } finally {await reader.cancel(); reader.releaseLock();}
        if (size !== expected.size) throw Error('Incomplete evidence download');
        const blob = new Blob(parts, {type: 'application/vnd.tcpdump.pcap'});
        if (globalThis.crypto?.subtle) {
            const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
            const actual = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
            if (actual !== expected.sha256) throw Error('Evidence checksum mismatch');
        }
        if (!operation.current()) return;
        const url = URL.createObjectURL(blob), link = document.createElement('a');
        link.href = url; link.download = `event-${operation.id}.pcap`; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {if (operation.current()) failed = true;}
    finally {
        clearTimeout(timer);
        if (download === controller) download = null;
        if (operation.current()) {busy = false; render(failed ? 'download_failed' : 'downloaded');}
    }
}
