/** 승인된 자산 범위와 조치 영수증을 보여 주는 독립 실행기 화면. */
import {authFetch, canConfigure, isAuthEnabled, getAuthToken} from '../core/api.js';
import {esc, formatTime} from '../core/utils.js';

const t = (key, options = {}) => window.i18next.t('console.response.' + key,
    {interpolation: {escapeValue: false}, ...options});
let generation = 0;
let mutation = null;

async function read(url) {
    const response = await authFetch(url);
    if (!response?.ok) throw Error('Response data unavailable');
    return response.json();
}

function current(attempt, token) {
    return attempt === generation && token === getAuthToken() && isAuthEnabled();
}

function proposalCard(proposal, devices, admin) {
    const mapping = proposal.target_mapping || {};
    const scope = proposal.match_scope || {};
    const matching = devices.filter(device => device.ip_address === proposal.source_ip);
    const device = matching.length === 1 ? matching[0] : null;
    const valid = device && Number.isSafeInteger(device.id) && Number.isSafeInteger(device.ip_mapping_version)
        && scope.kind === 'asset' && scope.service_aware === false && scope.asset_id === mapping.asset_id
        && mapping.shared === false && mapping.protected === false && mapping.confirmed_at;
    const form = admin && proposal.status === 'proposed' && valid ? `
        <form data-response-approve="${esc(proposal.id)}"><fieldset class="response-fields">
            <label>${esc(t('reason'))}<input class="input-search" name="reason" maxlength="512" required></label>
            <button type="submit" class="btn btn-accent">${esc(t('approve'))}</button>
    </fieldset></form>` : `<p class="scope-hint">${esc(t(!admin ? 'readonly' : proposal.status !== 'proposed' ? 'already_decided' : 'cannot_approve'))}</p>`;
    return `<article class="response-card" data-proposal-id="${esc(proposal.id)}">
        <div class="onboarding-check-heading"><h4>${esc(proposal.source_ip)}</h4><span class="response-state">${esc(t('proposal_states.' + proposal.status, {defaultValue: t('already_decided')}))}</span></div>
        <p>${esc(mapping.asset_id || t('unknown_asset'))} · ${esc(t('ttl', {seconds: proposal.ttl_seconds}))}</p>
        <p class="scope-hint">${esc(t('mapping_checked'))} ${esc(formatTime(mapping.confirmed_at))}</p>
        <p class="scope-hint">${esc(t('visibility.' + proposal.visibility_state, {defaultValue: t('visibility.unknown')}))}</p>
        <details data-response-impact="${esc(proposal.id)}"><summary>${esc(t('impact'))}</summary><div data-impact-content></div></details>
        ${form}</article>`;
}

function actionCard(action, admin) {
    const binding = action.binding;
    const state = t('states.' + action.state, {defaultValue: t('states.unknown')});
    const approvedUntil = binding ? formatTime(binding.approval_expires_at) : t('no_binding');
    const apply = admin && binding && action.state === 'requested'
        ? `<button class="btn btn-accent" type="button" data-response-operation="activate">${esc(t('activate_shadow'))}</button>` : '';
    const recover = admin && binding && action.attempt_count > 0
        ? `<button class="btn" type="button" data-response-operation="verify">${esc(t('verify'))}</button>
           <button class="btn" type="button" data-response-operation="remove">${esc(t('remove'))}</button>` : '';
    return `<article class="response-card" data-action-id="${esc(action.id)}">
        <div class="onboarding-check-heading"><h4>${esc(action.target)}</h4><span class="response-state" data-state="${esc(action.state)}">${esc(state)}</span></div>
        <p>${esc(binding?.reason || t('no_binding'))}</p>
        <dl class="response-facts"><div><dt>${esc(t('approval_until'))}</dt><dd>${esc(approvedUntil)}</dd></div>
            <div><dt>${esc(t('action_until'))}</dt><dd>${esc(action.expire_at ? formatTime(action.expire_at) : t('not_started'))}</dd></div></dl>
        <fieldset class="response-fields">${apply}${recover}</fieldset>
        <details data-response-receipts="${esc(action.id)}"><summary>${esc(t('receipts'))}</summary><div data-receipt-content></div></details>
        </article>`;
}

export async function loadResponse(notice = '') {
    const panel = document.getElementById('response-panel');
    if (!panel || mutation || !isAuthEnabled()) return;
    const attempt = ++generation;
    const token = getAuthToken();
    panel.hidden = false;
    panel.innerHTML = `<div class="response-heading"><div><p class="response-eyebrow">${esc(t('eyebrow'))}</p><h3>${esc(t('title'))}</h3></div>
        <button type="button" class="btn" data-response-refresh>${esc(t('refresh'))}</button></div>
        <p class="response-mode">${esc(t('shadow_notice'))}</p>
        <p role="status" aria-live="polite" data-response-result>${esc(notice)}</p>
        <div data-response-content>${esc(t('loading'))}</div>`;
    panel.querySelector('[data-response-refresh]').addEventListener('click', () => loadResponse());
    let data;
    try {
        data = await Promise.all([read('/api/response-proposals?limit=50'), read('/api/response-actions?limit=50'), read('/api/devices')]);
    } catch {
        if (current(attempt, token)) panel.querySelector('[data-response-content]').textContent = t('unavailable');
        return;
    }
    if (!current(attempt, token)) return;
    const proposals = data[0].proposals || [];
    const actions = data[1].actions || [];
    const devices = data[2].devices || [];
    const admin = canConfigure();
    panel.querySelector('[data-response-content]').innerHTML = `<div class="response-columns">
        <section><h4 class="response-column-title">${esc(t('proposals_title'))} <span>${proposals.length}</span></h4>
            ${proposals.map(proposal => proposalCard(proposal, devices, admin)).join('') || `<p>${esc(t('no_proposals'))}</p>`}</section>
        <section><h4 class="response-column-title">${esc(t('actions_title'))} <span>${actions.length}</span></h4>
            ${actions.map(action => actionCard(action, admin)).join('') || `<p>${esc(t('no_actions'))}</p>`}</section></div>`;
    for (const form of panel.querySelectorAll('[data-response-approve]')) {
        form.addEventListener('submit', event => {
            event.preventDefault();
            const proposal = proposals.find(item => String(item.id) === form.dataset.responseApprove);
            const device = devices.find(item => item.ip_address === proposal.source_ip);
            const body = {target: proposal.source_ip, direction: 'input', ttl_seconds: proposal.ttl_seconds,
                scope: {asset: proposal.target_mapping.asset_id}, device_id: device.id,
                base_version: `device:${device.id}:${device.ip_mapping_version}`,
                reason: form.elements.reason.value.trim()};
            if (body.reason) change(panel, `/api/change-proposals/${proposal.id}/approve`, body, t('approval_saved'), attempt, token);
        });
    }
    for (const button of panel.querySelectorAll('[data-response-operation]')) {
        button.addEventListener('click', () => {
            const id = button.closest('[data-action-id]').dataset.actionId;
            const action = actions.find(item => String(item.id) === id);
            const operation = button.dataset.responseOperation;
            const body = operation === 'activate' ? {target: action.target, direction: action.direction,
                ttl_seconds: action.ttl_seconds, scope: action.binding.scope, base_version: action.base_version} : undefined;
            change(panel, `/api/response-actions/${id}/${operation}`, body, t('intent_recorded'), attempt, token);
        });
    }
    for (const details of panel.querySelectorAll('[data-response-impact], [data-response-receipts]')) {
        let loaded = false;
        details.addEventListener('toggle', async () => {
            if (!details.open || loaded) return;
            loaded = true;
            const impact = details.dataset.responseImpact;
            const target = details.querySelector(impact ? '[data-impact-content]' : '[data-receipt-content]');
            target.textContent = t('loading');
            try {
                const value = await read(impact ? `/api/response-proposals/${impact}/impact` : `/api/response-actions/${details.dataset.responseReceipts}`);
                if (!current(attempt, token) || !details.isConnected) return;
                if (impact) {
                    const observed = value.observed_scope?.asset_ids || [];
                    const uncertain = value.unconfirmed_scope?.asset_ids || [];
                    const reasons = (value.unconfirmed_scope?.reasons || []).map(reason => t('uncertainty.' + reason, {defaultValue: t('uncertainty.unknown')}));
                    target.innerHTML = `<p><strong>${esc(t('observed_assets'))}</strong> ${esc(observed.join(' · ') || t('none'))}</p>
                        <p><strong>${esc(t('unconfirmed_assets'))}</strong> ${esc(uncertain.join(' · ') || t('none'))}</p>
                        <p>${esc(reasons.join(' · '))}</p>`;
                } else {
                    target.innerHTML = (value.receipts || []).map(receipt => `<p>${esc(formatTime(receipt.observed_at))} · ${esc(t('phases.' + receipt.phase, {defaultValue: t('receipts')}))} · ${esc(t('outcomes.' + receipt.outcome, {defaultValue: t('outcomes.unverified')}))}<br>${esc(receipt.detail?.detail || '')}</p>`).join('') || esc(t('no_receipts'));
                }
            } catch {
                if (current(attempt, token) && details.isConnected) target.textContent = t('unavailable');
                loaded = false;
            }
        });
    }
}

async function change(panel, url, body, success, attempt, token) {
    if (mutation || !canConfigure() || !current(attempt, token)) return;
    const ticket = {};
    mutation = ticket;
    panel.querySelectorAll('fieldset').forEach(field => { field.disabled = true; });
    const status = panel.querySelector('[data-response-result]');
    status.textContent = t('saving');
    let saved = false;
    try {
        const response = await authFetch(url, {method: 'POST', ...(body ? {body: JSON.stringify(body)} : {})});
        if (!current(attempt, token)) return;
        if (!response?.ok) {
            status.textContent = t(!response || response.status >= 500 ? 'unknown_result' : 'rejected');
            if (!response || response.status >= 500) panel.querySelectorAll('[data-response-approve] button, [data-response-operation="activate"]').forEach(button => { button.disabled = true; });
        } else saved = true;
    } catch {
        if (current(attempt, token)) {
            status.textContent = t('unknown_result');
            panel.querySelectorAll('[data-response-approve] button, [data-response-operation="activate"]').forEach(button => { button.disabled = true; });
        }
    } finally {
        if (mutation === ticket) {
            mutation = null;
            if (current(attempt, token)) panel.querySelectorAll('fieldset').forEach(field => { field.disabled = false; });
        }
    }
    if (saved && current(attempt, token)) await loadResponse(success);
}

window.addEventListener('nw-session-ended', () => {
    generation++;
    mutation = null;
    const panel = document.getElementById('response-panel');
    if (panel) panel.replaceChildren();
});
