/** 사건 담당자·처리 상태와 인계 이력. */
import { authFetch, canConfigure } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';
import { featureEnabled } from '../core/capabilities.js';
const t = (key, options = {}) => window.i18next.t('console.case_workflow.' + key, options);
const loads = new WeakMap();

async function accountChoices() {
    const response = await authFetch('/api/users?limit=1000');
    if (!response?.ok) throw Error('Accounts unavailable');
    const page = await response.json();
    if (page.total > 1000 || page.users.length !== page.total) throw Error('Incomplete account choices');
    return page.users;
}

export async function loadCaseWorkflow(event, panel) {
    if (!panel?.isConnected) return;
    const attempt = Symbol(); loads.set(panel, attempt);
    panel.textContent = t('loading');
    let data;
    try {
        const response = await authFetch(`/api/events/${event.id}/case`);
        if (!response?.ok) throw new Error('Case unavailable');
        data = await response.json();
    } catch {
        if (panel.isConnected && loads.get(panel) === attempt) panel.textContent = t('unavailable');
        return;
    }
    if (!panel.isConnected || loads.get(panel) !== attempt) return;
    const current = data.case;
    panel.innerHTML = `<h3>${esc(t('title'))}</h3>
        <p role="status" aria-live="polite">${esc(t('statuses.' + current.status))} · ${esc(current.owner || t('unassigned'))}</p>
        <p class="scope-hint">${esc(t('scope'))}</p>
        ${current.owner_id ? `<p class="scope-hint">${esc(t(current.owner_enabled ? 'account_linked' : 'account_disabled'))}</p>` : current.owner ? `<p class="scope-hint">${esc(t('label_only'))}</p>` : ''}
        <button type="button" class="btn" data-case-refresh>${esc(t('refresh'))}</button>
        <h4>${esc(t('history'))}</h4><ol class="case-history"></ol>
        <p data-case-history-error role="status"></p>
        <button type="button" class="btn" data-case-more>${esc(t('more'))}</button>`;
    panel.querySelector('[data-case-refresh]').addEventListener('click', () => loadCaseWorkflow(event, panel));
    const list = panel.querySelector('.case-history');
    const more = panel.querySelector('[data-case-more]');
    let cursor;
    function appendHistory(page) {
        for (const entry of page.history) {
            const item = document.createElement('li');
            item.innerHTML = `<p>${esc(formatTime(entry.updated_at))} · ${esc(entry.actor)} · ${esc(t('statuses.' + entry.status))} · ${esc(entry.owner || t('unassigned'))}</p><p class="case-note">${esc(entry.note)}</p>`;
            list.append(item);
        }
        cursor = page.next_before_version;
        more.hidden = cursor === null;
    }
    appendHistory(data);
    if (!data.history.length) list.textContent = t('no_history');
    more.addEventListener('click', async () => {
        more.disabled = true;
        const message = panel.querySelector('[data-case-history-error]');
        message.textContent = '';
        try {
            const response = await authFetch(`/api/events/${event.id}/case?before_version=${cursor}`);
            if (!response?.ok) throw new Error('History unavailable');
            const page = await response.json();
            if (panel.isConnected) appendHistory(page);
        } catch {
            if (panel.isConnected) message.textContent = t('history_unavailable');
        } finally { more.disabled = false; }
    });
    if (!canConfigure()) return;
    let accounts = null;
    if (featureEnabled('users')) {
        try { accounts = await accountChoices(); }
        catch {
            if (panel.isConnected && loads.get(panel) === attempt) {
                const error = document.createElement('p'); error.setAttribute('role', 'status');
                error.textContent = t('accounts_unavailable'); panel.append(error);
            }
            return;
        }
        if (!panel.isConnected || loads.get(panel) !== attempt || !canConfigure()) return;
    }
    const form = document.createElement('form');
    form.className = 'business-review-form';
    form.innerHTML = `<fieldset><legend>${esc(t('edit'))}</legend>
        ${accounts ? `<div class="form-group"><label for="case-owner-id">${esc(t('owner_account'))}</label>
            <select id="case-owner-id" class="input-search"><option value="">${esc(t('label_choice'))}</option>
            ${accounts.map(account => `<option value="${esc(account.id)}"${account.id === current.owner_id ? ' selected' : ''}${!account.enabled && account.id !== current.owner_id ? ' disabled' : ''}>${esc(account.username)}${account.enabled ? '' : ' · '+esc(t('disabled'))}</option>`).join('')}</select></div>` : ''}
        <div class="form-group"><label for="case-owner">${esc(t('owner'))}</label>
        <input id="case-owner" class="input-search" type="text" maxlength="128"></div>
        <div class="form-group"><label for="case-status">${esc(t('status'))}</label>
        <select id="case-status" class="input-search">${['open','investigating','closed'].map(value => `<option value="${value}">${esc(t('statuses.'+value))}</option>`).join('')}</select></div>
        <div class="form-group"><label for="case-note">${esc(t('note'))}</label>
        <textarea id="case-note" class="input-search" required minlength="3" maxlength="1024" rows="3"></textarea></div>
        <button type="submit" class="btn btn-accent">${esc(t('save'))}</button></fieldset>
        <p data-case-result role="status" aria-live="polite"></p>`;
    panel.append(form);
    form.querySelector('#case-owner').value = current.owner;
    if (accounts) {
        const select = form.querySelector('#case-owner-id');
        const input = form.querySelector('#case-owner'); input.readOnly = !!select.value;
        select.addEventListener('change', () => {
            const account = accounts.find(candidate => candidate.id === select.value);
            input.value = account ? account.username : ''; input.readOnly = !!account;
        });
    }
    form.querySelector('#case-status').value = current.status;
    form.addEventListener('submit', async submit => {
        submit.preventDefault();
        const payload = {owner: form.querySelector('#case-owner').value.trim(),
            status: form.querySelector('#case-status').value,
            note: form.querySelector('#case-note').value.trim(), expected_version: current.version};
        payload.owner_id = accounts ? (form.querySelector('#case-owner-id').value || null)
            : payload.owner === current.owner ? current.owner_id : null;
        form.querySelector('fieldset').disabled = true;
        const result = form.querySelector('[data-case-result]');
        result.textContent = t('saving');
        try {
            const response = await authFetch(`/api/events/${event.id}/case`, {method:'PUT',
                headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
            if (!response?.ok) {
                const error = await response?.json();
                result.textContent = response?.status === 409 ? t('reasons.'+error.detail) : t('unknown_result');
                return;
            }
            await loadCaseWorkflow(event, panel);
        } catch {
            if (panel.isConnected) result.textContent = t('unknown_result');
        }
    });
}
