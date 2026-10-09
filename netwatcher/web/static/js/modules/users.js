/** 개인 계정의 조회와 관리. 변경 요청은 자동 재시도하지 않는다. */
import { authFetch, canConfigure, isAuthEnabled } from '../core/api.js';
import { featureEnabled } from '../core/capabilities.js';
import { esc, formatTime } from '../core/utils.js';

const t = (key, options = {}) => window.i18next.t('console.users.' + key,
    {interpolation: {escapeValue: false}, ...options});
let generation = 0;
let busy = false;
let pageOffset = 0;
const identityLoads = new WeakMap();

function roles(current = 'viewer') {
    return ['viewer', 'analyst', 'admin'].map(role =>
        `<option value="${role}"${role === current ? ' selected' : ''}>${esc(t('roles.' + role))}</option>`).join('');
}

function passwordField(label) {
    return `<label>${esc(label)}<input class="input-search" name="password" type="password"
        autocomplete="new-password" minlength="12" maxlength="72" required></label>`;
}

function accountCard(user) {
    return `<article class="user-card" data-user-id="${esc(user.id)}">
        <h4>${esc(user.username)} <span class="text-dim">${esc(t(user.enabled ? 'active' : 'inactive'))}</span></h4>
        <p class="scope-hint">${esc(t('version', {version: user.version}))} · ${esc(formatTime(user.updated_at))}</p>
        <form data-user-update><fieldset class="user-fields">
            <div><label for="user-role-${esc(user.id)}">${esc(t('role'))}</label>
                <select id="user-role-${esc(user.id)}" class="input-search" name="role">${roles(user.role)}</select></div>
            <label class="user-enabled"><input type="checkbox" name="enabled"${user.enabled ? ' checked' : ''}>${esc(t('enabled'))}</label>
            <button class="btn" type="submit">${esc(t('save_state'))}</button>
        </fieldset></form>
        <details><summary>${esc(t('reset_password'))}</summary>
            <form data-user-password><fieldset class="user-fields">${passwordField(t('new_password'))}
                <button class="btn" type="submit">${esc(t('reset_password'))}</button>
            </fieldset></form>
        </details>
        <details data-user-identities><summary>${esc(t('identities'))}</summary>
            <div data-identities-content></div>
        </details></article>`;
}

export async function loadUsers(offset = pageOffset, notice = '', requestId = '') {
    if (!canConfigure() || !featureEnabled('users') || !isAuthEnabled()) return;
    const panel = document.getElementById('users-panel');
    if (!panel) return;
    const attempt = ++generation;
    pageOffset = Math.max(0, offset);
    panel.innerHTML = `<div class="onboarding-check-heading"><h3>${esc(t('title'))}</h3>
        <button type="button" class="btn" data-users-refresh>${esc(t('refresh'))}</button></div>
        <p class="scope-hint">${esc(t('scope'))}</p><p class="scope-hint">${esc(t('password_hint'))}</p>
        <p data-users-result role="status" aria-live="polite">${esc(notice)}</p>
        <div data-users-audit></div><div data-users-content>${esc(t('loading'))}</div>`;
    panel.querySelector('[data-users-refresh]').addEventListener('click', () => { if (!busy) loadUsers(pageOffset); });
    if (/^[a-f0-9]{32}$/.test(requestId)) addAuditLink(panel, requestId);
    const content = panel.querySelector('[data-users-content]');
    let data;
    try {
        const response = await authFetch(`/api/users?limit=50&offset=${pageOffset}`);
        if (!response?.ok) throw Error('Account list unavailable');
        data = await response.json();
    } catch {
        if (attempt === generation && panel.isConnected) content.textContent = t('unavailable');
        return;
    }
    if (attempt !== generation || !canConfigure() || !isAuthEnabled()) return;
    if (pageOffset >= data.total && pageOffset > 0) {
        await loadUsers(Math.max(0, pageOffset - 50), notice, requestId);
        return;
    }
    content.innerHTML = `<details class="user-create"><summary>${esc(t('create'))}</summary>
        <form data-user-create><fieldset class="user-fields">
            <label>${esc(t('username'))}<input class="input-search" name="username" pattern="[A-Za-z0-9_.-]+"
                maxlength="64" autocomplete="off" required></label>${passwordField(t('initial_password'))}
            <div><label for="user-create-role">${esc(t('role'))}</label>
                <select id="user-create-role" class="input-search" name="role">${roles()}</select></div>
            <button class="btn btn-accent" type="submit">${esc(t('create'))}</button>
        </fieldset></form></details>
        <p>${esc(t('total', {count: data.total}))}</p>
        <div class="users-grid">${data.users.map(accountCard).join('')}</div><div data-users-pages></div>`;
    content.querySelector('[data-user-create]').addEventListener('submit', event => {
        event.preventDefault();
        const form = event.currentTarget;
        const body = {username: form.elements.username.value, password: form.elements.password.value, role: form.elements.role.value};
        form.elements.password.value = '';
        mutate('/api/users', 'POST', body, 0);
    });
    for (const user of data.users) {
        const card = content.querySelector(`[data-user-id="${user.id}"]`);
        card.querySelector('[data-user-update]').addEventListener('submit', event => {
            event.preventDefault();
            const form = event.currentTarget;
            mutate('/api/users/' + user.id, 'PUT', {expected_version: user.version,
                role: form.elements.role.value, enabled: form.elements.enabled.checked});
        });
        card.querySelector('[data-user-password]').addEventListener('submit', event => {
            event.preventDefault();
            const form = event.currentTarget;
            const body = {expected_version: user.version, password: form.elements.password.value};
            form.elements.password.value = '';
            mutate('/api/users/' + user.id + '/password', 'POST', body);
        });
        const identities = card.querySelector('[data-user-identities]');
        identities.addEventListener('toggle', () => {
            if (identities.open) loadIdentities(card, user.id, attempt);
        });
    }
    const pages = content.querySelector('[data-users-pages]');
    for (const [label, offset, enabled] of [[t('previous'), pageOffset - 50, pageOffset > 0],
                                           [t('next'), pageOffset + 50, pageOffset + 50 < data.total]]) {
        if (!enabled) continue;
        const button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
        button.textContent = label; button.addEventListener('click', () => { if (!busy) loadUsers(offset); }); pages.append(button);
    }
}

async function loadIdentities(card, userId, attempt) {
    const load = Symbol();
    identityLoads.set(card, load);
    const content = card.querySelector('[data-identities-content]');
    content.textContent = t('loading');
    let data;
    try {
        const response = await authFetch('/api/users/' + userId + '/identities');
        if (!response?.ok) throw Error('Identity list unavailable');
        data = await response.json();
    } catch {
        if (card.isConnected && attempt === generation && identityLoads.get(card) === load) content.textContent = t('unavailable');
        return;
    }
    if (!card.isConnected || attempt !== generation || identityLoads.get(card) !== load || !canConfigure() || !isAuthEnabled()) return;
    content.innerHTML = `<p class="scope-hint">${esc(t('identity_hint'))}</p>
        <form data-user-identity-link><fieldset class="user-fields">
            <label>${esc(t('issuer'))}<input class="input-search" type="url" name="issuer" maxlength="512" required autocomplete="off"></label>
            <label>${esc(t('subject'))}<input class="input-search" name="subject" maxlength="255" required autocomplete="off"></label>
            <button class="btn" type="submit">${esc(t('link_identity'))}</button></fieldset></form>
        <p>${esc(t('identity_count', {count: data.identities.length}))}</p><div data-identity-list></div>`;
    content.querySelector('[data-user-identity-link]').addEventListener('submit', event => {
        event.preventDefault();
        const form = event.currentTarget;
        mutate('/api/users/' + userId + '/identities', 'POST', {expected_version: data.user.version,
            issuer: form.elements.issuer.value, subject: form.elements.subject.value});
    });
    const list = content.querySelector('[data-identity-list]');
    let offset = 0;
    function render() {
        list.innerHTML = data.identities.slice(offset, offset + 5).map(item =>
            `<div class="case-note"><p>${esc(item.issuer)}</p><p>${esc(item.subject)}</p>
                <button class="btn" type="button" data-identity-unlink="${esc(item.id)}">${esc(t('unlink_identity'))}</button></div>`).join('');
        list.querySelectorAll('[data-identity-unlink]').forEach(button => button.addEventListener('click', () => {
            mutate('/api/users/' + userId + '/identities/' + button.dataset.identityUnlink,
                'DELETE', {expected_version: data.user.version});
        }));
        for (const [label, next] of [[t('previous'), offset - 5], [t('next'), offset + 5]]) {
            if (next < 0 || next >= data.identities.length) continue;
            const button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
            button.textContent = label; button.addEventListener('click', () => { if (!busy) {offset = next; render();} }); list.append(button);
        }
    }
    render();
}

async function mutate(path, method, body, offset = pageOffset) {
    if (busy || !canConfigure() || !isAuthEnabled()) return;
    busy = true;
    const panel = document.getElementById('users-panel');
    panel.querySelectorAll('fieldset,button').forEach(control => control.disabled = true);
    panel.querySelector('[data-users-result]').textContent = t('saving');
    let notice = t('unknown_result');
    let requestId = '';
    try {
        const response = await authFetch(path, {method, body: JSON.stringify(body)});
        requestId = response.headers.get('X-Request-ID') || '';
        const result = await response.json();
        requestId = requestId || result.request_id || '';
        if (response.ok) notice = t('saved');
        else if (response.status === 409) notice = t('reasons.' + result.detail, {defaultValue: t('conflict')});
        else if (response.status === 422) notice = t('invalid_input');
        else if (response.status === 403) notice = t('forbidden');
    } catch { /* 응답이 끊겼으면 읽기 조회로 확인하고 변경 요청은 반복하지 않는다. */ }
    finally {
        body.password = undefined;
        busy = false;
    }
    // 자기 계정 변경은 이 조회에서 이전 토큰을 거절하고 로그인 화면을 연다.
    await loadUsers(offset, notice, requestId);
}

function addAuditLink(panel, requestId) {
    const box = panel.querySelector('[data-users-audit]');
    const button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
    button.textContent = t('audit'); box.append(button);
    const result = document.createElement('p'); result.className = 'case-note'; result.setAttribute('role', 'status'); box.append(result);
    button.addEventListener('click', async () => {
        button.disabled = true; result.textContent = t('loading');
        try {
            const response = await authFetch('/api/audit/changes/' + requestId);
            if (!response.ok) throw Error('Audit unavailable');
            const history = await response.json();
            const lines = [t(history.requires_reconciliation ? 'audit_unknown' : 'audit_known',
                {outcome: t('outcomes.' + history.outcome), requestId})];
            const outcome = [...history.entries].reverse().find(entry => entry.action === 'api_mutation');
            if (outcome) {
                lines.push(t('audit_actor', {actor: outcome.user, time: formatTime(outcome.created_at)}));
                for (const key of ['before', 'after']) {
                    const state = outcome.details[key];
                    if (state) lines.push(t('audit_state', {label: t(key), role: t('roles.' + state.role),
                        state: t(state.enabled ? 'active' : 'inactive'), version: state.version}));
                }
            }
            result.textContent = lines.join('\n');
        } catch { result.textContent = t('audit_unavailable'); }
        finally { button.disabled = false; }
    });
}
