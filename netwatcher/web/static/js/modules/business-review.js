/** 원래 경보와 분리된 사건별 업무 판정. */
import { authFetch, canConfigure } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';

const t = (key, options = {}) => window.i18next.t('console.business_review.' + key, options);
const decisions = ['investigate', 'insufficient_evidence', 'expected_backup', 'approved_maintenance'];
const normal = decision => ['expected_backup', 'approved_maintenance'].includes(decision);

export async function loadBusinessReview(event, panel) {
    if (!panel?.isConnected) return;
    panel.textContent = t('loading');
    let data;
    try {
        const response = await authFetch(`/api/events/${event.id}/business-review`);
        if (!response?.ok) throw new Error('Review unavailable');
        data = await response.json();
    } catch {
        if (panel.isConnected) panel.textContent = t('unavailable');
        return;
    }
    if (!panel.isConnected) return;
    const review = data.review;
    panel.innerHTML = `<h3>${esc(t('title'))}</h3>
        <p class="business-review-state" role="status" aria-live="polite" data-state="${esc(data.state)}">${esc(t('states.' + data.state))}</p>
        <p class="text-dim">${esc(t('reasons.' + data.reason))}</p>
        ${review ? `<div class="detail-grid"><div class="detail-label">${esc(t('reviewer'))}</div><div class="detail-value">${esc(review.actor)}</div>
        <div class="detail-label">${esc(t('expires'))}</div><div class="detail-value">${esc(review.expires_at ? formatTime(review.expires_at) : t('no_expiry'))}</div>
        <div class="detail-label">${esc(t('note'))}</div><div class="detail-value">${esc(review.note)}</div></div>` : ''}
        <p class="scope-hint">${esc(t('scope'))}</p>
        <button type="button" class="btn" data-review-refresh>${esc(t('refresh'))}</button>`;
    panel.querySelector('[data-review-refresh]').addEventListener('click', () => loadBusinessReview(event, panel));
    const history = document.createElement('section');
    history.innerHTML = `<h4>${esc(t('history_title'))}</h4><p class="scope-hint">${esc(t('history_scope'))}</p>
        <ol class="case-history"></ol><p data-history-message role="status"></p>
        <button type="button" class="btn" data-history-more hidden>${esc(t('history_more'))}</button>`;
    panel.append(history);
    let cursor = null;
    const more = history.querySelector('[data-history-more]');
    const message = history.querySelector('[data-history-message]');
    async function loadHistory() {
        more.disabled = true;
        message.textContent = t('history_loading');
        try {
            const response = await authFetch(`/api/events/${event.id}/business-review/history` + (cursor === null ? '' : `?before_version=${cursor}`));
            if (!response?.ok) throw new Error('History unavailable');
            const page = await response.json();
            if (!panel.isConnected) return;
            for (const entry of page.history) {
                const item = document.createElement('li');
                item.innerHTML = `<p>${esc(formatTime(entry.reviewed_at))} · ${esc(entry.actor)} · ${esc(t('decisions.'+entry.decision))}</p>
                    <p class="case-note">${esc(entry.note)}</p>
                    ${entry.scope?.dest_ip ? `<p class="text-dim">${esc(t('history_peer'))}: ${esc(entry.scope.source_ip || '-')} → ${esc(entry.scope.dest_ip)} · ${esc(entry.scope.protocol || '-')} / ${esc(entry.scope.dest_port ?? '-')}</p>` : ''}
                    ${entry.scope?.max_bytes ? `<p class="text-dim">${esc(t('history_limit'))}: ${esc(entry.scope.max_bytes)}</p>` : ''}
                    ${entry.scope?.asset_context?.role ? `<p class="text-dim">${esc(t('history_role'))}: ${esc(window.i18next.t('console.asset_context.roles.' + entry.scope.asset_context.role, {defaultValue:entry.scope.asset_context.role}))}</p>` : ''}
                    ${entry.scope?.work_schedule ? `<p class="text-dim">${esc(t('history_work'))}: ${esc(entry.scope.work_schedule.content.title)} · ${esc(entry.scope.work_schedule.content.owner)} · ${esc(entry.scope.work_schedule.content.ticket)}</p>` : ''}
                    <p class="text-dim">${esc(t('expires'))}: ${esc(entry.expires_at ? formatTime(entry.expires_at) : t('no_expiry'))}</p>`;
                history.querySelector('ol').append(item);
            }
            cursor = page.next_before_version;
            more.hidden = cursor === null;
            message.textContent = history.querySelector('ol').children.length ? '' : t('history_empty');
        } catch {
            if (panel.isConnected) message.textContent = t('history_unavailable');
        } finally { more.disabled = false; }
    }
    more.addEventListener('click', loadHistory);
    loadHistory();
    if (!canConfigure()) return;
    const availableDecisions = event.metadata?.external_eve ? decisions : decisions.filter(value => !normal(value));
    const form = document.createElement('form');
    form.className = 'business-review-form';
    form.innerHTML = `<fieldset><legend>${esc(t('edit'))}</legend>
        <div class="form-group"><label for="review-decision">${esc(t('decision'))}</label>
        <select id="review-decision" class="input-search">${availableDecisions.map(value => `<option value="${value}">${esc(t('decisions.' + value))}</option>`).join('')}</select></div>
        <div class="form-group"><label for="review-note">${esc(t('note'))}</label>
        <textarea id="review-note" class="input-search" required minlength="3" maxlength="512" rows="3"></textarea></div>
        <div data-normal-fields class="business-review-limits">
        <div class="form-group"><label for="review-hours">${esc(t('hours'))}</label>
        <input id="review-hours" class="input-search" type="number" min="1" max="168" step="1" value="24"></div>
        <div class="form-group"><label for="review-max-bytes">${esc(t('volume'))}</label>
        <input id="review-max-bytes" class="input-search" type="number" min="1" max="1099511627776" step="1"></div></div>
        <button class="btn btn-accent" type="submit">${esc(t('save'))}</button></fieldset>
        <p data-review-result role="status" aria-live="polite"></p>`;
    panel.append(form);
    const select = form.querySelector('#review-decision');
    const note = form.querySelector('#review-note');
    const maximum = form.querySelector('#review-max-bytes');
    const hours = form.querySelector('#review-hours');
    select.value = availableDecisions.includes(review?.decision) ? review.decision : 'investigate';
    note.value = review?.note || '';
    maximum.value = review?.scope?.max_bytes || '';
    function updateFields() {
        const required = normal(select.value);
        form.querySelector('[data-normal-fields]').hidden = !required;
        maximum.required = required; hours.required = required;
    }
    select.addEventListener('change', updateFields); updateFields();
    form.addEventListener('submit', async submit => {
        submit.preventDefault();
        const result = form.querySelector('[data-review-result]');
        const payload = {decision: select.value, note: note.value.trim(), expected_version: review?.version || 0,
                         valid_hours: normal(select.value) ? Number(hours.value) : 24,
                         max_bytes: normal(select.value) ? Number(maximum.value) : null};
        form.querySelector('fieldset').disabled = true;
        result.textContent = t('saving');
        try {
            const response = await authFetch(`/api/events/${event.id}/business-review`, {
                method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
            if (!response?.ok) {
                const error = await response?.json();
                result.textContent = response?.status === 409 ? t('reasons.' + error.detail) + ' ' + t('reload_first') : t('unknown_result');
                return;
            }
            await loadBusinessReview(event, panel);
        } catch {
            if (panel.isConnected) result.textContent = t('unknown_result');
        }
    });
}
