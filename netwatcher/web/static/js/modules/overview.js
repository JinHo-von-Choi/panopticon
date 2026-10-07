/** Bounded summaries of real stored events; scope is explicit, never inferred. */
import { authFetch } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';
const t = (key, options = {}) => window.i18next.t('console.overview.' + key, options);
let snapshot = null;
let request = 0;

function render() {
    const box = document.getElementById('console-overview');
    if (!box) return;
    if (!snapshot) { box.textContent = t('unavailable'); return; }
    const {events, health, failed} = snapshot;
    const observation = health?.components?.observation || {};
    const queue = health?.components?.alert_queue || {};
    const changes = events.filter(event => event.metadata?.change_type || event.engine === 'behavior_profile').slice(0, 3);
    const relations = events.filter(event => event.dest_ip || event.metadata?.flows?.length).slice(0, 3);
    const review = [...events].filter(event => event.severity !== 'INFO')
        .sort((a,b) => (a.severity === 'CRITICAL' ? 0 : 1) - (b.severity === 'CRITICAL' ? 0 : 1)).slice(0, 3);
    const eventButton = event => `<button type="button" class="overview-event" data-overview-event="${esc(event.id)}"><span class="console-eyebrow">#${esc(event.id)} / ${esc(event.engine)} / ${esc(event.severity)}</span><strong>${esc(event.title)}</strong><small>${esc(formatTime(event.timestamp))}</small></button>`;
    box.innerHTML = `<article class="overview-panel"><p class="console-eyebrow">01 / ${esc(t('coverage'))}</p>
        <h3>${esc(observation.state || 'unknown')}</h3><p>${esc((observation.reasons || []).join(' / ') || t('coverage_unknown'))}</p>
        <p>${esc(t('queue', {count: queue.depth ?? 'unknown', lost: queue.expired_unconfirmed ?? 'unknown'}))}</p>
        ${queue.recovery_spool ? `<p>${esc(t('spool', {state: queue.recovery_spool.state, count: queue.recovery_spool.files}))}</p>` : ''}
        <button type="button" class="btn" data-overview-screen="governance">${esc(t('verify_scope'))}</button></article>
        <article class="overview-panel"><p class="console-eyebrow">02 / ${esc(t('changes'))}</p>
        ${failed ? `<p>${esc(t('unavailable'))}</p>` : changes.length ? changes.map(eventButton).join('') : `<p>${esc(t('no_changes'))}</p>`}
        <p class="text-dim">${esc(t('bounded_scope'))}</p></article>
        <article class="overview-panel"><p class="console-eyebrow">03 / ${esc(t('review'))}</p>
        ${failed ? `<p>${esc(t('unavailable'))}</p>` : review.length ? review.map(eventButton).join('') : `<p>${esc(t('no_review'))}</p>`}
        <button type="button" class="btn" data-overview-screen="incidents">${esc(t('incidents'))}</button></article>
        <article class="overview-panel overview-relations"><p class="console-eyebrow">04 / ${esc(t('relationships'))}</p>
        ${relations.length ? relations.map(event => {
            const flow = event.metadata?.flows?.[0];
            const peer = event.dest_ip || flow?.peer_ip;
            const business = event.metadata?.business_context;
            return `<button type="button" class="overview-event relation-edge" data-overview-event="${esc(event.id)}">
                <span><code>${esc(event.source_mac || event.source_ip || 'unknown')}</code> <span aria-hidden="true">→</span> <code>${esc(peer || 'unknown')}</code></span>
                <small>${esc(business?.state === 'expected_job' ? `${business.role} / v${business.context_version}` : t('owner_unknown'))} · ${esc(event.engine)} / #${esc(event.id)}</small></button>`;
        }).join('') : `<p>${esc(failed ? t('unavailable') : t('no_relations'))}</p>`}
        <p class="text-dim">${esc(t('relationship_scope'))}</p></article>`;
    box.querySelectorAll('[data-overview-event]').forEach(button => button.addEventListener('click', () => window.showEventDetail(button.dataset.overviewEvent)));
    box.querySelectorAll('[data-overview-screen]').forEach(button => button.addEventListener('click', () => document.querySelector(`.tab[data-tab="${button.dataset.overviewScreen}"]`)?.click()));
}

export async function loadOverview() {
    const current = ++request;
    const since = new Date(Date.now()-86400000).toISOString();
    const results = await Promise.allSettled(['/api/events?limit=50&since='+encodeURIComponent(since), '/api/health'].map(async path => {
        const response = await authFetch(path);
        if (!response?.ok) throw new Error('Overview unavailable');
        return response.json();
    }));
    if (current !== request) return;
    snapshot = {events: results[0].status === 'fulfilled' ? results[0].value.events || [] : [],
        health: results[1].status === 'fulfilled' ? results[1].value : null,
        failed: results[0].status !== 'fulfilled'};
    render();
}

export function initOverview() {
    document.getElementById('overview-refresh').addEventListener('click', loadOverview);
    window.i18next.on('languageChanged', render);
}
