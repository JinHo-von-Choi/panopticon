/** Bounded summaries of real stored events; scope is explicit, never inferred. */
import { authFetch } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';
import { featureEnabled } from '../core/capabilities.js';
import { loadObservedChanges } from './observations.js';
const t = (key, options = {}) => window.i18next.t('console.overview.' + key, options);
let snapshot = null;
let request = 0;
let priorityCategory = 'unclosed';
let priorityOffset = 0;
let priorityRequest = 0;
const priorityLabels = {unclosed:'미종결',unassigned:'미배정·미종결',unreviewed:'판정 기록 없음·미종결',expired:'정상 판정 기한 만료',recheck:'정상 판정 재검토'};

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
    const eventButton = event => `<button type="button" class="overview-event" data-overview-event="${esc(event.id)}"><span class="console-eyebrow">#${esc(event.id)} / ${esc(event.engine)} / ${esc(event.severity)}</span><strong>${esc(event.title)}</strong><small>${esc(formatTime(event.timestamp))}</small>${event.review_reason ? '<small>'+esc(window.i18next.t('console.business_review.reasons.'+event.review_reason,{defaultValue:event.review_reason}))+'</small>' : ''}</button>`;
    box.innerHTML = `<article class="overview-panel"><p class="console-eyebrow">01 / ${esc(t('coverage'))}</p>
        <h3>${esc(observation.state || 'unknown')}</h3><p>${esc((observation.reasons || []).join(' / ') || t('coverage_unknown'))}</p>
        <p>${esc(t('queue', {count: queue.depth ?? 'unknown', lost: queue.expired_unconfirmed ?? 'unknown'}))}</p>
        ${queue.recovery_spool ? `<p>${esc(t('spool', {state: queue.recovery_spool.state, count: queue.recovery_spool.files}))}</p>` : ''}
        <button type="button" class="btn" data-overview-screen="governance">${esc(t('verify_scope'))}</button></article>
        <article class="overview-panel"><p class="console-eyebrow">02 / ${esc(t('changes'))}</p>
        ${featureEnabled('eve_observations') ? '<div id="overview-observations"></div>' : failed ? `<p>${esc(t('unavailable'))}</p>` : changes.length ? changes.map(eventButton).join('') : `<p>${esc(t('no_changes'))}</p>`}
        ${featureEnabled('eve_observations') ? '' : '<p class="text-dim">'+esc(t('bounded_scope'))+'</p>'}</article>
        <article class="overview-panel"><p class="console-eyebrow">03 / ${esc(t('review'))}</p>
        ${featureEnabled('investigation_priorities') ? '<div id="overview-priority"></div>' : ''}
        ${featureEnabled('investigation_priorities') ? '' : failed ? `<p>${esc(t('unavailable'))}</p>` : review.length ? review.map(eventButton).join('') : `<p>${esc(t('no_review'))}</p>`}
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
    if (featureEnabled('eve_observations')) loadObservedChanges(box.querySelector('#overview-observations'));
    renderPriorities();
    box.querySelectorAll('[data-overview-event]').forEach(button => button.addEventListener('click', () => window.showEventDetail(button.dataset.overviewEvent)));
    box.querySelectorAll('[data-overview-screen]').forEach(button => button.addEventListener('click', () => document.querySelector(`.tab[data-tab="${button.dataset.overviewScreen}"]`)?.click()));
}

export async function loadOverview() {
    const current = ++request;
    const ownPriorityRequest = ++priorityRequest;
    const since = new Date(Date.now()-86400000).toISOString();
    const results = await Promise.allSettled(['/api/events?limit=50&since='+encodeURIComponent(since), '/api/health', ...(featureEnabled('investigation_priorities') ? ['/api/investigation/priorities?limit=5&category='+priorityCategory] : [])].map(async path => {
        const response = await authFetch(path);
        if (!response?.ok) throw new Error('Overview unavailable');
        return response.json();
    }));
    if (current !== request) return;
    snapshot = {events: results[0].status === 'fulfilled' ? results[0].value.events || [] : [],
        health: results[1].status === 'fulfilled' ? results[1].value : null,
        failed: results[0].status !== 'fulfilled',
        priorities: ownPriorityRequest === priorityRequest ? (results[2]?.status === 'fulfilled' ? results[2].value : null) : snapshot?.priorities || null};
    if (ownPriorityRequest === priorityRequest) priorityOffset = 0;
    render();
}

export function initOverview() {
    document.getElementById('overview-refresh').addEventListener('click', loadOverview);
    window.i18next.on('languageChanged', render);
}


function renderPriorities() {
    const container = document.getElementById('overview-priority');
    if (!container) return;
    const data = snapshot?.priorities;
    container.innerHTML = '<h3>처리 우선순위</h3>' +
        '<p class="scope-note">보존 중인 전체 사건 기준입니다. 항목끼리 중복될 수 있습니다. 정상 판정 재검토를 선택하면 기한·장치·근거·작업 일정의 현재 유효성을 확인합니다.</p>' +
        '<label for="priority-category">우선순위 분류</label><select id="priority-category">' +
        Object.entries(priorityLabels).map(([key,label]) => `<option value="${key}" ${key===priorityCategory?'selected':''}>${esc(label)}</option>`).join('') + '</select>' +
        (!data ? (snapshot?.priorityCapacity ? '<p>정상 판정이 1,000건을 넘어 전체 재검토 목록을 조회할 수 없습니다. 개별 사건에서 판정을 확인하세요.</p>' : '<p>처리 상태를 불러오지 못했습니다. 새로고침으로 다시 확인하세요.</p>') :
        `<p>미종결 ${esc(data.counts.unclosed)} · 미배정 ${esc(data.counts.unassigned)} · 판정 기록 없음 ${esc(data.counts.unreviewed)} · 정상 판정 기한 만료 ${esc(data.counts.expired)}${data.recheck_evaluated ? ' · 정상 판정 재검토 '+esc(data.counts.recheck) : ''}</p>` +
        (data.proposals_available ? `<button class="btn" data-priority-proposals>탐지 설정 승인 대기 ${esc(data.pending_proposals)}건</button>` : '<p>승인 제안 기능을 사용하지 않습니다.</p>') +
        `<p>${esc(formatTime(data.snapshot_at))} 기준 · ${esc(priorityLabels[data.category])} ${esc(data.total)}건</p>` +
        '<p class="scope-note">심각도가 높은 사건부터, 같은 심각도에서는 최근 발생 순으로 표시합니다.</p>' +
        data.events.map(event => `<button type="button" class="overview-event" data-priority-event="${esc(event.id)}"><strong>${esc(event.severity)} · ${esc(event.title)}</strong><small>${esc(event.owner || '미배정')} · ${esc(({open:'미처리',investigating:'조사 중',closed:'종결'})[event.status])} · ${esc(formatTime(event.timestamp))}</small>${event.review_reason ? '<small>'+esc(window.i18next.t('console.business_review.reasons.'+event.review_reason,{defaultValue:event.review_reason}))+'</small>' : ''}</button>`).join('') +
        (data.total===0?'<p>이 분류에 해당하는 보존 사건이 없습니다.</p>':'') +
        (data.offset>0?'<button class="btn" data-priority-prev>이전 우선순위 사건</button>':'') +
        (data.offset+data.events.length<data.total?'<button class="btn" data-priority-next>다음 우선순위 사건</button>':''));
    container.querySelector('select').addEventListener('change', event => {
        priorityCategory = event.target.value;
        loadPriorities(0);
    });
    container.querySelectorAll('[data-priority-event]').forEach(button => button.addEventListener('click',()=>window.showEventDetail(button.dataset.priorityEvent)));
    container.querySelector('[data-priority-prev]')?.addEventListener('click',()=>loadPriorities(Math.max(0,priorityOffset-5)));
    container.querySelector('[data-priority-next]')?.addEventListener('click',()=>loadPriorities(priorityOffset+5));
    container.querySelector('[data-priority-proposals]')?.addEventListener('click',()=>document.querySelector('.tab[data-tab="governance"]')?.click());
}

async function loadPriorities(offset) {
    const current = ++priorityRequest;
    const category = priorityCategory;
    try {
        const response = await authFetch(`/api/investigation/priorities?limit=5&category=${category}&offset=${offset}`);
        if (!response.ok) {
            if (current !== priorityRequest || category !== priorityCategory) return;
            snapshot.priorities = null;
            snapshot.priorityCapacity = response.status === 413;
            renderPriorities();
            return;
        }
        const data = await response.json();
        if (current!==priorityRequest || category!==priorityCategory) return;
        snapshot.priorities = data;
        snapshot.priorityCapacity = false;
        priorityOffset = offset;
    } catch {
        if (current!==priorityRequest || category!==priorityCategory) return;
        snapshot.priorities = null;
    }
    renderPriorities();
}
