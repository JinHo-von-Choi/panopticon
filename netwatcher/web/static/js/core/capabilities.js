/** 서버가 제공하는 기능에 맞춰 콘솔의 조회와 조작을 표시한다. */
import { authFetch, canConfigure, getCurrentUserId } from './api.js';

let features = {};
let states = {};
export function featureEnabled(name) { return features[name] === true; }
/** 기능 상태: available | unsupported | unconfigured | unknown. 조회 전이나 실패 시 unknown. */
export function featureState(name) { return states[name] || { state: 'unknown', reason: 'capabilities_unavailable' }; }

let noticeLanguageHook = false;

function renderNotices() {
    if (!noticeLanguageHook && window.i18next?.on) {
        noticeLanguageHook = true;
        window.i18next.on('languageChanged', () => renderNotices());
    }
    document.querySelectorAll('[data-capability-notice]').forEach(el => {
        const { state, reason } = featureState(el.dataset.capabilityNotice);
        // 장치 대신 관측 주소를 보여 주는 구성에서는 미지원 안내가 혼란만 준다.
        const replaced = el.dataset.capabilityNotice === 'devices' && featureState('observed_assets').state === 'available';
        el.hidden = state === 'available' || replaced;
        if (el.hidden) { el.textContent = ''; return; }
        const t = key => window.i18next.t(key);
        el.textContent = `${t('console.capability.state.' + state)} — ${t('console.capability.reason.' + (reason || 'none'))}`;
    });
}

export async function loadCapabilities() {
    features = {}; states = {};
    try {
        const response = await authFetch('/api/capabilities');
        if (response?.ok) {
            const body = await response.json();
            features = body.features || {};
            states = body.states || {};
        }
    } catch { /* 확인하지 못한 선택 기능은 실행하지 않는다. */ }
    renderNotices();
    for (const name of ['engines', 'whitelist', 'blocklist', 'incidents', 'defense', 'ai-analyzer', 'traffic']) {
        document.querySelectorAll(`[data-tab="${name}"]`).forEach(button => {
            button.style.display = featureEnabled(name) ? '' : 'none';
        });
    }
    for (const [id, name] of [['replay-panel', 'replay'], ['proposal-panel', 'proposals'], ['case-queue-toolbar', 'case_workflows'], ['events-case-header', 'case_workflows'], ['event-groups-panel', 'event_groups']]) {
        const panel = document.getElementById(id);
        if (panel) panel.hidden = !featureEnabled(name);
    }
    document.querySelectorAll('[data-tab="users"]').forEach(button => {
        button.style.display = featureEnabled('users') && canConfigure() ? '' : 'none';
    });
    document.querySelectorAll('[data-requires-feature]').forEach(el => { el.hidden = !featureEnabled(el.dataset.requiresFeature); });
    document.querySelectorAll('[data-requires-state]').forEach(el => { el.hidden = featureState(el.dataset.requiresState).state === 'unsupported'; });
    document.querySelectorAll('[data-nav-group]').forEach(group => {
        group.hidden = ![...group.querySelectorAll('.tab')].some(tab => tab.style.display !== 'none');
    });
    const mine = document.getElementById('case-mine-control');
    if (mine) mine.hidden = !featureEnabled('users') || !getCurrentUserId();
    if (mine?.hidden) {
        document.getElementById('filter-case-mine').checked = false;
        document.getElementById('filter-case-owner').disabled = false;
    }
}
