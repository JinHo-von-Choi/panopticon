/** 서버가 제공하는 기능에 맞춰 콘솔의 조회와 조작을 표시한다. */
import { authFetch, canConfigure, getCurrentUserId } from './api.js';

let features = {};
export function featureEnabled(name) { return features[name] === true; }

export async function loadCapabilities() {
    features = {};
    try {
        const response = await authFetch('/api/capabilities');
        if (response?.ok) features = (await response.json()).features || {};
    } catch { /* 확인하지 못한 선택 기능은 실행하지 않는다. */ }
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
    const mine = document.getElementById('case-mine-control');
    if (mine) mine.hidden = !featureEnabled('users') || !getCurrentUserId();
    if (mine?.hidden) {
        document.getElementById('filter-case-mine').checked = false;
        document.getElementById('filter-case-owner').disabled = false;
    }
}
