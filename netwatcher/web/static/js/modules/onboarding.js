/** 현재 설치 점검: 실제 측정과 현장 미확인을 구분한다. */
import { authFetch } from '../core/api.js';
import { esc, formatBytes } from '../core/utils.js';
const t = (key, options = {}) => window.i18next.t('console.onboarding.' + key, options);
let report = null;
let requestId = 0;

function render() {
    const box = document.getElementById('onboarding-box');
    const summary = document.getElementById('onboarding-summary');
    if (!box || !summary) return;
    summary.removeAttribute('data-i18n');
    if (!report) {
        box.textContent = t('unavailable');summary.textContent = t('unavailable');return;
    }
    const checks = Array.isArray(report.checks) ? report.checks : [];
    const count = checks.filter(check => check.status === 'attention').length;
    summary.textContent = t('summary', {count, unknown: checks.filter(check => check.status === 'unknown').length});
    box.innerHTML = checks.map(check => {
        const state = ['pass', 'attention', 'unknown'].includes(check.status) ? check.status : 'unknown';
        const facts = check.facts || {};
        let fact = '';
        if (check.name === 'storage' && Number.isFinite(facts.free_bytes)) {
            fact = t('disk_facts', {free: formatBytes(facts.free_bytes), required: formatBytes(facts.required_bytes)});
        } else if (check.name === 'memory' && Number.isFinite(facts.main_process_peak_rss_bytes)) {
            fact = t('memory_facts', {rss: formatBytes(facts.main_process_peak_rss_bytes)});
        } else if (check.name === 'coverage') {
            fact = t('observation', {state: facts.observation_state || 'unknown'});
        } else if (check.name === 'capture') {
            fact = t('interface', {interface: facts.configured_interface || 'auto'});
        }
        return `<article class="onboarding-check" data-state="${state}">
            <div class="onboarding-check-heading"><h4>${esc(t('names.' + check.name))}</h4><span>${esc(t('states.' + state))}</span></div>
            <p>${esc(t('reasons.' + check.reason))}</p>${fact ? `<p class="text-dim">${esc(fact)}</p>` : ''}</article>`;
    }).join('');
}

export async function loadOnboarding() {
    const current = ++requestId;
    try {
        const response = await authFetch('/api/onboarding');
        if (!response?.ok) throw new Error('Installation check unavailable');
        const data = await response.json();
        if (current !== requestId) return;
        report = data;
    } catch (error) {
        if (current !== requestId) return;
        console.error('Installation check failed', error); report = null;
    }
    render();
}

export function initOnboarding() {
    document.getElementById('onboarding-open')?.addEventListener('click', () => {
        document.querySelector('.tab[data-tab="governance"]').click();
        document.getElementById('onboarding-panel').scrollIntoView({block:'start'});
    });
    document.getElementById('onboarding-refresh')?.addEventListener('click', loadOnboarding);
    window.i18next.on('languageChanged', render);
}
