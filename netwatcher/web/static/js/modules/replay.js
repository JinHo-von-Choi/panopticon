/** 동일 특징값의 정상/공격 비교. 운영 설정 적용은 별도의 승인 경로다. */
import { authFetch, canAnalyze, getAuthToken } from '../core/api.js';
import { esc, showToast } from '../core/utils.js';
import {featureEnabled} from '../core/capabilities.js';
import {attachRemoteValidation} from './proposals.js';
const t = (key, options = {}) => window.i18next.t('console.replay.' + key, options);
let capabilities = null;
let pair = null;
let selectedRun = null;
let selectedProposal = null;
let refreshId = 0;
let rendered = null;
let poll = null;
let sessionEpoch = 0;
window.addEventListener('nw-session-ended', () => {
    sessionEpoch++; refreshId++; capabilities = null; pair = null; selectedRun = null; selectedProposal = null; rendered = null;
    if (poll) {clearInterval(poll);poll = null;}
    document.getElementById('replay-comparison')?.replaceChildren();
    document.getElementById('replay-runs')?.replaceChildren();
    document.getElementById('replay-form')?.reset();
});

function defaults() {
    const engine = document.getElementById('replay-engine').value;
    const value = JSON.stringify(capabilities?.defaults?.[engine] || {}, null, 2);
    document.getElementById('replay-baseline').value = value;
    document.getElementById('replay-candidate').value = value;
    selectedProposal = null;
}

async function inputFile(id) {
    const file = document.getElementById(id).files[0];
    if (!file || file.size > 768 * 1024) throw new Error(t('file_limit'));
    const data = JSON.parse(await file.text());
    const records = Array.isArray(data) ? data : data.records;
    if (!Array.isArray(records) || !records.length || records.length > capabilities.max_records) {
        throw new Error(t('invalid_input'));
    }
    return records;
}

function params(id) {
    const data = JSON.parse(document.getElementById(id).value);
    if (!data || Array.isArray(data) || typeof data !== 'object') throw new Error(t('invalid_parameters'));
    const allowed = capabilities.parameters[document.getElementById('replay-engine').value] || [];
    if (Object.entries(data).some(([key, value]) => !allowed.includes(key) || !Number.isSafeInteger(value) || value < 1)) {
        throw new Error(t('invalid_parameters'));
    }
    return data;
}

function totals(run, side) {
    return (run?.[side] || []).reduce((sum, result) => sum + (result.observation_count || 0), 0);
}

function renderSide(run, label) {
    if (!run) return `<p>${esc(t('unavailable'))}</p>`;
    const context = run.comparison_context || {};
    const before = context.baseline_contract || {};
    const candidate = context.candidate_contract || {};
    const reasons = run.non_comparable_reasons || [];
    const counts = run.diff?.counts || {};
    return `<article class="replay-result"><h4>${esc(t(label))} / #${esc(run.run_id)}</h4>
        <p>${esc(t('status.' + run.status))}</p><p>${esc(t('hash'))}: <code>${esc(run.input_hash || 'unknown')}</code></p>
        <div class="replay-contract">${esc(t('before'))}: ${esc(JSON.stringify(before.params || {}))}
${esc(t('candidate'))}: ${esc(JSON.stringify(candidate.params || {}))}
${esc(t('versions'))} / ${esc(t('before'))}: ${esc(JSON.stringify(before.versions || {}))}
${esc(t('versions'))} / ${esc(t('candidate'))}: ${esc(JSON.stringify(candidate.versions || {}))}
${esc(t('implementation'))}: ${esc(context.implementation_version || 'unknown')}</div>
        ${run.status === 'completed' ? `<p>${esc(t('counts', {before: totals(run, 'baseline'), candidate: totals(run, 'candidate'), removed: counts.removed || 0, changed: counts.changed || 0}))}</p>` : ''}
        ${reasons.length ? `<ul>${reasons.map(reason => `<li>${esc(reason.code)}: ${esc(reason.detail)}</li>`).join('')}</ul>` : ''}</article>`;
}

function renderComparison() {
    const box = document.getElementById('replay-comparison');
    if (!rendered) { box.textContent = ''; return; }
    if (!pair || selectedRun) {
        box.innerHTML = renderSide(rendered.single, 'single'); return;
    }
    const {normal, attack} = rendered;
    const done = normal?.status === 'completed' && attack?.status === 'completed';
    const labelled = normal?.comparison_context?.input_label === 'normal' && attack?.comparison_context?.input_label === 'attack'
        && normal?.comparison_context?.label_confirmed === true && attack?.comparison_context?.label_confirmed === true;
    const comparable = done && labelled && normal.comparable === true && attack.comparable === true;
    const distinctInputs = Boolean(normal?.input_hash && attack?.input_hash && normal.input_hash !== attack.input_hash);
    const positiveControl = totals(attack, 'baseline') > 0;
    const preserved = comparable && distinctInputs && positiveControl && attack.diff?.counts.removed === 0 && attack.diff?.counts.changed === 0
        && totals(attack, 'candidate') >= totals(attack, 'baseline');
    const state = !done ? 'pending_pair' : !comparable ? 'not_comparable' : !distinctInputs ? 'same_input' : !positiveControl ? 'no_positive_control' : !preserved ? 'attack_lost' : 'observations_preserved';
    box.innerHTML = `<article class="replay-result" data-state="${preserved ? 'preserved' : 'blocked'}"><h4>${esc(t(state))}</h4><p>${esc(t('interpretation'))}</p></article>`
        + renderSide(normal, 'normal') + renderSide(attack, 'attack');
    if (selectedProposal && normal && attack) {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'btn'; button.textContent = t('attach_validation');
        button.disabled = !preserved;
        button.addEventListener('click', () => attachValidation(normal.run_id, attack.run_id, button));
        box.prepend(button);
    }
}

async function attachValidation(normal, attack, button) {
    if (!selectedProposal || !canAnalyze()) return;
    const proposalId = selectedProposal.id;
    const epoch = sessionEpoch, token = getAuthToken();
    const current = () => epoch === sessionEpoch && token === getAuthToken();
    button.disabled = true;
    try {
        if (featureEnabled('proposals_control_remote')) {
            const saved = await attachRemoteValidation(selectedProposal, normal, attack);
            if (saved && current() && selectedProposal?.id === proposalId) {selectedProposal = null;renderComparison();}
            return;
        }
        const response = await authFetch('/api/proposals/' + proposalId + '/validation', {
            method: 'POST', body: JSON.stringify({normal_run_id: normal, attack_run_id: attack})});
        if (!response?.ok) {
            const error = response ? await response.json() : null;
            throw new Error(error?.detail?.error || t('attach_failed'));
        }
        if (!current()) return;
        if (selectedProposal?.id === proposalId) { selectedProposal = null; renderComparison(); }
        showToast(t('attached'), '', 'info');
        window.dispatchEvent(new Event('proposal-validation-attached'));
    } catch (error) { if (current()) showToast(error.message || t('attach_failed'), '', 'critical'); }
    finally { if (current() && button.isConnected) button.disabled = featureEnabled('proposals_control_remote'); }

}

export async function loadReplay() {
    const request = ++refreshId;
    const epoch = sessionEpoch, token = getAuthToken();
    const current = () => epoch === sessionEpoch && token === getAuthToken() && request === refreshId;
    const availability = document.getElementById('replay-availability');
    try {
        if (!capabilities) {
            const response = await authFetch('/api/replay-capabilities');
            if (!response?.ok) throw new Error('Replay unavailable');
            if (!current()) return;
            const fetched = await response.json();
            if (!current()) return;
            capabilities = fetched;
            const select = document.getElementById('replay-engine');
            select.replaceChildren(...capabilities.engines.map(engine => {
                const option = document.createElement('option');option.value = engine;option.textContent = engine;return option;
            }));
            defaults();
        }
        availability.textContent = t('available', {engines: capabilities.engines.join(' / ')});
        document.getElementById('replay-form').hidden = !canAnalyze();
        const response = await authFetch('/api/replay-runs?limit=20');
        if (!response?.ok) throw new Error('Replay list unavailable');
        const data = await response.json();
        if (!current()) return;
        const list = document.getElementById('replay-runs');list.replaceChildren();list.className = 'replay-run-list';
        for (const run of data.runs || []) {
            const button = document.createElement('button');button.className = 'btn';button.type = 'button';
            button.textContent = '#' + run.id + ' · ' + t('status.' + run.status);
            button.addEventListener('click', () => { selectedRun = run.id;loadReplay(); });list.appendChild(button);
        }
        const ids = selectedRun ? [selectedRun] : pair ? [pair.normal, pair.attack] : [];
        const results = [];
        for (const id of ids) {
            const response = await authFetch('/api/replay-runs/' + id + '/diff');
            results.push(response?.ok ? await response.json() : null);
        }
        if (!current()) return;
        rendered = selectedRun ? {single: results[0]} : pair ? {normal: results[0], attack: results[1]} : null;
        renderComparison();
        const pending = (data.runs || []).some(run => ['pending', 'running'].includes(run.status));
        if (pending && !poll) poll = setInterval(() => {
            if (!document.hidden && document.getElementById('tab-governance').classList.contains('active')) loadReplay();
        }, 2000);
        if (!pending && poll) { clearInterval(poll);poll = null; }
    } catch (error) {
        if (!current()) return;
        console.error('Replay read failed', error);
        availability.textContent = t('unavailable');
        document.getElementById('replay-form').hidden = true;
    }
}

export function initReplay() {
    document.getElementById('replay-refresh').addEventListener('click', loadReplay);
    document.getElementById('replay-engine').addEventListener('change', defaults);
    document.getElementById('replay-form').addEventListener('submit', async event => {
        event.preventDefault();
        if (!canAnalyze() || !capabilities || !document.getElementById('replay-label-confirmed').checked) return;
        const button = document.getElementById('replay-submit');button.disabled = true;
        const epoch = sessionEpoch, token = getAuthToken(), proposal = selectedProposal;
        const current = () => epoch === sessionEpoch && token === getAuthToken();
        try {
            const normal = await inputFile('replay-normal-file'), attack = await inputFile('replay-attack-file');
            if (!current()) return;
            const payload = {engines: [document.getElementById('replay-engine').value],
                baseline_params: params('replay-baseline'), candidate_params: params('replay-candidate'),
                baseline_version: capabilities.build_version, candidate_version: capabilities.build_version,
                label_confirmed: true, proposal_id: proposal?.id || null};
            const submitted = {};
            for (const [label, records] of [['normal', normal], ['attack', attack]]) {
                if (!current()) return;
                const response = await authFetch('/api/replay-runs', {method:'POST', body:JSON.stringify({...payload, records, input_label:label})});
                if (!response?.ok) throw new Error(t('request_failed', {status: response?.status || 'unknown'}));
                const result = await response.json();
                if (!current()) return;
                submitted[label] = result.run_id;
            }
            pair = submitted;selectedRun = null;await loadReplay();
        } catch (error) {
            if (current()) {showToast(error.message || t('request_failed'), '', 'critical');await loadReplay();}
        } finally {if (current() && button.isConnected) button.disabled = false;}
    });
    window.addEventListener('proposal-validation', async event => {
        const epoch = sessionEpoch, token = getAuthToken();
        await loadReplay();
        if (epoch !== sessionEpoch || token !== getAuthToken()) return;
        const proposal = event.detail;
        if (!capabilities?.proposal_parameters?.[proposal.engine] ||
            Object.keys(proposal.params || {}).some(key => !capabilities.proposal_parameters[proposal.engine].includes(key))) {
            showToast(t('unsupported_change'), '', 'critical'); return;
        }
        selectedProposal = proposal;
        document.getElementById('replay-engine').value = proposal.engine;
        const before = Object.fromEntries(capabilities.parameters[proposal.engine].map(key => [key, proposal.before?.[key] ?? capabilities.defaults[proposal.engine][key]]));
        document.getElementById('replay-baseline').value = JSON.stringify(before, null, 2);
        document.getElementById('replay-candidate').value = JSON.stringify({...before, ...proposal.params}, null, 2);
        pair = null;selectedRun = null;rendered = null;renderComparison();
        document.getElementById('replay-panel').scrollIntoView({block:'start'});
    });
    window.i18next.on('languageChanged', () => {
        renderComparison();
        if (document.getElementById('tab-governance').classList.contains('active')) loadReplay();
    });
}
