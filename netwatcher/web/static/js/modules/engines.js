/** 탐지 엔진 조회와 설정 변경. */

import { authFetch, canConfigure, getAuthToken } from '../core/api.js';
import { esc, showToast, newRequestId } from '../core/utils.js';

var enginesData = [];
let selectedEngine = null;
let busy = false;
let needsRefresh = false;
let remoteControl = false;
let sessionEpoch = 0;
let loadAttempt = 0;
let inflight = null;
const tr = key => window.i18next.t('console.engine_control.' + key);

function notice(key) {
    const node = document.getElementById('engine-control-status');
    if (node) node.textContent = key ? tr(key) : '';
}

function editable(eng) {
    return canConfigure() && !busy && !needsRefresh && eng.configuration_available !== false;
}

function render() {
    const refresh = document.getElementById('engine-control-refresh');
    if (refresh) refresh.disabled = busy;
    renderEnginesList();
    const selected = enginesData.find(engine => engine.name === selectedEngine);
    if (selected) renderEngineDetail(selected);
    else {
        const node = document.getElementById('engine-detail');
        if (node) node.textContent = tr('select');
    }
}

/**
 * 엔진 목록 요청 1회를 공유한다.
 *
 * 로그인 직후 loadEngines()와 populateEngineFilter()가 같은 목록을 동시에
 * 요청해 센서 왕복과 HTTP 요청이 각각 두 번 나가던 것을 하나로 합친다.
 * 상태를 건드리지 않으므로 이름만 필요한 호출자도 그대로 재사용한다.
 * 캐시는 두지 않는다 — 거절·응답 유실 뒤의 새로고침이 옛 값을 보여 주면 안 된다.
 */
function fetchEngineList(options) {
    const fresh = !!(options && options.fresh);
    if (!fresh && inflight) return inflight;
    const run = (async () => {
        const resp = await authFetch("/api/engines");
        if (!resp || !resp.ok) throw new Error('Engine list unavailable');
        const data = await resp.json();
        if (!Array.isArray(data.engines) || data.engines.length > 64) throw new Error('Invalid engine list');
        return data;
    })();
    // fresh도 진행 중 슬롯을 차지해야 한다. 이전 조회를 무효로 만든 뒤
    // 슬롯을 비워 두면, 그 사이 들어온 호출이 죽은 조회에 붙어
    // 새 요청 없이 false만 받는다.
    inflight = run;
    const clear = () => { if (inflight === run) inflight = null; };
    run.then(clear, clear);
    return run;
}

export async function loadEngines(options) {
    if (busy) return false;
    const attempt = ++loadAttempt;
    const epoch = sessionEpoch;
    const token = getAuthToken();
    const current = () => epoch === sessionEpoch && token === getAuthToken() && attempt === loadAttempt;
    try {
        const data = await fetchEngineList(options);
        if (!current()) return false;
        remoteControl = data.control_process === 'separate' || data.engines.some(engine => engine.base_version !== undefined);
        if (remoteControl && data.engines.some(engine => !/^[a-f0-9]{64}$/.test(engine.base_version))) {
            throw new Error('Missing engine version');
        }
        enginesData = data.engines;
        needsRefresh = false;
        notice(canConfigure() ? '' : 'readonly');
        render();
        return true;
    } catch (e) {
        if (!current()) return false;
        enginesData = [];
        needsRefresh = true;
        notice('load_failed');
        render();
        return false;
    }
}

export function renderEnginesList() {
    const container = document.getElementById("engines-list");
    if (!container) return;
    
    container.innerHTML = "";
    enginesData.forEach(eng => {
        const card = document.createElement("div");
        card.className = "engine-card" + (eng.enabled ? "" : " disabled") + (selectedEngine === eng.name ? ' selected' : '');
        
        const displayName = window.i18next.t("engines." + eng.name + ".name", { 
            defaultValue: eng.name.replace(/_/g, " ").toUpperCase() 
        });

        card.innerHTML = `
            <div class="engine-card-header">
                <button type="button" class="engine-card-name">${esc(displayName)}</button>
                <label class="toggle-switch">
                    <input type="checkbox" ${eng.enabled ? 'checked' : ''} ${editable(eng) ? '' : 'disabled'} data-engine="${esc(eng.name)}" aria-label="${esc(displayName + ' · ' + tr('toggle'))}" />
                    <span class="toggle-slider"></span>
                </label>
            </div>
        `;
        
        const checkbox = card.querySelector('input[type="checkbox"]');
        checkbox.addEventListener("change", (e) => {
            e.stopPropagation();
            toggleEngine(eng.name, e.target.checked);
        });

        card.addEventListener("click", () => {
            selectedEngine = eng.name;
            container.querySelectorAll('.engine-card').forEach(node => node.classList.toggle('selected', node === card));
            renderEngineDetail(eng);
        });
        container.appendChild(card);
    });
}

async function toggleEngine(name, enabled) {
    await changeEngine(name, 'toggle', {enabled}, 'PATCH');
}

async function changeEngine(name, operation, updates, method) {
    const eng = enginesData.find(engine => engine.name === name);
    if (!eng || !editable(eng)) return;
    const epoch = sessionEpoch;
    const token = getAuthToken();
    const current = () => epoch === sessionEpoch && token === getAuthToken();
    const requestId = newRequestId();
    const body = remoteControl ? {request_id: requestId, base_version: eng.base_version,
        ...(operation === 'toggle' ? updates : {config: updates})} : updates;
    busy = true;
    notice('pending');
    render();
    try {
        const resp = await authFetch(`/api/engines/${encodeURIComponent(name)}/${operation}`, {
            method, body: JSON.stringify(body)
        });
        if (!current()) return;
        if (!resp || resp.status >= 500) throw new Error('Unconfirmed result');
        if (!resp.ok) {
            needsRefresh = true;
            notice('rejected');
            return;
        }
        const result = await resp.json();
        if (!current()) return;
        if (remoteControl && (result.status !== 'applied' || result.request_id !== requestId
                || result.engine?.name !== name || !/^[a-f0-9]{64}$/.test(result.base_version))) {
            throw new Error('Unconfirmed result');
        }
        busy = false;
        if (await loadEngines({ fresh: true })) {
            if (current()) {
                notice('saved');
                showToast(tr('title'), tr('saved'), 'info');
            }
        }
    } catch (e) {
        if (!current()) return;
        needsRefresh = true;
        notice('unknown');
    } finally {
        if (current()) {
            busy = false;
            render();
        }
    }
}

function renderEngineDetail(eng) {
    document.querySelectorAll('.engine-tooltip').forEach(node => node.remove());
    const container = document.getElementById("engine-detail");
    if (!container) return;
    
    const displayName = window.i18next.t("engines." + eng.name + ".name", { 
        defaultValue: eng.name.replace(/_/g, " ").toUpperCase() 
    });
    
    const description = eng.description_key ? window.i18next.t(eng.description_key, { defaultValue: eng.description }) : eng.description;
    const schemaList = Array.isArray(eng.schema) ? eng.schema : [];
    const config = eng.config || {};
    const disabled = editable(eng) ? '' : 'disabled';

    const state = busy ? 'pending_state' : needsRefresh ? 'unknown_state' : eng.enabled ? 'enabled' : 'disabled';
    let html = `<div class="engine-detail-heading"><h3>${esc(displayName)}</h3><span class="engine-state" data-engine-state>${esc(tr(state))}</span></div>`;
    if (description) html += `<p class="engine-desc">${esc(description)}</p>`;
    if (eng.configuration_available === false) html += `<p>${esc(tr('unconfigured'))}</p>`;
    
    html += `<form id="engine-config-form">`;
    schemaList.forEach(field => {
        if (field.key === "enabled") return;
        const label = field.label_key ? window.i18next.t(field.label_key, { defaultValue: field.label }) : field.label;
        const desc  = field.description_key ? window.i18next.t(field.description_key, { defaultValue: field.description }) : field.description;
        const val   = config[field.key] !== undefined ? config[field.key] : field.default;
        const metaParts = [];
        if (field.type) metaParts.push(`type: ${field.type}`);
        if (field.min != null) metaParts.push(`min: ${field.min}`);
        if (field.max != null) metaParts.push(`max: ${field.max}`);
        const meta = metaParts.join(' · ');

        const tipIcon = desc
            ? `<span class="engine-tooltip-icon" data-tt-desc="${esc(desc)}" data-tt-key="${esc(field.key)}" data-tt-meta="${esc(meta)}">?</span>`
            : '';

        html += `<div class="form-group">
            <label for="engine-field-${esc(field.key)}" style="display:flex;align-items:center;gap:6px">${esc(label)} <small style="color:var(--text-dim)">(${esc(field.key)})</small>${tipIcon}</label>`;

        if (field.type === "bool") {
            html += `<select id="engine-field-${esc(field.key)}" name="${esc(field.key)}" class="input-search" ${disabled}>
                <option value="true" ${val === true ? 'selected' : ''}>${esc(tr('yes'))}</option>
                <option value="false" ${val === false ? 'selected' : ''}>${esc(tr('no'))}</option>
            </select>`;
        } else {
            const text = field.type === 'list' ? JSON.stringify(val ?? []) : String(val ?? '');
            html += `<input id="engine-field-${esc(field.key)}" type="text" name="${esc(field.key)}" class="input-search" value="${esc(text)}" ${disabled} />`;
        }
        html += `</div>`;
    });

    html += `<button type="submit" class="btn btn-accent" style="width:100%;margin-top:10px" ${disabled}>${esc(tr('save'))}</button></form>`;
    container.innerHTML = html;

    // 툴팁 hover 핸들러
    let _activeTip = null;
    container.querySelectorAll('.engine-tooltip-icon').forEach(icon => {
        icon.addEventListener('mouseenter', () => {
            if (_activeTip) _activeTip.remove();
            const tip = document.createElement('div');
            tip.className = 'engine-tooltip';
            tip.innerHTML =
                `<div class="tt-key">${esc(icon.dataset.ttKey)}</div>` +
                (icon.dataset.ttMeta ? `<div class="tt-meta">${esc(icon.dataset.ttMeta)}</div>` : '') +
                `<div class="tt-desc">${esc(icon.dataset.ttDesc)}</div>`;
            document.body.appendChild(tip);
            _activeTip = tip;
            const r = icon.getBoundingClientRect();
            const tipW = Math.min(380, window.innerWidth - 16);
            const left = Math.max(8, Math.min(r.left, window.innerWidth - tipW - 8));
            tip.style.cssText = `position:fixed;left:${left}px;top:${r.bottom + 6}px;max-width:${tipW}px`;
        });
        icon.addEventListener('mouseleave', () => {
            if (_activeTip) { _activeTip.remove(); _activeTip = null; }
        });
    });

    document.getElementById("engine-config-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const updates = {};
        try { schemaList.forEach(field => {
            if (field.key === "enabled") return;
            let val = formData.get(field.key);
            if (field.type === "int" || field.type === "float") {
                if (!val.trim()) throw new Error('Empty number');
                val = Number(val);
                if (!Number.isFinite(val) || (field.type === 'int' && !Number.isSafeInteger(val))) throw new Error('Invalid number');
            }
            else if (field.type === "bool") val = (val === "true");
            else if (field.type === 'list') {
                val = JSON.parse(val);
                if (!Array.isArray(val)) throw new Error('Invalid list');
            }
            updates[field.key] = val;
        }); } catch (error) {
            notice('invalid');
            return;
        }
        saveEngineConfig(eng.name, updates);
    });
}

async function saveEngineConfig(name, updates) {
    await changeEngine(name, 'config', updates, 'PUT');
}

window.addEventListener('nw-session-ended', () => {
    sessionEpoch++;
    loadAttempt++;
    inflight = null;
    enginesData = [];
    selectedEngine = null;
    busy = false;
    needsRefresh = true;
    remoteControl = false;
    const filter = document.getElementById('filter-engine');
    if (filter) while (filter.options.length > 1) filter.remove(1);
    notice('');
    render();
});

// 거절·응답 유실 뒤의 수동 새로고침은 진행 중인 예전 조회를 재사용하면 안 된다.
// 변경이 적용되기 전에 시작한 조회가 그대로 공유되면 needsRefresh가 다시 내려가
// 같은 오래된 base_version으로 재시도할 수 있다.
document.getElementById('engine-control-refresh')?.addEventListener('click', () => loadEngines({ fresh: true }));

export async function populateEngineFilter() {
    const epoch = sessionEpoch;
    const token = getAuthToken();
    const filter = document.getElementById("filter-engine");
    if (!filter) return;
    try {
        const data = await fetchEngineList();
        if (epoch !== sessionEpoch || token !== getAuthToken() || !Array.isArray(data.engines)) return;
        while (filter.options.length > 1) filter.remove(1);
        data.engines.forEach(eng => {
            const opt = document.createElement("option");
            opt.value = eng.name;
            opt.textContent = window.i18next.t("engines." + eng.name + ".name", { defaultValue: eng.name });
            filter.appendChild(opt);
        });
    } catch (error) {
        if (epoch !== sessionEpoch || token !== getAuthToken()) return;
        while (filter.options.length > 1) filter.remove(1);
        console.warn('Engine filter unavailable', error);
    }
}
