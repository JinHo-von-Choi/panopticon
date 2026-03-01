/**
 * NetWatcher Engines Module (Production Grade - No Omissions)
 */

import { authFetch } from '../core/api.js';
import { esc, showToast } from '../core/utils.js';

var enginesData = [];

export async function loadEngines() {
    try {
        const resp = await authFetch("/api/engines");
        if (!resp || !resp.ok) return;
        const data = await resp.json();
        enginesData = data.engines;
        renderEnginesList();
    } catch (e) { console.error("Failed to load engines", e); }
}

export function renderEnginesList() {
    const container = document.getElementById("engines-list");
    if (!container) return;
    
    container.innerHTML = "";
    enginesData.forEach(eng => {
        const card = document.createElement("div");
        card.className = "engine-card" + (eng.enabled ? "" : " disabled");
        
        const displayName = window.i18next.t("engines." + eng.name + ".name", { 
            defaultValue: eng.name.replace(/_/g, " ").toUpperCase() 
        });

        card.innerHTML = `
            <div class="engine-card-header">
                <span class="engine-card-name">${esc(displayName)}</span>
                <label class="toggle-switch">
                    <input type="checkbox" ${eng.enabled ? 'checked' : ''} data-engine="${esc(eng.name)}" />
                    <span class="toggle-slider"></span>
                </label>
            </div>
        `;
        
        const checkbox = card.querySelector('input[type="checkbox"]');
        checkbox.addEventListener("change", (e) => {
            e.stopPropagation();
            toggleEngine(eng.name, e.target.checked);
        });

        card.addEventListener("click", () => renderEngineDetail(eng));
        container.appendChild(card);
    });
}

async function toggleEngine(name, enabled) {
    try {
        const resp = await authFetch(`/api/engines/${name}/toggle`, {
            method: "PATCH",
            body: JSON.stringify({ enabled: enabled })
        });
        if (resp.ok) {
            showToast("Engine Updated", `${name} is now ${enabled ? 'enabled' : 'disabled'}`, "info");
            loadEngines();
        }
    } catch (e) { showToast("Error", "Failed to toggle engine", "critical"); }
}

function renderEngineDetail(eng) {
    const container = document.getElementById("engine-detail");
    if (!container) return;
    
    const displayName = window.i18next.t("engines." + eng.name + ".name", { 
        defaultValue: eng.name.replace(/_/g, " ").toUpperCase() 
    });
    
    const description = eng.description_key ? window.i18next.t(eng.description_key, { defaultValue: eng.description }) : eng.description;
    const schemaList = Array.isArray(eng.schema) ? eng.schema : [];
    const config = eng.config || {};

    let html = `<h3>${esc(displayName)}</h3>`;
    if (description) html += `<p class="engine-desc">${esc(description)}</p>`;
    
    html += `<form id="engine-config-form">`;
    schemaList.forEach(field => {
        if (field.key === "enabled") return;
        const label = field.label_key ? window.i18next.t(field.label_key, { defaultValue: field.label }) : field.label;
        const desc  = field.description_key ? window.i18next.t(field.description_key, { defaultValue: field.description }) : field.description;
        const val   = config[field.key] !== undefined ? config[field.key] : field.default;
        const metaParts = [];
        if (field.type) metaParts.push(`type: ${field.type}`);
        if (field.min !== undefined) metaParts.push(`min: ${field.min}`);
        if (field.max !== undefined) metaParts.push(`max: ${field.max}`);
        const meta = metaParts.join(' · ');

        const tipIcon = desc
            ? `<span class="engine-tooltip-icon" data-tt-desc="${esc(desc)}" data-tt-key="${esc(field.key)}" data-tt-meta="${esc(meta)}">?</span>`
            : '';

        html += `<div class="form-group">
            <label style="display:flex;align-items:center;gap:6px">${esc(label)} <small style="color:var(--text-dim)">(${field.key})</small>${tipIcon}</label>`;

        if (field.type === "bool") {
            html += `<select name="${field.key}" class="input-search">
                <option value="true" ${val === true ? 'selected' : ''}>True</option>
                <option value="false" ${val === false ? 'selected' : ''}>False</option>
            </select>`;
        } else {
            html += `<input type="text" name="${field.key}" class="input-search" value="${esc(val.toString())}" />`;
        }
        html += `</div>`;
    });

    html += `<button type="submit" class="btn btn-accent" style="width:100%;margin-top:10px">Save Configuration</button></form>`;
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
        schemaList.forEach(field => {
            if (field.key === "enabled") return;
            let val = formData.get(field.key);
            if (field.type === "int") val = parseInt(val, 10);
            else if (field.type === "float") val = parseFloat(val);
            else if (field.type === "bool") val = (val === "true");
            updates[field.key] = val;
        });
        saveEngineConfig(eng.name, updates);
    });
}

async function saveEngineConfig(name, updates) {
    try {
        const resp = await authFetch(`/api/engines/${name}/config`, {
            method: "PUT",
            body: JSON.stringify(updates)
        });
        if (resp.ok) {
            showToast("Success", "Engine configuration saved and reloaded", "info");
            loadEngines();
        }
    } catch (e) { showToast("Error", "Failed to save configuration", "critical"); }
}

export async function populateEngineFilter() {
    const filter = document.getElementById("filter-engine");
    if (!filter) return;
    try {
        const resp = await authFetch("/api/engines");
        const data = await resp.json();
        while (filter.options.length > 1) filter.remove(1);
        data.engines.forEach(eng => {
            const opt = document.createElement("option");
            opt.value = eng.name;
            opt.textContent = window.i18next.t("engines." + eng.name + ".name", { defaultValue: eng.name });
            filter.appendChild(opt);
        });
    } catch (e) {}
}
