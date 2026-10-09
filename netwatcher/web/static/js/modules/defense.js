/**
 * NetWatcher Defense Module
 *
 * 능동 방어 표면을 한곳에 모은다.
 *  - Active Blocks: 방화벽에 실제로 적용 중인 IP 차단
 *  - Signature Rules: 시그니처 규칙 활성화/재적재
 *
 * 탐지 매칭용 Blocklist와 실제 차단인 Blocks는 별개다. 두 개념을 섞지 않는다.
 */

import { authFetch, getAuthToken } from '../core/api.js';
import { loadResponse } from './response.js';
import { esc, formatTime, showToast } from '../core/utils.js';

import {loadRules, registerRulesListeners} from './rules.js';
import {featureEnabled} from '../core/capabilities.js';
export {loadRules} from './rules.js';

let blocks = [];

/* ------------------------------------------------------------------ */
/* Active Blocks                                                       */
/* ------------------------------------------------------------------ */

export async function loadBlocks() {
    const body  = document.getElementById("blocks-body");
    const count = document.getElementById("blocks-count");
    if (!body) return;

    try {
        const resp = await authFetch("/api/blocks");
        if (!resp || !resp.ok) {
            body.innerHTML = `<tr><td colspan="5" class="empty-state" data-i18n="defense.blocks_unavailable">차단 기능이 비활성 상태입니다. config의 response.enabled를 확인하세요.</td></tr>`;
            if (count) count.textContent = "-";
            return;
        }
        const data = await resp.json();
        blocks = data.blocks || [];
        if (count) count.textContent = blocks.length;

        if (!blocks.length) {
            body.innerHTML = `<tr><td colspan="5" class="empty-state" data-i18n="defense.no_blocks">적용 중인 차단이 없습니다.</td></tr>`;
            return;
        }

        body.innerHTML = blocks.map(b => `
            <tr>
                <td class="mono"><code>${esc(b.ip)}</code></td>
                <td>${esc(b.reason || "-")}</td>
                <td class="time">${esc(formatTime(b.created_at))}</td>
                <td class="time">${b.expires_at ? esc(formatTime(b.expires_at)) : "영구"}</td>
                <td><button class="btn-detail" data-unblock="${esc(b.ip)}">Unblock</button></td>
            </tr>
        `).join("");

        body.querySelectorAll("[data-unblock]").forEach(btn => {
            btn.addEventListener("click", () => unblock(btn.dataset.unblock));
        });
    } catch (e) {
        console.error("Failed to load blocks", e);
    }
}

async function unblock(ip) {
    if (!confirm(`${ip} 차단을 해제하시겠습니까?`)) return;
    try {
        const resp = await authFetch(`/api/blocks/${encodeURIComponent(ip)}`, { method: "DELETE" });
        if (resp && resp.ok) {
            showToast("Block", `${ip} 차단 해제됨`, "INFO");
            await loadBlocks();
        } else {
            const err = resp ? await resp.json().catch(() => ({})) : {};
            showToast("Block", err.error || `${ip} 해제 실패`, "CRITICAL");
        }
    } catch (e) {
        console.error("Failed to unblock", e);
    }
}

async function addBlock() {
    const ipEl     = document.getElementById("block-ip");
    const reasonEl = document.getElementById("block-reason");
    const ip       = (ipEl?.value || "").trim();
    if (!ip) return;

    try {
        const resp = await authFetch("/api/blocks", {
            method: "POST",
            body: JSON.stringify({ ip, reason: (reasonEl?.value || "").trim() || "Manual block" }),
        });
        if (resp && resp.ok) {
            showToast("Block", `${ip} 차단됨`, "INFO");
            if (ipEl) ipEl.value = "";
            if (reasonEl) reasonEl.value = "";
            await loadBlocks();
        } else {
            const err = resp ? await resp.json().catch(() => ({})) : {};
            showToast("Block", err.error || `${ip} 차단 실패`, "CRITICAL");
        }
    } catch (e) {
        console.error("Failed to add block", e);
    }
}

/* ------------------------------------------------------------------ */
/* Signature Rules                                                     */
/* ------------------------------------------------------------------ */

let defenseGeneration = 0;
export async function loadDefense() {
    const attempt = ++defenseGeneration;
    const token = getAuthToken();
    const legacy = document.getElementById('defense-legacy');
    const panel = document.getElementById('response-panel');
    if (legacy) legacy.hidden = true;
    const rulePanel = document.getElementById('signature-rules');
    if (rulePanel) rulePanel.hidden = !featureEnabled('rules');
    if (featureEnabled('rules')) loadRules();
    if (!featureEnabled('response')) {
        if (panel) panel.hidden = true;
        if (legacy) legacy.hidden = !featureEnabled('direct_blocks');
        if (featureEnabled('direct_blocks')) loadBlocks();
        return;
    }
    try {
        const response = await authFetch('/api/response/capabilities');
        if (!response?.ok) throw Error('Response capabilities unavailable');
        const capabilities = await response.json();
        if (attempt !== defenseGeneration || token !== getAuthToken()) return;
        if (capabilities?.execution_process === 'separate') {
            await loadResponse();
            return;
        }
    } catch {
        if (attempt !== defenseGeneration || token !== getAuthToken()) return;
        if (panel) {
            panel.hidden = false;
            const message = document.createElement('p');
            message.textContent = window.i18next.t('console.response.unavailable');
            const retry = document.createElement('button');
            retry.type = 'button';
            retry.className = 'btn';
            retry.textContent = window.i18next.t('console.response.refresh');
            retry.addEventListener('click', loadDefense);
            panel.replaceChildren(message, retry);
        }
        return;
    }
    if (panel) panel.hidden = true;
    if (legacy) legacy.hidden = false;
    if (featureEnabled('direct_blocks')) loadBlocks();
}
window.addEventListener('nw-session-ended', () => { defenseGeneration++; });

export function registerDefenseListeners() {
    document.getElementById("btn-add-block")?.addEventListener("click", addBlock);
    document.getElementById("btn-blocks-refresh")?.addEventListener("click", loadBlocks);
    registerRulesListeners();
}
