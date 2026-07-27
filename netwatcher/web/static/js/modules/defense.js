/**
 * NetWatcher Defense Module
 *
 * 능동 방어 표면을 한곳에 모은다.
 *  - Active Blocks: 방화벽에 실제로 적용 중인 IP 차단
 *  - Signature Rules: 시그니처 규칙 활성화/재적재
 *
 * 탐지 매칭용 Blocklist와 실제 차단인 Blocks는 별개다. 두 개념을 섞지 않는다.
 */

import { authFetch } from '../core/api.js';
import { esc, formatTime, showToast } from '../core/utils.js';

let blocks = [];
let rules  = [];

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

export async function loadRules() {
    const body  = document.getElementById("rules-body");
    const count = document.getElementById("rules-count");
    if (!body) return;

    try {
        const resp = await authFetch("/api/rules");
        if (!resp || !resp.ok) {
            body.innerHTML = `<tr><td colspan="5" class="empty-state" data-i18n="defense.rules_unavailable">시그니처 엔진이 비활성 상태입니다.</td></tr>`;
            if (count) count.textContent = "-";
            return;
        }
        const data = await resp.json();
        rules = data.rules || [];
        if (count) count.textContent = rules.length;

        if (!rules.length) {
            body.innerHTML = `<tr><td colspan="5" class="empty-state" data-i18n="defense.no_rules">로드된 규칙이 없습니다.</td></tr>`;
            return;
        }

        body.innerHTML = rules.map(r => `
            <tr>
                <td class="mono"><code>${esc(r.id)}</code></td>
                <td>${esc(r.name)}</td>
                <td><span class="severity-badge severity-${esc(r.severity)}">${esc(r.severity)}</span></td>
                <td>${esc(r.protocol || "any")}</td>
                <td>
                    <label class="toolbar-check">
                        <input type="checkbox" data-rule-toggle="${esc(r.id)}" ${r.enabled ? "checked" : ""} />
                        <span>${r.enabled ? "enabled" : "disabled"}</span>
                    </label>
                </td>
            </tr>
        `).join("");

        body.querySelectorAll("[data-rule-toggle]").forEach(el => {
            el.addEventListener("change", () => toggleRule(el.dataset.ruleToggle, el.checked));
        });
    } catch (e) {
        console.error("Failed to load rules", e);
    }
}

async function toggleRule(ruleId, enabled) {
    try {
        const resp = await authFetch(`/api/rules/${encodeURIComponent(ruleId)}/toggle`, {
            method: "PUT",
            body: JSON.stringify({ enabled }),
        });
        if (!resp || !resp.ok) {
            showToast("Rules", `${ruleId} 상태 변경 실패`, "CRITICAL");
        }
        await loadRules();
    } catch (e) {
        console.error("Failed to toggle rule", e);
    }
}

async function reloadRules() {
    try {
        const resp = await authFetch("/api/rules/reload", { method: "POST" });
        if (resp && resp.ok) {
            showToast("Rules", "규칙을 다시 읽었습니다", "INFO");
            await loadRules();
        } else {
            showToast("Rules", "규칙 재적재 실패", "CRITICAL");
        }
    } catch (e) {
        console.error("Failed to reload rules", e);
    }
}

export function loadDefense() {
    loadBlocks();
    loadRules();
}

export function registerDefenseListeners() {
    document.getElementById("btn-add-block")?.addEventListener("click", addBlock);
    document.getElementById("btn-blocks-refresh")?.addEventListener("click", loadBlocks);
    document.getElementById("btn-rules-reload")?.addEventListener("click", reloadRules);
}
