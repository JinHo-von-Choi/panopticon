/**
 * NetWatcher Hunting Drawer
 *
 * IP·도메인을 클릭했을 때 우측에서 열리는 조사 패널. 별도 탭을 만들지 않고
 * 이벤트·인시던트·디바이스 화면의 맥락에서 바로 진입한다.
 *
 * IOC 상관 결과와 엔티티 타임라인만 노출한다. MITRE Navigator 레이어와
 * 커버리지 갭은 일일 운영 행동으로 이어지지 않아 여기에 넣지 않는다.
 */

import { authFetch } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';

let drawerEl = null;

function ensureDrawer() {
    if (drawerEl) return drawerEl;

    drawerEl = document.createElement("aside");
    drawerEl.id = "hunt-drawer";
    drawerEl.className = "hunt-drawer hidden";
    drawerEl.innerHTML = `
        <div class="hunt-drawer-head">
            <span class="hunt-drawer-title" id="hunt-drawer-title"></span>
            <button class="modal-close" id="hunt-drawer-close">&times;</button>
        </div>
        <div class="hunt-drawer-body" id="hunt-drawer-body"></div>
    `;
    document.body.appendChild(drawerEl);

    drawerEl.querySelector("#hunt-drawer-close").addEventListener("click", closeHuntDrawer);
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeHuntDrawer();
    });
    return drawerEl;
}

export function closeHuntDrawer() {
    if (drawerEl) drawerEl.classList.add("hidden");
}

/**
 * 엔티티 조사 패널을 연다.
 * @param {"ip"|"domain"} type
 * @param {string} value
 */
export async function openHuntDrawer(type, value) {
    const el    = ensureDrawer();
    const title = el.querySelector("#hunt-drawer-title");
    const body  = el.querySelector("#hunt-drawer-body");

    title.textContent = `${type.toUpperCase()} · ${value}`;
    body.innerHTML = `<div class="empty-state">조회 중…</div>`;
    el.classList.remove("hidden");

    const [ioc, timeline] = await Promise.all([
        fetchJson(`/api/hunting/ioc/${encodeURIComponent(type)}/${encodeURIComponent(value)}`),
        fetchJson(`/api/hunting/timeline/${encodeURIComponent(type)}/${encodeURIComponent(value)}?hours=24`),
    ]);

    body.innerHTML = renderSummary(ioc) + renderTimeline(timeline);
}

async function fetchJson(url) {
    try {
        const resp = await authFetch(url);
        if (!resp || !resp.ok) return null;
        return await resp.json();
    } catch (e) {
        console.error("Hunt query failed", url, e);
        return null;
    }
}

function renderSummary(ioc) {
    if (!ioc) {
        return `<div class="empty-state">상관 정보를 가져오지 못했습니다.</div>`;
    }

    const rows = [
        ["최초 관측", ioc.first_seen ? formatTime(ioc.first_seen) : "-"],
        ["최근 관측", ioc.last_seen ? formatTime(ioc.last_seen) : "-"],
        ["이벤트 수", ioc.event_count ?? 0],
        ["최고 심각도", ioc.severity_max || "-"],
        ["관련 IP", (ioc.related_ips || []).length],
        ["관련 도메인", (ioc.related_domains || []).length],
    ];

    const engines = (ioc.engines_triggered || [])
        .map(e => `<span class="type-tag">${esc(e)}</span>`).join(" ") || "-";

    return `
        <h4>요약</h4>
        <table class="hunt-summary">
            ${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(String(v))}</td></tr>`).join("")}
        </table>
        <h4>탐지 엔진</h4>
        <div>${engines}</div>
    `;
}

function renderTimeline(entries) {
    if (!Array.isArray(entries) || !entries.length) {
        return `<h4>타임라인 (24h)</h4><div class="empty-state">기록된 활동이 없습니다.</div>`;
    }

    return `
        <h4>타임라인 (24h)</h4>
        <ul class="hunt-timeline">
            ${entries.map(e => `
                <li class="hunt-timeline-item sev-${esc(e.severity)}">
                    <span class="hunt-time">${esc(formatTime(e.timestamp))}</span>
                    <span class="severity-badge severity-${esc(e.severity)}">${esc(e.severity)}</span>
                    <span class="hunt-engine">${esc(e.engine)}</span>
                    <div class="hunt-desc">${esc(e.description || e.event_type || "")}</div>
                </li>
            `).join("")}
        </ul>
    `;
}

/**
 * 문서 전역에서 data-hunt-ip / data-hunt-domain 요소 클릭을 받아 드로어를 연다.
 * 동적으로 렌더되는 테이블에도 적용되도록 이벤트 위임을 사용한다.
 */
export function registerHuntListeners() {
    document.addEventListener("click", (e) => {
        const ipEl = e.target.closest("[data-hunt-ip]");
        if (ipEl) {
            e.preventDefault();
            openHuntDrawer("ip", ipEl.dataset.huntIp);
            return;
        }
        const domainEl = e.target.closest("[data-hunt-domain]");
        if (domainEl) {
            e.preventDefault();
            openHuntDrawer("domain", domainEl.dataset.huntDomain);
        }
    });
}
