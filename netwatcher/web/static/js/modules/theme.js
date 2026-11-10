/**
 * 테마 컨트롤러 — Operator / Auditor
 *
 * 테마는 `html[data-theme]` 속성 하나로 표현한다. 선택은 localStorage에 저장하고,
 * 알 수 없는 값은 Operator로 되돌린다.
 */

import { esc } from '../core/utils.js';

const THEMES = ['operator', 'auditor'];
const DEFAULT_THEME = 'operator';
const STORAGE_KEY = 'nw_theme';
const root = document.documentElement;

export function currentTheme() {
    return THEMES.includes(root.dataset.theme) ? root.dataset.theme : DEFAULT_THEME;
}

export function setTheme(theme, persist = true) {
    const next = THEMES.includes(theme) ? theme : DEFAULT_THEME;
    root.dataset.theme = next;
    if (persist) {
        try {
            localStorage.setItem(STORAGE_KEY, next);
        } catch {
            /* 저장 실패 시에도 현재 세션 테마는 그대로 적용된다. */
        }
    }
    return next;
}

export function initTheme() {
    const selector = document.getElementById('theme-selector');
    if (selector) {
        selector.value = currentTheme();
        selector.addEventListener('change', event => setTheme(event.target.value));
    }
    return { theme: currentTheme() };
}

/**
 * 3중 인코딩 뱃지 마크업 헬퍼.
 * 색상만으로 상태를 전달하지 않는다 — 텍스트 라벨을 반드시 포함한다.
 */
export function severityBadge(level, label) {
    const key = ['critical', 'high', 'warning', 'info', 'ok', 'unknown'].includes(level) ? level : 'unknown';
    return `<span class="badge badge-sev badge-sev-${key}">${esc(label ?? key.toUpperCase())}</span>`;
}
