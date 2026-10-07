import { authFetch } from '../core/api.js';
import { closeEventDrawer } from '../core/detail-drawer.js';

const t = key => window.i18next?.t(`console.${key}`) || key;
let palette;
let returnFocus;

export async function loadConsoleState() {
    if (document.hidden) return;
    const box = document.getElementById('console-readiness');
    const label = document.getElementById('console-ready-label');
    const reason = document.getElementById('console-ready-reason');
    if (!box) return;
    // 동적 상태를 언어 전환 시 초기 unknown 문구로 덮어쓰지 않는다.
    label.removeAttribute('data-i18n');
    reason.removeAttribute('data-i18n');
    try {
        const response = await authFetch('/api/health');
        if (!response.ok) throw new Error('state unavailable');
        const data = await response.json();
        if (typeof data.ready !== 'boolean') throw new Error('invalid state');
        const state = data.ready ? 'ready' : 'not_ready';
        box.dataset.state = state;
        label.textContent = t(state);
        const components = data.components || {};
        const checks = [['database', 'db_unavailable'], ['sniffer', 'sensor_unavailable'],
                        ['engines', 'engines_unavailable'], ['alert_queue', 'queue_unavailable']];
        if (components.stats_flush) checks.push(['stats_flush', 'stats_unavailable']);
        const failed = checks.find(([name]) => components[name]?.status !== 'healthy');
        reason.textContent = data.ready ? t('ready_reason') : failed ? t(failed[1]) :
            components.observation?.reasons?.[0] || t('observation_unavailable');
    } catch {
        box.dataset.state = 'unknown';
        label.textContent = t('unknown');
        reason.textContent = t('state_unavailable');
    }
}

function screens() {
    return [...document.querySelectorAll('.tab[data-tab]')]
        .filter(button => getComputedStyle(button).display !== 'none');
}

function renderScreens() {
    const list = palette.querySelector('.console-palette-list');
    const query = palette.querySelector('input').value.trim().toLocaleLowerCase();
    list.replaceChildren();
    for (const tab of screens()) {
        const name = tab.textContent.trim();
        if (!name.toLocaleLowerCase().includes(query)) continue;
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = name;
        button.addEventListener('click', () => {
            returnFocus = tab;
            closeEventDrawer();
            palette.close();
            tab.click();
            tab.focus();
        });
        list.append(button);
    }
    if (!list.children.length) {
        const empty = document.createElement('p');
        empty.textContent = t('no_screens');
        list.append(empty);
    }
}

function openPalette() {
    if (!document.getElementById('login-overlay').classList.contains('hidden')) return;
    returnFocus = document.activeElement;
    palette.querySelector('input').value = '';
    renderScreens();
    if (!palette.open) palette.showModal();
    palette.querySelector('input').focus();
}

export function initConsole() {
    document.getElementById('console-readiness')?.addEventListener('click', () => {
        document.querySelector('.tab[data-tab="governance"]')?.click();
    });
    palette = document.createElement('dialog');
    palette.className = 'console-palette';
    palette.setAttribute('aria-labelledby', 'console-palette-title');
    const close = document.createElement('button');
    close.className = 'btn console-palette-close';
    close.type = 'button';
    close.dataset.i18n = 'console.close';
    close.textContent = 'Close';
    close.addEventListener('click', () => palette.close());
    const heading = document.createElement('h2');
    heading.id = 'console-palette-title';
    heading.dataset.i18n = 'console.navigate';
    heading.textContent = 'Navigate';
    const input = document.createElement('input');
    input.className = 'input-search';
    input.placeholder = 'Find a screen';
    input.dataset.i18n = 'console.find_screen';
    input.setAttribute('aria-labelledby', heading.id);
    input.addEventListener('input', renderScreens);
    input.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            palette.querySelector('.console-palette-list button')?.focus();
        }
    });
    const list = document.createElement('div');
    list.className = 'console-palette-list';
    palette.append(close, heading, input, list);
    document.body.append(palette);
    palette.addEventListener('close', () => returnFocus?.focus());
    document.getElementById('console-search')?.addEventListener('click', openPalette);
    document.addEventListener('keydown', event => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            openPalette();
        }
        if (palette.open && event.key === 'Escape') event.stopImmediatePropagation();
    }, { capture: true });
}
