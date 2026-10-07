/** 사건·자산 패널의 키보드 탐색·초점 복원. */
let opener = null;
let openerSelector = null;
let overflow = '';
let activeOverlay = null;

function openDrawer(id, closeId) {
    const overlay = document.getElementById(id);
    if (activeOverlay && activeOverlay !== overlay) closeDrawer(activeOverlay.id);
    if (overlay.classList.contains('hidden')) {
        opener = document.activeElement;
        const device = opener.closest('[data-mac]') || opener.querySelector?.('[data-mac]');
        openerSelector = opener.id ? '#' + CSS.escape(opener.id) : device ? '[data-mac="' + CSS.escape(device.dataset.mac) + '"]' : null;
        overflow = document.body.style.overflow;
    }
    overlay.classList.remove('hidden');
    activeOverlay = overlay;
    document.body.style.overflow = 'hidden';
    document.querySelector('main').inert = true;
    document.querySelector('header').inert = true;
    document.getElementById(closeId).focus();
}

function closeDrawer(id) {
    const overlay = document.getElementById(id);
    if (overlay.classList.contains('hidden')) return;
    overlay.classList.add('hidden');
    if (activeOverlay !== overlay) return;
    activeOverlay = null;
    document.body.style.overflow = overflow;
    document.querySelector('main').inert = false;
    document.querySelector('header').inert = false;
    const target = opener?.isConnected ? opener : openerSelector ? document.querySelector(openerSelector) : null;
    (target || document.querySelector('.tab.active'))?.focus();
    opener = null;
    openerSelector = null;
}

export const openEventDrawer = () => openDrawer('modal-overlay', 'modal-close-btn');
export const closeEventDrawer = () => closeDrawer('modal-overlay');
export const openDeviceDrawer = () => openDrawer('device-modal-overlay', 'device-modal-close-btn');
export const closeDeviceDrawer = () => closeDrawer('device-modal-overlay');

document.addEventListener('keydown', event => {
    const overlay = activeOverlay;
    if (!overlay || overlay.classList.contains('hidden') || document.querySelector('dialog[open]')) return;
    if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        closeDrawer(overlay.id);
    } else if (event.key === 'Tab') {
        const items = [...overlay.querySelectorAll('button, a[href], input, select, textarea, summary, [tabindex="0"]')]
            .filter(item => {
                const closed = item.closest('details:not([open])');
                return !item.disabled && item.getClientRects().length
                    && (!closed || (item.tagName === 'SUMMARY' && item.parentElement === closed));
            });
        const first = items[0], last = items.at(-1);
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault(); last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault(); first?.focus();
        }
    }
}, true);
