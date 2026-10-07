/** 사건 문맥 패널의 키보드 탐색·초점 복원. */
let opener = null;
let overflow = '';

export function openEventDrawer() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay.classList.contains('hidden')) {
        opener = document.activeElement;
        overflow = document.body.style.overflow;
    }
    overlay.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    document.querySelector('main').inert = true;
    document.querySelector('header').inert = true;
    document.getElementById('modal-close-btn').focus();
}

export function closeEventDrawer() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay.classList.contains('hidden')) return;
    overlay.classList.add('hidden');
    document.body.style.overflow = overflow;
    document.querySelector('main').inert = false;
    document.querySelector('header').inert = false;
    if (opener?.isConnected) opener.focus();
    opener = null;
}

document.addEventListener('keydown', event => {
    const overlay = document.getElementById('modal-overlay');
    if (!overlay || overlay.classList.contains('hidden') || document.querySelector('dialog[open]')) return;
    if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        closeEventDrawer();
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
