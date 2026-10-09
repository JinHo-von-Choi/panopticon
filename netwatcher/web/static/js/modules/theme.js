/**
 * Tri-Theme 컨트롤러 — Operator / Auditor / Cinematic
 *
 * 계약
 * - 테마는 `html[data-theme]` 속성 하나로 표현한다. CSS 쪽 선택자는
 *   css/themes.css 의 `:root` / `html[data-theme="..."]` 뿐이다.
 * - Cinematic의 스캔라인·사운드는 기본 OFF이며, 헤더 체크박스를 통해
 *   사용자가 명시적으로 켤 때만 `data-hud-*` 속성이 붙는다.
 * - 선택은 localStorage에 저장하며, 알 수 없는 값은 Operator로 되돌린다.
 * - 사운드는 사용자 제스처(체크박스 클릭) 안에서만 WebAudio를 만든다.
 *   브라우저 자동재생 정책 때문에 초기 로드 시에는 절대 소리를 내지 않는다.
 */

import { esc } from '../core/utils.js';

const THEMES = ['operator', 'auditor', 'cinematic'];
const DEFAULT_THEME = 'operator';
const STORAGE_KEY = 'nw_theme';
const FX_KEY = 'nw_hud_fx';

/** css/themes.css 의 스캔라인 토큰이 읽는 유일한 속성 */
const root = document.documentElement;

function readStored() {
    try {
        return localStorage.getItem(STORAGE_KEY);
    } catch {
        return null;
    }
}

/**
 * 첫 페인트 전에 인라인 스크립트가 호출하는 진입점.
 * css 로드 뒤 모듈 로드 전 화면이 깜빡이는 것을 막는다.
 */
export function applyStoredTheme() {
    const stored = readStored();
    const theme = THEMES.includes(stored) ? stored : DEFAULT_THEME;
    root.dataset.theme = theme;
    let fx = {};
    try {
        fx = JSON.parse(localStorage.getItem(FX_KEY) || '{}') || {};
    } catch {
        fx = {};
    }
    syncFxFlags(fx);
    return theme;
}

function syncFxFlags(fx) {
    // 장식은 Cinematic 에서만 의미가 있다. 다른 테마로 전환하면 즉시 해제한다.
    const on = root.dataset.theme === 'cinematic';
    const scanlines = on && fx.scanlines === true;
    const sound = on && fx.sound === true;
    if (scanlines) root.dataset.hudScanlines = 'on';
    else delete root.dataset.hudScanlines;
    if (sound) root.dataset.hudSound = 'on';
    else delete root.dataset.hudSound;
    const state = document.getElementById('hud-sound-state');
    if (state) state.textContent = sound ? 'ON' : 'OFF';
    return { scanlines, sound };
}

export function currentTheme() {
    return THEMES.includes(root.dataset.theme) ? root.dataset.theme : DEFAULT_THEME;
}

export function setTheme(theme, persist = true) {
    const next = THEMES.includes(theme) ? theme : DEFAULT_THEME;
    root.dataset.theme = next;
    let fx = {};
    try {
        fx = JSON.parse(localStorage.getItem(FX_KEY) || '{}') || {};
    } catch {
        fx = {};
    }
    const applied = syncFxFlags(fx);
    if (persist) {
        try {
            localStorage.setItem(STORAGE_KEY, next);
        } catch {
            /* 저장 실패 시에도 현재 세션 테마는 그대로 적용된다. */
        }
    }
    // 체크박스 UI를 실제 상태에 맞춰 동기화한다(테마 전환으로 강제 해제된 경우).
    const scanlineToggle = document.getElementById('hud-scanlines-toggle');
    if (scanlineToggle) scanlineToggle.checked = applied.scanlines;
    const soundToggle = document.getElementById('hud-sound-toggle');
    if (soundToggle) soundToggle.checked = applied.sound;
    return next;
}

function setFx(key, value) {
    let fx = {};
    try {
        fx = JSON.parse(localStorage.getItem(FX_KEY) || '{}') || {};
    } catch {
        fx = {};
    }
    fx[key] = value;
    try {
        localStorage.setItem(FX_KEY, JSON.stringify(fx));
    } catch {
        /* 저장 실패는 장식 유지 여부에 영향을 주지 않는다. */
    }
    return syncFxFlags(fx);
}

/* --------------------------------------------------------------------------
   사운드 — 선택 사항이며 기본 OFF.
   WebAudio 오실레이터로 짧은 HUD 클릭음을 만든다. 파일 에셋이 없어 콘솔
   로딩에 실패할 여지도 없다. 사용자가 토글하기 전에는 아무것도 생성하지 않는다.
   ------------------------------------------------------------------------ */
let audioContext = null;

function playHudBlip() {
    if (root.dataset.hudSound !== 'on') return;
    try {
        const Ctx = window.AudioContext || window.webkitAudioContext;
        if (!Ctx) return;
        if (!audioContext) audioContext = new Ctx();
        if (audioContext.state === 'suspended') audioContext.resume();
        const now = audioContext.currentTime;
        const osc = audioContext.createOscillator();
        const gain = audioContext.createGain();
        osc.type = 'square';
        osc.frequency.value = 880;
        gain.gain.setValueAtTime(0.0001, now);
        gain.gain.exponentialRampToValueAtTime(0.06, now + 0.01);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.09);
        osc.connect(gain).connect(audioContext.destination);
        osc.start(now);
        osc.stop(now + 0.1);
    } catch {
        /* 오디오는 부가 기능이다. 실패해도 콘솔 기능에는 영향이 없다. */
    }
}

/** 테스트·검증용: 상태 스냅샷 */
export function themeState() {
    return {
        theme: currentTheme(),
        scanlines: root.dataset.hudScanlines === 'on',
        sound: root.dataset.hudSound === 'on',
    };
}

export function initTheme() {
    const selector = document.getElementById('theme-selector');
    if (selector) {
        selector.value = currentTheme();
        selector.addEventListener('change', event => {
            setTheme(event.target.value);
        });
    }

    const scanlineToggle = document.getElementById('hud-scanlines-toggle');
    if (scanlineToggle) {
        scanlineToggle.checked = root.dataset.hudScanlines === 'on';
        scanlineToggle.addEventListener('change', event => {
            const applied = setFx('scanlines', event.target.checked);
            event.target.checked = applied.scanlines;
        });
    }

    const soundToggle = document.getElementById('hud-sound-toggle');
    if (soundToggle) {
        soundToggle.checked = root.dataset.hudSound === 'on';
        soundToggle.addEventListener('change', event => {
            // 사용자 제스처 핸들러 안에서만 오디오 컨텍스트를 만든다.
            const applied = setFx('sound', event.target.checked);
            event.target.checked = applied.sound;
            if (applied.sound) playHudBlip();
        });
    }

    const state = document.getElementById('hud-sound-state');
    if (state) {
        state.removeAttribute('data-i18n');
        state.textContent = root.dataset.hudSound === 'on' ? 'ON' : 'OFF';
    }

    return themeState();
}

/**
 * 3중 인코딩 뱃지 마크업 헬퍼.
 * 색상만으로 상태를 전달하지 않는다 — 텍스트 라벨을 반드시 포함한다.
 */
export function severityBadge(level, label) {
    const key = ['critical', 'high', 'warning', 'info', 'ok', 'unknown'].includes(level) ? level : 'unknown';
    return `<span class="badge badge-sev badge-sev-${key}">${esc(label ?? key.toUpperCase())}</span>`;
}