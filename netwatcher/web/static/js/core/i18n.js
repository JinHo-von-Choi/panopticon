/**
 * NetWatcher Dashboard i18n
 */

import { isAuthEnabled } from './api.js';

export async function initI18n(onLangChange) {
    var currentLang = localStorage.getItem("nw_lang") || "ko";
    
    // 가능한 모든 전역 객체명 시도
    const backend = window.i18nextHttpBackend || window.i18nextBackend || window.I18nextHttpBackend;
    
    if (!backend) {
        console.error("i18next-http-backend not found! Fallback to local resources.");
        await window.i18next.init({
            lng: currentLang,
            fallbackLng: "en"
        });
    } else {
        await window.i18next
            .use(backend)
            .init({
                lng: currentLang,
                fallbackLng: "en",
                backend: {
                    loadPath: "/locales/{{lng}}/translation.json"
                }
            });
    }
    
    var langSelector = document.getElementById("lang-selector");
    if (langSelector) {
        langSelector.value = currentLang;
        langSelector.addEventListener("change", function () {
            var newLang = this.value;
            localStorage.setItem("nw_lang", newLang);
            window.i18next.changeLanguage(newLang).then(function () {
                updateContent();
                if (onLangChange) onLangChange(newLang);
            });
        });
    }

    updateContent();
}

export function updateContent() {
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
        var key = el.getAttribute("data-i18n");
        var options = el.getAttribute("data-i18n-options");
        if (options) {
            try {
                options = JSON.parse(options);
            } catch (e) {
                options = {};
            }
        } else {
            options = {};
        }
        
        if (el.tagName === "INPUT" && el.getAttribute("placeholder")) {
            el.placeholder = window.i18next.t(key, options);
        } else if (el.hasAttribute("title")) {
            el.title = window.i18next.t(key, options);
        } else {
            el.textContent = window.i18next.t(key, options);
        }
    });
}
