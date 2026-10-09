/**
 * NetWatcher Dashboard API Client (Robust Version)
 */

let _token = localStorage.getItem("nw_token");
let _authEnabled = false;
let _authRequired = true;
let _currentRole = "viewer";
let _currentUserId = null;

export function setCurrentUserId(id) { _currentUserId = typeof id === 'string' ? id : null; }
export function getCurrentUserId() { return _currentUserId; }

export function setCurrentRole(role) {
    _currentRole = ["viewer", "analyst", "admin"].includes(role) ? role : "viewer";
}

export function canConfigure() { return _currentRole === "admin"; }
export function canAnalyze() { return ["admin", "analyst"].includes(_currentRole); }

export function getAuthToken() {
    return _token;
}

export function setAuthToken(token) {
    _token = token;
    if (token) {
        localStorage.setItem("nw_token", token);
    } else {
        localStorage.removeItem("nw_token");
        _currentRole = "viewer";
        _currentUserId = null;
        _authEnabled = false; // 토큰이 없으면 인증도 비활성화
    }
}

export function isAuthEnabled() {
    return _authEnabled && (!_authRequired || !!_token);
}

export function setAuthRequired(required) {
    _authRequired = required;
    if (!required) _currentRole = "admin";
}

export function setAuthEnabled(enabled) {
    _authEnabled = enabled;
}

/**
 * 인증 헤더가 포함된 fetch 래퍼.
 */
export async function authFetch(url, options) {
    options = options || {};
    options.headers = options.headers || {};
    
    // 본문이 문자열(JSON)인 경우 헤더 추가
    if (options.body && typeof options.body === "string" && !options.headers["Content-Type"]) {
        options.headers["Content-Type"] = "application/json";
    }
    
    const token = getAuthToken();
    if (token) {
        options.headers["Authorization"] = "Bearer " + token;
    }
    
    try {
        const resp = await fetch(url, options);
        if (resp.status === 401) {
            console.warn("Session unauthorized for URL:", url);
            // 로그인 중일 때는 무시 (로그인 자체가 401일 수 있음)
            if (!url.includes("/auth/login")) {
                handleUnauthorized();
            }
        }
        return resp;
    } catch (err) {
        console.error("Fetch network error:", err);
        throw err;
    }
}

export function handleUnauthorized() {
    const hadSession = !!_token || _authEnabled;
    setAuthToken(null);
    setAuthEnabled(false);
    const overlay = document.getElementById("login-overlay");
    if (overlay) {
        overlay.classList.remove("hidden");
        // 에러 메시지 표시
        const errEl = document.getElementById("login-error");
        if (errEl) errEl.textContent = window.i18next?.t('console.users.session_expired') || "Please sign in again.";
    }
    if (hadSession) window.dispatchEvent(new Event('nw-session-ended'));
}
