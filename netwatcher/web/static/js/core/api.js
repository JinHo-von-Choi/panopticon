/**
 * NetWatcher Dashboard API Client (Robust Version)
 */

let _token = localStorage.getItem("nw_token");
let _authEnabled = false;

export function getAuthToken() {
    return _token;
}

export function setAuthToken(token) {
    _token = token;
    if (token) {
        localStorage.setItem("nw_token", token);
    } else {
        localStorage.removeItem("nw_token");
        _authEnabled = false; // 토큰이 없으면 인증도 비활성화
    }
}

export function isAuthEnabled() {
    return _authEnabled && !!_token;
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

function handleUnauthorized() {
    setAuthToken(null);
    setAuthEnabled(false);
    const overlay = document.getElementById("login-overlay");
    if (overlay) {
        overlay.classList.remove("hidden");
        // 에러 메시지 표시
        const errEl = document.getElementById("login-error");
        if (errEl) errEl.textContent = "Session expired. Please login again.";
    }
}
