/**
 * NetWatcher Dashboard Utilities
 */

var HTML_ESCAPES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "`": "&#96;"
};

/**
 * 텍스트 → HTML 이스케이프.
 *
 * 이전 구현은 div.textContent → div.innerHTML 왕복을 썼다. textContent는
 * &, <, > 만 이스케이프하므로 속성값 컨텍스트(`title="${esc(x)}"`)에서
 * 따옴표 탈출이 가능했다. 여기서는 따옴표/백틱/역슬래시까지 처리한다.
 */
export function esc(str) {
    if (str === null || str === undefined) return "";
    return String(str).replace(/[&<>"'`]/g, function (ch) {
        return HTML_ESCAPES[ch];
    });
}

/**
 * 값이 아닌 DOM 노드로 안전하게 출력한다. 문자열 조립이 필요 없는 모든
 * 렌더링 경로에서 이 함수를 우선 사용한다(PR 02).
 */
export function textEl(value) {
    var el = document.createElement("span");
    el.textContent = value === null || value === undefined ? "" : String(value);
    return el;
}

/** 속성값 전용 이스케이프. esc() 와 동일하지만 의도를 명시한다. */
export function escAttr(value) {
    return esc(value);
}

export function formatTime(ts) {
    if (!ts) return "-";
    return new Date(ts).toLocaleString();
}

export function formatBytes(bytes) {
    if (!bytes) return "0 B";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
}

export function formatHexDump(hex) {
    if (!hex) return "";
    var lines = [];
    for (var i = 0; i < hex.length; i += 32) {
        var chunk = hex.substr(i, 32);
        var res = "";
        for (var j = 0; j < chunk.length; j += 2) {
            res += chunk.substr(j, 2) + " ";
        }
        lines.push(res.trim().toUpperCase());
    }
    return lines.join("\n");
}

export function showToast(title, body, severity) {
    var container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    var toast = document.createElement("div");
    toast.className = "toast toast-" + (severity || "info");
    toast.innerHTML =
        '<div class="toast-header">' +
            '<span class="toast-title">' + esc(title) + '</span>' +
            '<span class="toast-close">&times;</span>' +
        '</div>' +
        '<div class="toast-body">' + esc(body) + '</div>';

    container.appendChild(toast);
    
    toast.querySelector(".toast-close").addEventListener("click", function() {
        toast.classList.add("toast-hiding");
        setTimeout(function() { toast.remove(); }, 300);
    });

    setTimeout(function() {
        if (toast.parentNode) {
            toast.classList.add("toast-hiding");
            setTimeout(function() { toast.remove(); }, 300);
        }
    }, 5000);
}

export function renderPagination(container, currentPage, totalItems, pageSize, onPageChange) {
    if (!container) return;
    var totalPages = Math.ceil(totalItems / pageSize);
    if (totalPages <= 1) {
        container.innerHTML = "";
        return;
    }

    container.innerHTML = "";
    var prev = document.createElement("button");
    prev.textContent = "Prev";
    prev.disabled = currentPage === 0;
    prev.addEventListener("click", function () { onPageChange(currentPage - 1); });
    container.appendChild(prev);

    var startPage = Math.max(0, currentPage - 3);
    var endPage = Math.min(totalPages - 1, currentPage + 3);

    if (startPage > 0) {
        container.appendChild(makePageBtn(0, currentPage, onPageChange));
        if (startPage > 1) {
            var dots = document.createElement("span");
            dots.className = "page-info";
            dots.textContent = "...";
            container.appendChild(dots);
        }
    }

    for (var i = startPage; i <= endPage; i++) {
        container.appendChild(makePageBtn(i, currentPage, onPageChange));
    }

    if (endPage < totalPages - 1) {
        if (endPage < totalPages - 2) {
            var dots = document.createElement("span");
            dots.className = "page-info";
            dots.textContent = "...";
            container.appendChild(dots);
        }
        container.appendChild(makePageBtn(totalPages - 1, currentPage, onPageChange));
    }

    var next = document.createElement("button");
    next.textContent = "Next";
    next.disabled = currentPage >= totalPages - 1;
    next.addEventListener("click", function () { onPageChange(currentPage + 1); });
    container.appendChild(next);
}

export function newRequestId() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

function makePageBtn(page, current, onPageChange) {
    var btn = document.createElement("button");
    btn.textContent = page + 1;
    if (page === current) btn.className = "active";
    btn.addEventListener("click", function () { onPageChange(page); });
    return btn;
}
