/** NetWatcher Dashboard */

(function () {
    "use strict";

    var API = "";
    var ws = null;
    var reconnectTimer = null;

    // === AUTH STATE ===
    var authToken   = localStorage.getItem("nw_token");
    var authEnabled = false;

    /**
     * 인증 헤더가 포함된 fetch 래퍼.
     * 401 응답 시 자동으로 로그인 화면으로 전환한다.
     */
    async function authFetch(url, opts) {
        opts = opts || {};
        if (authToken) {
            opts.headers = opts.headers || {};
            opts.headers["Authorization"] = "Bearer " + authToken;
        }
        var resp = await fetch(url, opts);
        if (resp.status === 401 && authEnabled) {
            localStorage.removeItem("nw_token");
            authToken = null;
            showLoginOverlay();
            throw new Error("Unauthorized");
        }
        return resp;
    }

    function showLoginOverlay() {
        document.getElementById("login-overlay").classList.remove("hidden");
    }

    function hideLoginOverlay() {
        document.getElementById("login-overlay").classList.add("hidden");
    }

    /**
     * 앱 시작 시 인증 상태를 확인하고, 필요하면 로그인 화면을 표시한다.
     */
    async function checkAuth() {
        try {
            var statusResp = await fetch(API + "/api/auth/status");
            var statusData = await statusResp.json();
            authEnabled = statusData.enabled;
        } catch (e) {
            // 서버 접근 불가 시 인증 없이 진행
            initApp();
            return;
        }

        if (!authEnabled) {
            document.getElementById("btn-logout").style.display = "none";
            initApp();
            return;
        }

        // 저장된 토큰 유효성 확인
        if (authToken) {
            try {
                var checkResp = await fetch(API + "/api/auth/check", {
                    headers: { "Authorization": "Bearer " + authToken },
                });
                if (checkResp.ok) {
                    document.getElementById("btn-logout").style.display = "";
                    initApp();
                    return;
                }
            } catch (e) {
                // 네트워크 오류 시 토큰 폐기
            }
            localStorage.removeItem("nw_token");
            authToken = null;
        }

        // 토큰 없거나 만료 → 로그인 화면
        showLoginOverlay();
    }

    // --- Login form ---
    document.getElementById("login-form").addEventListener("submit", async function (e) {
        e.preventDefault();
        var username = document.getElementById("login-username").value.trim();
        var password = document.getElementById("login-password").value;
        var errEl    = document.getElementById("login-error");
        errEl.style.display = "none";

        try {
            var resp = await fetch(API + "/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: username, password: password }),
            });
            var data = await resp.json();
            if (!resp.ok) {
                errEl.textContent = data.error || "Login failed";
                errEl.style.display = "block";
                return;
            }
            authToken = data.token;
            localStorage.setItem("nw_token", authToken);
            hideLoginOverlay();
            document.getElementById("btn-logout").style.display = "";
            initApp();
        } catch (err) {
            errEl.textContent = "Connection failed: " + err.message;
            errEl.style.display = "block";
        }
    });

    // --- Logout ---
    document.getElementById("btn-logout").addEventListener("click", function () {
        localStorage.removeItem("nw_token");
        authToken = null;
        location.reload();
    });

    // Pagination state
    var eventsPage = 0;
    var eventsTotal = 0;
    var devicesPage = 0;
    var devicesAll = [];
    var devicesFiltered = [];
    var DEVICES_PER_PAGE = 50;

    // Blocklist state
    var blPage = 0;
    var blTotal = 0;
    var BL_PER_PAGE = 50;

    // --- DOM refs ---
    var $clock = document.getElementById("clock");
    var $connStatus = document.getElementById("connection-status");
    var $eventsBody = document.getElementById("events-body");
    var $devicesBody = document.getElementById("devices-body");
    var $filterSeverity = document.getElementById("filter-severity");
    var $filterEngine = document.getElementById("filter-engine");
    var $filterPagesize = document.getElementById("filter-pagesize");
    var $filterSearch = document.getElementById("filter-search");
    var $filterSince = document.getElementById("filter-since");
    var $filterUntil = document.getElementById("filter-until");
    var $btnRefresh = document.getElementById("btn-refresh");
    var $btnExportCsv = document.getElementById("btn-export-csv");
    var $btnExportJson = document.getElementById("btn-export-json");
    var $eventsPag = document.getElementById("events-pagination");
    var $devicesPag = document.getElementById("devices-pagination");
    var $devicesSearch = document.getElementById("devices-search");
    var $blBody = document.getElementById("blocklist-body");
    var $blPag = document.getElementById("blocklist-pagination");
    var $blFilterType = document.getElementById("bl-filter-type");
    var $blFilterSource = document.getElementById("bl-filter-source");
    var $blSearch = document.getElementById("bl-search");

    // Chart instances
    var trafficChart = null;
    var protocolChart = null;
    var severityChart = null;
    var enginesChart = null;
    var searchDebounceTimer = null;

    function getPageSize() {
        return parseInt($filterPagesize.value) || 100;
    }

    // === TOOLTIP ===
    var $tooltip = null;

    function createTooltip() {
        if ($tooltip) return;
        $tooltip = document.createElement("div");
        $tooltip.className = "engine-tooltip";
        $tooltip.style.display = "none";
        document.body.appendChild($tooltip);
    }

    function showTooltip(anchor) {
        createTooltip();
        var key = anchor.getAttribute("data-tt-key") || "";
        var type = anchor.getAttribute("data-tt-type") || "";
        var def = anchor.getAttribute("data-tt-default") || "";
        var min = anchor.getAttribute("data-tt-min") || "";
        var max = anchor.getAttribute("data-tt-max") || "";
        var desc = anchor.getAttribute("data-tt-desc") || "";

        var html = '<div class="tt-key">' + esc(key) + '</div>';
        var metaParts = [];
        if (type) metaParts.push("Type: " + type);
        if (def !== "") metaParts.push("Default: " + def);
        if (min !== "" || max !== "") {
            var range = "";
            if (min !== "" && max !== "") range = min + " ~ " + max;
            else if (min !== "") range = ">= " + min;
            else range = "<= " + max;
            metaParts.push("Range: " + range);
        }
        if (metaParts.length) {
            html += '<div class="tt-meta">' + esc(metaParts.join("  |  ")) + '</div>';
        }
        if (desc) {
            html += '<div class="tt-desc">' + esc(desc) + '</div>';
        }

        $tooltip.innerHTML = html;
        $tooltip.style.display = "block";

        var rect = anchor.getBoundingClientRect();
        var tw = $tooltip.offsetWidth;
        var th = $tooltip.offsetHeight;
        var left = rect.left + rect.width / 2 - tw / 2;
        var top = rect.bottom + 8;

        if (left < 8) left = 8;
        if (left + tw > window.innerWidth - 8) left = window.innerWidth - 8 - tw;
        if (top + th > window.innerHeight - 8) {
            top = rect.top - th - 8;
        }

        $tooltip.style.left = left + window.scrollX + "px";
        $tooltip.style.top = top + window.scrollY + "px";
    }

    function hideTooltip() {
        if ($tooltip) $tooltip.style.display = "none";
    }

    document.addEventListener("mouseenter", function (e) {
        if (e.target.classList && e.target.classList.contains("engine-tooltip-icon")) {
            showTooltip(e.target);
        }
    }, true);
    document.addEventListener("mouseleave", function (e) {
        if (e.target.classList && e.target.classList.contains("engine-tooltip-icon")) {
            hideTooltip();
        }
    }, true);
    document.addEventListener("click", function (e) {
        if (e.target.classList && e.target.classList.contains("engine-tooltip-icon")) {
            e.preventDefault();
            if ($tooltip && $tooltip.style.display === "block") {
                hideTooltip();
            } else {
                showTooltip(e.target);
            }
        } else if ($tooltip && $tooltip.style.display === "block") {
            hideTooltip();
        }
    });

    // --- Clock ---
    function updateClock() {
        $clock.textContent = new Date().toLocaleTimeString();
    }
    setInterval(updateClock, 1000);
    updateClock();

    // --- Tabs ---
    document.querySelectorAll(".tab").forEach(function (tab) {
        tab.addEventListener("click", function () {
            document.querySelectorAll(".tab").forEach(function (t) { t.classList.remove("active"); });
            document.querySelectorAll(".tab-content").forEach(function (c) { c.classList.remove("active"); });
            tab.classList.add("active");
            document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
            if (tab.dataset.tab === "devices") loadDevices();
            if (tab.dataset.tab === "traffic") loadCharts();
            if (tab.dataset.tab === "blocklist") loadBlocklist(0);
            if (tab.dataset.tab === "engines") loadEngines();
        });
    });

    // --- Helpers ---
    function formatTime(ts) {
        if (!ts) return "-";
        return new Date(ts).toLocaleString();
    }

    function formatBytes(bytes) {
        if (!bytes) return "0 B";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
        return (bytes / 1073741824).toFixed(2) + " GB";
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        var s = String(str);
        var div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
    }

    function esc(s) { return escapeHtml(s); }

    function formatHexDump(hexStr) {
        if (!hexStr) return "";
        var lines = [];
        for (var i = 0; i < hexStr.length; i += 32) {
            var chunk = hexStr.slice(i, i + 32);
            var offset = (i / 2).toString(16).padStart(4, "0");
            var parts = chunk.match(/.{1,2}/g);
            if (!parts) continue;
            var hex = parts.join(" ");
            var ascii = "";
            for (var j = 0; j < chunk.length; j += 2) {
                var code = parseInt(chunk.slice(j, j + 2), 16);
                ascii += (code >= 32 && code < 127) ? String.fromCharCode(code) : ".";
            }
            lines.push(offset + "  " + hex.padEnd(48, " ") + "  " + ascii);
        }
        return lines.join("\n");
    }

    // --- Pagination renderer ---
    function renderPagination(container, currentPage, totalItems, perPage, onPageChange) {
        container.innerHTML = "";
        var totalPages = Math.ceil(totalItems / perPage);
        if (totalPages <= 1) return;

        // Prev button
        var prev = document.createElement("button");
        prev.textContent = "\u2190";
        prev.disabled = currentPage === 0;
        prev.addEventListener("click", function () { onPageChange(currentPage - 1); });
        container.appendChild(prev);

        // Page numbers (show max 7 pages with ellipsis)
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

        for (var p = startPage; p <= endPage; p++) {
            container.appendChild(makePageBtn(p, currentPage, onPageChange));
        }

        if (endPage < totalPages - 1) {
            if (endPage < totalPages - 2) {
                var dots2 = document.createElement("span");
                dots2.className = "page-info";
                dots2.textContent = "...";
                container.appendChild(dots2);
            }
            container.appendChild(makePageBtn(totalPages - 1, currentPage, onPageChange));
        }

        // Next button
        var next = document.createElement("button");
        next.textContent = "\u2192";
        next.disabled = currentPage >= totalPages - 1;
        next.addEventListener("click", function () { onPageChange(currentPage + 1); });
        container.appendChild(next);

        // Info text
        var info = document.createElement("span");
        info.className = "page-info";
        var from = currentPage * perPage + 1;
        var to = Math.min((currentPage + 1) * perPage, totalItems);
        info.textContent = from + "-" + to + " of " + totalItems.toLocaleString();
        container.appendChild(info);
    }

    function makePageBtn(page, currentPage, onPageChange) {
        var btn = document.createElement("button");
        btn.textContent = page + 1;
        if (page === currentPage) btn.className = "active";
        btn.addEventListener("click", function () { onPageChange(page); });
        return btn;
    }

    // === EVENT DETAIL MODAL ===
    window.closeModal = function () {
        document.getElementById("modal-overlay").classList.add("hidden");
    };

    window.showEventDetail = async function (eventId) {
        if (!eventId) return;
        var modalBody = document.getElementById("modal-body");
        modalBody.innerHTML = '<div style="text-align:center;color:var(--text-dim)">Loading...</div>';
        document.getElementById("modal-overlay").classList.remove("hidden");

        try {
            var resp = await authFetch(API + "/api/events/" + eventId);
            if (!resp.ok) {
                modalBody.innerHTML = "Error: HTTP " + resp.status;
                return;
            }
            var data = await resp.json();
            var ev = data.event;
            if (!ev) { modalBody.innerHTML = "Event not found"; return; }
            renderEventDetail(ev);
        } catch (e) {
            modalBody.innerHTML = "Failed to load event: " + esc(e.message);
        }
    };

    function renderEventDetail(ev) {
        var modalTitle = document.getElementById("modal-title");
        var modalBody = document.getElementById("modal-body");
        modalTitle.textContent = "[" + ev.severity + "] " + ev.title;

        var html = "";

        // Overview
        html += '<div class="detail-section"><h3>Overview</h3><div class="detail-grid">';
        html += row("ID", ev.id);
        html += row("Timestamp", formatTime(ev.timestamp));
        html += row("Engine", ev.engine);
        html += row("Severity", '<span class="severity-badge severity-' + esc(ev.severity) + '">' + esc(ev.severity) + '</span>');
        html += '</div></div>';

        // Detection Reasoning (WARNING 이상)
        if (ev.severity === "WARNING" || ev.severity === "CRITICAL") {
            html += renderReasoning(ev);
        }

        // Network
        html += '<div class="detail-section"><h3>Network</h3><div class="detail-grid">';
        html += row("Source IP", ev.source_ip || "-");
        html += row("Source MAC", ev.source_mac || "-");
        html += row("Dest IP", ev.dest_ip || "-");
        html += row("Dest MAC", ev.dest_mac || "-");
        html += '</div></div>';

        // Packet Info
        var pkt = ev.packet_info;
        if (pkt && typeof pkt === "object" && Object.keys(pkt).length > 0) {
            html += '<div class="detail-section"><h3>Packet Detail</h3>';
            if (pkt.layers && pkt.layers.length) {
                html += '<div style="margin-bottom:12px">';
                pkt.layers.forEach(function (l) { html += '<span class="layer-badge">' + esc(l) + '</span>'; });
                html += '</div>';
            }
            html += '<div class="detail-grid">';
            html += row("Packet Size", (pkt.length || 0) + " bytes");
            if (pkt.ip_src) html += row("IP Src", pkt.ip_src);
            if (pkt.ip_dst) html += row("IP Dst", pkt.ip_dst);
            if (pkt.ip_ttl !== undefined) html += row("TTL", pkt.ip_ttl);
            if (pkt.ip_flags) html += row("IP Flags", pkt.ip_flags);
            if (pkt.tcp_flags_list) html += row("TCP Flags", pkt.tcp_flags_list.join(", ") || "none");
            if (pkt.src_port !== undefined) html += row("Src Port", pkt.src_port);
            if (pkt.dst_port !== undefined) html += row("Dst Port", pkt.dst_port);
            if (pkt.tcp_seq !== undefined) html += row("TCP Seq", pkt.tcp_seq);
            if (pkt.tcp_ack !== undefined) html += row("TCP Ack", pkt.tcp_ack);
            if (pkt.tcp_window !== undefined) html += row("TCP Window", pkt.tcp_window);
            if (pkt.udp_length) html += row("UDP Length", pkt.udp_length);
            if (pkt.icmp_type !== undefined) html += row("ICMP Type", pkt.icmp_type);
            if (pkt.icmp_code !== undefined) html += row("ICMP Code", pkt.icmp_code);
            if (pkt.arp_op) {
                html += row("ARP Op", pkt.arp_op);
                html += row("ARP Src", pkt.arp_hwsrc + " / " + pkt.arp_psrc);
                html += row("ARP Dst", pkt.arp_hwdst + " / " + pkt.arp_pdst);
            }
            if (pkt.dns_qname) {
                html += row("DNS Type", pkt.dns_qr || "-");
                html += row("DNS Query", pkt.dns_qname);
                if (pkt.dns_qtype !== undefined) html += row("DNS QType", pkt.dns_qtype);
            }
            if (pkt.dns_answers && pkt.dns_answers.length) {
                var ansHtml = pkt.dns_answers.map(function (a) {
                    return esc(a.rrname) + " -> " + esc(a.rdata) + " (TTL:" + a.ttl + ")";
                }).join("<br>");
                html += row("DNS Answers", ansHtml);
            }
            if (pkt.eth_src) html += row("Eth Src", pkt.eth_src);
            if (pkt.eth_dst) html += row("Eth Dst", pkt.eth_dst);
            if (pkt.eth_type) html += row("Eth Type", pkt.eth_type);
            html += '</div>';

            // HTTP
            if (pkt.http_host || pkt.http_user_agent || pkt.http_headers) {
                html += '<div style="margin-top:16px"><h3 style="font-size:12px;color:var(--accent);margin-bottom:8px">HTTP Details</h3>';
                html += '<div class="detail-grid">';
                if (pkt.http_host) html += row("Host", pkt.http_host);
                if (pkt.http_user_agent) html += row("User-Agent", pkt.http_user_agent);
                if (pkt.http_content_type) html += row("Content-Type", pkt.http_content_type);
                if (pkt.http_content_length) html += row("Content-Length", pkt.http_content_length);
                html += '</div>';
                if (pkt.http_headers) {
                    html += '<div style="margin-top:8px"><span class="detail-label">Headers:</span>';
                    html += '<pre class="payload-text">' + esc(pkt.http_headers) + '</pre></div>';
                }
                if (pkt.http_body_preview) {
                    html += '<div style="margin-top:8px"><span class="detail-label">Body Preview:</span>';
                    html += '<pre class="payload-text">' + esc(pkt.http_body_preview) + '</pre></div>';
                }
                html += '</div>';
            }

            // Payload
            if (pkt.payload_size) {
                html += '<div style="margin-top:16px"><div class="detail-grid">';
                html += row("Payload Size", pkt.payload_size + " bytes");
                html += '</div>';
                if (pkt.payload_text) {
                    html += '<div style="margin-top:8px"><span class="detail-label">Payload (Text):</span>';
                    html += '<pre class="payload-text">' + esc(pkt.payload_text) + '</pre></div>';
                }
                if (pkt.payload_hex) {
                    html += '<div style="margin-top:8px"><span class="detail-label">Payload (Hex Dump):</span>';
                    html += '<pre class="hex-dump">' + esc(formatHexDump(pkt.payload_hex)) + '</pre></div>';
                }
                html += '</div>';
            }
            html += '</div>';
        }

        // Metadata
        var meta = ev.metadata;
        if (meta && typeof meta === "object" && Object.keys(meta).length > 0) {
            html += '<div class="detail-section"><h3>Engine Metadata</h3>';
            html += '<pre class="json-block">' + esc(JSON.stringify(meta, null, 2)) + '</pre>';
            html += '</div>';
        }

        modalBody.innerHTML = html;
    }

    function renderReasoning(ev) {
        var meta = ev.metadata || {};
        var engine = ev.engine;
        var html = '<div class="detail-section"><h3>Detection Reasoning</h3>';
        html += '<div class="reasoning-box">';

        // Description
        html += '<div class="reasoning-desc">' + esc(ev.description) + '</div>';

        // Engine-specific reasoning
        var items = [];

        if (engine === "arp_spoof") {
            if (meta.original_mac) items.push(["기존 MAC", meta.original_mac]);
            if (meta.new_mac) items.push(["변경된 MAC", meta.new_mac]);
            if (meta.original_mac && meta.new_mac) {
                items.push(["판단 근거", "동일 IP에 대한 MAC 주소 변경 감지 → ARP 캐시 포이즈닝 의심"]);
            }
            if (meta.count) items.push(["판단 근거", "Gratuitous ARP " + meta.count + "회 전송 → 스푸핑 준비 단계 의심"]);
        }

        if (engine === "dns_anomaly") {
            if (meta.qname) items.push(["Query", meta.qname]);
            if (meta.label_length) items.push(["판단 근거", "라벨 길이 " + meta.label_length + "자 (임계값: 50자) → 데이터 인코딩 의심 (DNS 터널링)"]);
            if (meta.depth) items.push(["판단 근거", "서브도메인 깊이 " + meta.depth + "단계 (임계값: 7단계) → 비정상 도메인 구조"]);
            if (meta.entropy) items.push(["Shannon Entropy", meta.entropy + " (임계값: 3.8)"]);
            if (meta.entropy) items.push(["판단 근거", "높은 무작위성 → DGA(Domain Generation Algorithm) 의심"]);
            if (meta.label) items.push(["분석 대상 라벨", meta.label]);
            if (meta.query_count) items.push(["판단 근거", "1초간 DNS 쿼리 " + meta.query_count + "회 (임계값: 200회) → 비정상 대량 질의"]);
        }

        if (engine === "port_scan") {
            if (meta.unique_ports) items.push(["스캔된 포트 수", meta.unique_ports + "개 (임계값: 15개)"]);
            if (meta.window_seconds) items.push(["탐지 윈도우", meta.window_seconds + "초"]);
            if (meta.sample_ports) items.push(["포트 샘플", meta.sample_ports.join(", ")]);
            items.push(["판단 근거", "짧은 시간 내 다수 포트에 SYN 패킷 전송 → 포트 스캔"]);
        }

        if (engine === "http_suspicious") {
            if (meta.host) items.push(["대상 호스트", meta.host]);
            if (meta.avg_interval) {
                items.push(["접속 주기", "~" + meta.avg_interval + "초 간격"]);
                items.push(["접속 횟수", meta.connection_count + "회"]);
                items.push(["간격 편차", (meta.deviation * 100).toFixed(1) + "% (임계값: 15%)"]);
                items.push(["판단 근거", "동일 호스트에 일정 간격으로 반복 접속 → C2 비컨 패턴 의심"]);
            } else {
                items.push(["판단 근거", "알려진 애드웨어/트래킹 도메인 패턴 매칭"]);
            }
        }

        if (engine === "traffic_anomaly") {
            if (meta.mac) items.push(["MAC 주소", meta.mac]);
            if (meta.bytes) {
                items.push(["전송량", meta.bytes.toLocaleString() + " bytes"]);
                items.push(["평균 기준선", (meta.avg_bytes || 0).toLocaleString() + " bytes"]);
                items.push(["배율", meta.multiplier + "x (임계값: 3.0x)"]);
                items.push(["판단 근거", "기준선 대비 비정상적 트래픽 급증 → 데이터 유출 또는 이상 행위 의심"]);
            }
            if (meta.ip && !meta.bytes) {
                items.push(["판단 근거", "네트워크에서 처음 관측된 디바이스"]);
            }
        }

        if (engine === "threat_intel") {
            if (meta.blocklisted_ip) items.push(["블록리스트 IP", meta.blocklisted_ip]);
            if (meta.direction) items.push(["방향", meta.direction === "outbound" ? "내부 → 외부 (유출)" : "외부 → 내부 (침입)"]);
            if (meta.qname) items.push(["질의 도메인", meta.qname]);
            if (meta.matched_domain) items.push(["매칭된 블록리스트", meta.matched_domain]);
            items.push(["판단 근거", "위협 인텔리전스 피드(abuse.ch, Feodo 등)에 등록된 악성 지표와 일치"]);
        }

        if (items.length > 0) {
            html += '<div class="detail-grid" style="margin-top:12px">';
            items.forEach(function (item) {
                var isReason = item[0] === "판단 근거";
                if (isReason) {
                    html += '<div class="detail-label" style="color:var(--warning)">' + esc(item[0]) + '</div>';
                    html += '<div class="detail-value" style="color:var(--warning);font-family:inherit">' + esc(item[1]) + '</div>';
                } else {
                    html += '<div class="detail-label">' + esc(item[0]) + '</div>';
                    html += '<div class="detail-value">' + esc(item[1]) + '</div>';
                }
            });
            html += '</div>';
        }

        html += '</div></div>';
        return html;
    }

    function row(label, value) {
        return '<div class="detail-label">' + esc(label) + '</div><div class="detail-value">' + (typeof value === "number" ? value : (value || "-")) + '</div>';
    }

    // === DEVICE DETAIL MODAL ===
    window.closeDeviceModal = function () {
        document.getElementById("device-modal-overlay").classList.add("hidden");
    };

    window.showDeviceDetail = async function (mac) {
        if (!mac) return;
        var body = document.getElementById("device-modal-body");
        body.innerHTML = '<div style="text-align:center;color:var(--text-dim)">Loading...</div>';
        document.getElementById("device-modal-overlay").classList.remove("hidden");

        try {
            var resp = await authFetch(API + "/api/devices/" + encodeURIComponent(mac));
            if (!resp.ok) { body.innerHTML = "Error: HTTP " + resp.status; return; }
            var data = await resp.json();
            var dev = data.device;
            if (!dev) { body.innerHTML = "Device not found"; return; }
            renderDeviceDetail(dev);
        } catch (e) {
            body.innerHTML = "Failed to load: " + esc(e.message);
        }
    };

    function renderDeviceDetail(dev) {
        document.getElementById("device-modal-title").textContent = "Device: " + (dev.nickname || dev.hostname || dev.ip_address || dev.mac_address);
        var body = document.getElementById("device-modal-body");
        var html = '<div class="detail-section"><h3>Device Info</h3><div class="detail-grid">';
        html += row("Nickname", dev.nickname ? '<span class="nickname-tag">' + esc(dev.nickname) + '</span>' : "-");
        html += row("MAC Address", dev.mac_address);
        html += row("Vendor", dev.vendor || "Unknown");
        html += row("IP Address", dev.ip_address || "-");
        html += row("Hostname", dev.hostname || "-");
        html += row("OS Hint", dev.os_hint || "-");
        html += row("Known Device", dev.is_known ? '<span class="known-badge">Registered</span>' : "No");
        html += row("First Seen", formatTime(dev.first_seen));
        html += row("Last Seen", formatTime(dev.last_seen));
        html += row("Total Packets", (dev.total_packets || 0).toLocaleString());
        html += row("Total Bytes", formatBytes(dev.total_bytes || 0));
        if (dev.notes) html += row("Notes", dev.notes);
        html += '</div></div>';
        if (dev.open_ports && dev.open_ports.length) {
            html += '<div class="detail-section"><h3>Observed Open Ports</h3>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:4px">';
            dev.open_ports.forEach(function (p) { html += '<span class="layer-badge">' + p + '</span>'; });
            html += '</div></div>';
        }
        body.innerHTML = html;
    }

    // Close modals
    window.closeModal = function () {
        document.getElementById("modal-overlay").classList.add("hidden");
    };
    window.closeDeviceForm = function () {
        document.getElementById("device-form-overlay").classList.add("hidden");
    };
    window.closeBlocklistForm = function () {
        document.getElementById("blocklist-form-overlay").classList.add("hidden");
    };

    document.getElementById("modal-close-btn").addEventListener("click", closeModal);
    document.getElementById("device-modal-close-btn").addEventListener("click", closeDeviceModal);
    document.getElementById("device-form-close-btn").addEventListener("click", closeDeviceForm);
    document.getElementById("device-form-cancel-btn").addEventListener("click", closeDeviceForm);
    document.getElementById("blocklist-form-close-btn").addEventListener("click", closeBlocklistForm);
    document.getElementById("blocklist-form-cancel-btn").addEventListener("click", closeBlocklistForm);

    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") { closeModal(); closeDeviceModal(); closeDeviceForm(); closeBlocklistForm(); }
    });
    document.getElementById("modal-overlay").addEventListener("click", function (e) {
        if (e.target === this) closeModal();
    });
    document.getElementById("device-modal-overlay").addEventListener("click", function (e) {
        if (e.target === this) closeDeviceModal();
    });
    document.getElementById("device-form-overlay").addEventListener("click", function (e) {
        if (e.target === this) closeDeviceForm();
    });
    document.getElementById("blocklist-form-overlay").addEventListener("click", function (e) {
        if (e.target === this) closeBlocklistForm();
    });

    // === EVENTS LIST WITH PAGINATION ===
    function renderEventRow(ev) {
        var tr = document.createElement("tr");
        tr.className = "clickable";
        var evId = ev.id || 0;
        tr.innerHTML =
            "<td>" + esc(formatTime(ev.timestamp)) + "</td>" +
            '<td><span class="severity-badge severity-' + esc(ev.severity) + '">' + esc(ev.severity) + "</span></td>" +
            '<td><span class="engine-tag">' + esc(ev.engine) + "</span></td>" +
            "<td>" + esc(ev.title) + "</td>" +
            "<td>" + esc(ev.source_ip || ev.source_mac || "-") + "</td>" +
            "<td>" + esc(ev.dest_ip || ev.dest_mac || "-") + "</td>" +
            '<td>' +
            '<button class="btn-detail" data-ev-id="' + evId + '">Detail</button>' +
            '</td>';
        tr.querySelector(".btn-detail").addEventListener("click", function (e) { e.stopPropagation(); showEventDetail(evId); });
        tr.addEventListener("click", function () { showEventDetail(evId); });
        return tr;
    }

    async function loadEvents(page) {
        if (page === undefined) page = eventsPage;
        var limit = getPageSize();
        var offset = page * limit;

        var params = new URLSearchParams();
        params.set("limit", limit);
        params.set("offset", offset);
        if ($filterSeverity.value) params.set("severity", $filterSeverity.value);
        if ($filterEngine.value) params.set("engine", $filterEngine.value);
        if ($filterSearch.value.trim()) params.set("q", $filterSearch.value.trim());
        if ($filterSince.value) params.set("since", $filterSince.value + "T00:00:00.000000Z");
        if ($filterUntil.value) params.set("until", $filterUntil.value + "T23:59:59.999999Z");

        try {
            var resp = await authFetch(API + "/api/events?" + params.toString());
            var data = await resp.json();

            eventsPage = page;
            eventsTotal = data.total;

            $eventsBody.innerHTML = "";
            data.events.forEach(function (ev) {
                $eventsBody.appendChild(renderEventRow(ev));
            });

            renderPagination($eventsPag, eventsPage, eventsTotal, limit, function (p) {
                loadEvents(p);
            });
        } catch (e) {
            console.error("Failed to load events:", e);
        }
    }

    // === DEVICES LIST WITH CLIENT-SIDE PAGINATION ===
    function filterDevices() {
        var q = ($devicesSearch.value || "").trim().toLowerCase();
        if (!q) {
            devicesFiltered = devicesAll;
        } else {
            devicesFiltered = devicesAll.filter(function (d) {
                return (d.mac_address || "").toLowerCase().indexOf(q) >= 0 ||
                       (d.ip_address || "").toLowerCase().indexOf(q) >= 0 ||
                       (d.hostname || "").toLowerCase().indexOf(q) >= 0 ||
                       (d.nickname || "").toLowerCase().indexOf(q) >= 0 ||
                       (d.vendor || "").toLowerCase().indexOf(q) >= 0;
            });
        }
    }

    function renderDevicesPage(page) {
        devicesPage = page;
        var start = page * DEVICES_PER_PAGE;
        var end = Math.min(start + DEVICES_PER_PAGE, devicesFiltered.length);

        $devicesBody.innerHTML = "";
        for (var i = start; i < end; i++) {
            var d = devicesFiltered[i];
            var tr = document.createElement("tr");
            tr.className = "clickable";
            var nickHtml = d.nickname
                ? '<span class="nickname-tag">' + esc(d.nickname) + '</span>' + (d.is_known ? ' <span class="known-badge">R</span>' : '')
                : (d.is_known ? '<span class="known-badge">Registered</span>' : '<span style="color:var(--text-dim)">-</span>');
            tr.innerHTML =
                "<td>" + nickHtml + "</td>" +
                "<td><code>" + esc(d.mac_address) + "</code></td>" +
                "<td>" + (d.vendor ? '<span class="vendor-tag">' + esc(d.vendor) + '</span>' : '<span style="color:var(--text-dim)">Unknown</span>') + "</td>" +
                "<td>" + esc(d.ip_address || "-") + "</td>" +
                "<td>" + esc(d.hostname || "-") + "</td>" +
                "<td>" + (d.os_hint ? '<span class="os-tag">' + esc(d.os_hint) + '</span>' : "-") + "</td>" +
                "<td>" + esc(formatTime(d.first_seen)) + "</td>" +
                "<td>" + esc(formatTime(d.last_seen)) + "</td>" +
                "<td>" + (d.total_packets || 0).toLocaleString() + "</td>" +
                '<td>' +
                '<button class="btn-detail" data-mac="' + esc(d.mac_address) + '">Edit</button>' +
                '</td>';
            (function (mac) {
                tr.querySelector(".btn-detail").addEventListener("click", function (e) { e.stopPropagation(); openEditDevice(mac); });
                tr.addEventListener("click", function () { showDeviceDetail(mac); });
            })(d.mac_address);
            $devicesBody.appendChild(tr);
        }

        renderPagination($devicesPag, devicesPage, devicesFiltered.length, DEVICES_PER_PAGE, renderDevicesPage);
    }

    async function loadDevices() {
        try {
            var resp = await authFetch(API + "/api/devices");
            var data = await resp.json();
            devicesAll = data.devices;
            document.getElementById("stat-devices").textContent = devicesAll.length;
            filterDevices();
            renderDevicesPage(0);
        } catch (e) {
            console.error("Failed to load devices:", e);
        }
    }

    // === DEVICE REGISTER / EDIT ===
    window.openEditDevice = async function (mac) {
        document.getElementById("df-mode").value = "edit";
        document.getElementById("device-form-title").textContent = "Edit Device";
        document.getElementById("df-mac").value = mac;
        document.getElementById("df-mac").disabled = true;
        document.getElementById("df-error").style.display = "none";

        // Load current values
        try {
            var resp = await authFetch(API + "/api/devices/" + encodeURIComponent(mac));
            var data = await resp.json();
            var dev = data.device;
            document.getElementById("df-nickname").value = dev.nickname || "";
            document.getElementById("df-ip").value = dev.ip_address || "";
            document.getElementById("df-hostname").value = dev.hostname || "";
            document.getElementById("df-os").value = dev.os_hint || "";
            document.getElementById("df-notes").value = dev.notes || "";
        } catch (e) {
            // Prefill with empty
        }
        document.getElementById("device-form-overlay").classList.remove("hidden");
    };

    // devicesAll 캐시에서 디바이스 조회 (API 호출 없이 즉시)
    function findDeviceByMac(mac) {
        mac = (mac || "").trim().toLowerCase();
        for (var i = 0; i < devicesAll.length; i++) {
            if (devicesAll[i].mac_address === mac) return devicesAll[i];
        }
        return null;
    }

    function fillDeviceForm(dev) {
        if (!dev) return;
        document.getElementById("df-ip").value = dev.ip_address || "";
        document.getElementById("df-hostname").value = dev.hostname || "";
        document.getElementById("df-os").value = dev.os_hint || "";
        document.getElementById("df-nickname").value = dev.nickname || "";
        document.getElementById("df-notes").value = dev.notes || "";
    }

    window.openRegisterDevice = function (prefillMac) {
        document.getElementById("df-mode").value = "register";
        document.getElementById("device-form-title").textContent = "Register Device";
        document.getElementById("df-mac").value = prefillMac || "";
        document.getElementById("df-mac").disabled = !!prefillMac;
        document.getElementById("df-nickname").value = "";
        document.getElementById("df-ip").value = "";
        document.getElementById("df-hostname").value = "";
        document.getElementById("df-os").value = "";
        document.getElementById("df-notes").value = "";
        document.getElementById("df-error").style.display = "none";
        // MAC이 있으면 캐시에서 즉시 자동 채움
        if (prefillMac) fillDeviceForm(findDeviceByMac(prefillMac));
        document.getElementById("device-form-overlay").classList.remove("hidden");
    };

    // MAC 입력 시 기존 디바이스 데이터 자동 채움
    var macAutoFillTimer = null;
    document.getElementById("df-mac").addEventListener("input", function () {
        clearTimeout(macAutoFillTimer);
        var mac = this.value;
        macAutoFillTimer = setTimeout(function () {
            var dev = findDeviceByMac(mac);
            if (dev) fillDeviceForm(dev);
        }, 400);
    });

    document.getElementById("btn-register-device").addEventListener("click", function () { openRegisterDevice(); });

    document.getElementById("device-form").addEventListener("submit", async function (e) {
        e.preventDefault();
        var mode = document.getElementById("df-mode").value;
        var mac = document.getElementById("df-mac").value.trim().toLowerCase();
        var nickname = document.getElementById("df-nickname").value.trim();
        var ip = document.getElementById("df-ip").value.trim() || null;
        var hostname = document.getElementById("df-hostname").value.trim() || null;
        var os = document.getElementById("df-os").value.trim() || null;
        var notes = document.getElementById("df-notes").value.trim();
        var errEl = document.getElementById("df-error");

        if (mode === "register" && !mac) {
            errEl.textContent = "MAC address is required";
            errEl.style.display = "block";
            return;
        }
        if (mode === "register" && !nickname) {
            errEl.textContent = "Nickname is required";
            errEl.style.display = "block";
            return;
        }

        try {
            var resp;
            if (mode === "register") {
                resp = await authFetch(API + "/api/devices/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ mac_address: mac, nickname: nickname, ip_address: ip, hostname: hostname, os_hint: os, notes: notes }),
                });
            } else {
                var body = {};
                if (nickname) body.nickname = nickname;
                if (ip) body.ip_address = ip;
                if (hostname) body.hostname = hostname;
                if (os) body.os_hint = os;
                body.notes = notes;
                resp = await authFetch(API + "/api/devices/" + encodeURIComponent(mac), {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(body),
                });
            }

            var data = await resp.json();
            if (!resp.ok) {
                errEl.textContent = data.error || "Request failed";
                errEl.style.display = "block";
                return;
            }
            closeDeviceForm();
            loadDevices();
        } catch (err) {
            errEl.textContent = "Request failed: " + err.message;
            errEl.style.display = "block";
        }
    });

    // === BLOCKLIST TAB ===
    async function loadBlocklist(page) {
        if (page === undefined) page = blPage;
        var params = new URLSearchParams();
        params.set("limit", BL_PER_PAGE);
        params.set("offset", page * BL_PER_PAGE);
        if ($blFilterType.value) params.set("entry_type", $blFilterType.value);
        if ($blFilterSource.value) params.set("source", $blFilterSource.value);
        if ($blSearch.value.trim()) params.set("search", $blSearch.value.trim());

        try {
            // Load entries + stats in parallel
            var [entryResp, statsResp] = await Promise.all([
                authFetch(API + "/api/blocklist?" + params.toString()),
                authFetch(API + "/api/blocklist/stats"),
            ]);
            var entryData = await entryResp.json();
            var statsData = await statsResp.json();

            blPage = page;
            blTotal = entryData.total;

            // Render stats
            var statsEl = document.getElementById("bl-stats");
            statsEl.innerHTML =
                '<span>IPs: <span class="stat-num">' + statsData.total_ips + '</span></span>' +
                '<span>Domains: <span class="stat-num">' + statsData.total_domains + '</span></span>' +
                '<span>Custom IPs: <span class="stat-num">' + statsData.custom_ips + '</span></span>' +
                '<span>Custom Domains: <span class="stat-num">' + statsData.custom_domains + '</span></span>';

            // Render table
            $blBody.innerHTML = "";
            entryData.entries.forEach(function (entry) {
                var tr = document.createElement("tr");
                var isCustom = entry.source === "Custom";
                var sourceClass = isCustom ? "source-custom" : "source-feed";
                tr.innerHTML =
                    '<td><span class="engine-tag">' + esc(entry.entry_type) + '</span></td>' +
                    '<td><code>' + esc(entry.value) + '</code></td>' +
                    '<td><span class="source-badge ' + sourceClass + '">' + esc(entry.source) + '</span></td>' +
                    '<td>' + (isCustom ? '<button class="btn-danger" data-bl-type="' + esc(entry.entry_type) + '" data-bl-value="' + esc(entry.value) + '">Remove</button>' : '-') + '</td>';
                var removeBtn = tr.querySelector(".btn-danger");
                if (removeBtn) {
                    (function (type, value) {
                        removeBtn.addEventListener("click", function () { removeBlocklistEntry(type, value); });
                    })(entry.entry_type, entry.value);
                }
                $blBody.appendChild(tr);
            });

            renderPagination($blPag, blPage, blTotal, BL_PER_PAGE, function (p) { loadBlocklist(p); });
        } catch (e) {
            console.error("Failed to load blocklist:", e);
        }
    }

    window.removeBlocklistEntry = async function (type, value) {
        if (!confirm("Remove " + value + " from blocklist?")) return;
        try {
            var resp = await authFetch(API + "/api/blocklist/" + type, {
                method: "DELETE",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(type === "ip" ? { ip: value } : { domain: value }),
            });
            if (resp.ok) loadBlocklist(blPage);
        } catch (e) {
            console.error("Failed to remove blocklist entry:", e);
        }
    };

    // Blocklist add modal
    document.getElementById("btn-add-blocklist").addEventListener("click", function () {
        document.getElementById("bf-value").value = "";
        document.getElementById("bf-notes").value = "";
        document.getElementById("bf-error").style.display = "none";
        document.getElementById("blocklist-form-overlay").classList.remove("hidden");
    });

    document.getElementById("blocklist-form").addEventListener("submit", async function (e) {
        e.preventDefault();
        var type = document.getElementById("bf-type").value;
        var value = document.getElementById("bf-value").value.trim();
        var notes = document.getElementById("bf-notes").value.trim();
        var errEl = document.getElementById("bf-error");

        if (!value) {
            errEl.textContent = "Value is required";
            errEl.style.display = "block";
            return;
        }

        try {
            var body = type === "ip" ? { ip: value, notes: notes } : { domain: value, notes: notes };
            var resp = await authFetch(API + "/api/blocklist/" + type, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            var data = await resp.json();
            if (!resp.ok) {
                errEl.textContent = data.error || "Failed to add entry";
                errEl.style.display = "block";
                return;
            }
            closeBlocklistForm();
            loadBlocklist(0);
        } catch (err) {
            errEl.textContent = "Request failed: " + err.message;
            errEl.style.display = "block";
        }
    });

    // === ENGINE FILTER (dynamic populate) ===
    async function populateEngineFilter() {
        try {
            var resp = await authFetch(API + "/api/engines");
            var data = await resp.json();
            var select = document.getElementById("filter-engine");
            while (select.options.length > 1) select.remove(1);
            data.engines.forEach(function (eng) {
                var opt = document.createElement("option");
                opt.value = eng.name;
                opt.textContent = eng.name.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
                select.appendChild(opt);
            });
        } catch (e) { /* silent fallback */ }
    }

    // === ENGINES TAB ===
    var enginesData = [];
    var selectedEngine = null;

    async function loadEngines() {
        try {
            var resp = await authFetch(API + "/api/engines");
            var data = await resp.json();
            enginesData = data.engines || [];
            renderEnginesList();
            if (selectedEngine) {
                var found = null;
                for (var i = 0; i < enginesData.length; i++) {
                    if (enginesData[i].name === selectedEngine) { found = enginesData[i]; break; }
                }
                if (found) renderEngineDetail(found);
            }
        } catch (e) {
            console.error("Failed to load engines:", e);
        }
    }

    function renderEnginesList() {
        var container = document.getElementById("engines-list");
        container.innerHTML = "";
        enginesData.forEach(function (eng) {
            var card = document.createElement("div");
            card.className = "engine-card" + (selectedEngine === eng.name ? " selected" : "");
            var displayName = eng.name.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
            card.innerHTML =
                '<div class="engine-card-header">' +
                    '<span class="engine-card-name">' + esc(displayName) + '</span>' +
                    '<label class="toggle-switch">' +
                        '<input type="checkbox"' + (eng.enabled ? ' checked' : '') + ' data-engine="' + esc(eng.name) + '" />' +
                        '<span class="toggle-slider"></span>' +
                    '</label>' +
                '</div>';
            var toggleLabel = card.querySelector('.toggle-switch');
            toggleLabel.addEventListener("click", function (e) {
                e.stopPropagation();
            });
            var checkbox = card.querySelector('input[type="checkbox"]');
            checkbox.addEventListener("change", function (e) {
                e.stopPropagation();
                toggleEngine(eng.name, this.checked);
            });
            card.addEventListener("click", function () {
                selectedEngine = eng.name;
                renderEnginesList();
                renderEngineDetail(eng);
            });
            container.appendChild(card);
        });
    }

    function renderEngineDetail(eng) {
        var container = document.getElementById("engine-detail");
        var displayName = eng.name.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
        var schemaList = Array.isArray(eng.schema) ? eng.schema : [];
        var config = eng.config || {};

        var html = '<h3 style="margin-bottom:16px;font-size:16px;font-weight:600">' + esc(displayName) + '</h3>';
        if (eng.description) {
            html += '<p class="engine-desc">' + esc(eng.description) + '</p>';
        }
        html += '<form id="engine-config-form">';

        var hasFields = false;
        for (var i = 0; i < schemaList.length; i++) {
            var fieldSchema = schemaList[i];
            var key = fieldSchema.key;
            if (key === "enabled") continue;
            hasFields = true;
            var fieldType = fieldSchema.type || "str";
            var fieldDesc = fieldSchema.description || "";
            var fieldLabel = fieldSchema.label || key;
            var fieldVal = config[key];
            var fieldDefault = fieldSchema.default;
            var fieldMin = fieldSchema.min;
            var fieldMax = fieldSchema.max;
            if (fieldVal === undefined || fieldVal === null) fieldVal = fieldDefault;

            html += '<div class="engine-field">';
            html += '<div class="engine-field-header">';
            html += '<label class="engine-field-label">' + esc(fieldLabel) + '</label>';
            if (fieldDesc || fieldDefault !== undefined || fieldMin !== undefined || fieldMax !== undefined) {
                html += '<span class="engine-tooltip-icon" '
                    + 'data-tt-key="' + esc(key) + '" '
                    + 'data-tt-type="' + esc(fieldType) + '" '
                    + 'data-tt-default="' + esc(fieldDefault !== undefined && fieldDefault !== null ? String(fieldDefault) : '') + '" '
                    + 'data-tt-min="' + esc(fieldMin !== undefined && fieldMin !== null ? String(fieldMin) : '') + '" '
                    + 'data-tt-max="' + esc(fieldMax !== undefined && fieldMax !== null ? String(fieldMax) : '') + '" '
                    + 'data-tt-desc="' + esc(fieldDesc) + '"'
                    + '>?</span>';
            }
            html += '</div>';

            if (fieldType === "bool") {
                var checked = fieldVal ? " checked" : "";
                html += '<label class="toggle-switch">' +
                    '<input type="checkbox" name="' + esc(key) + '" data-type="bool"' + checked + ' />' +
                    '<span class="toggle-slider"></span>' +
                    '</label>';
            } else if (fieldType === "int") {
                var minAttr = fieldMin !== undefined && fieldMin !== null ? ' min="' + fieldMin + '"' : "";
                var maxAttr = fieldMax !== undefined && fieldMax !== null ? ' max="' + fieldMax + '"' : "";
                html += '<input type="number" name="' + esc(key) + '" data-type="int" class="input-search engine-input" step="1"' +
                    minAttr + maxAttr + ' value="' + (fieldVal !== undefined ? fieldVal : "") + '" />';
            } else if (fieldType === "float") {
                var minAttrF = fieldMin !== undefined && fieldMin !== null ? ' min="' + fieldMin + '"' : "";
                var maxAttrF = fieldMax !== undefined && fieldMax !== null ? ' max="' + fieldMax + '"' : "";
                html += '<input type="number" name="' + esc(key) + '" data-type="float" class="input-search engine-input" step="any"' +
                    minAttrF + maxAttrF + ' value="' + (fieldVal !== undefined ? fieldVal : "") + '" />';
            } else if (fieldType === "list") {
                var listVal = "";
                if (Array.isArray(fieldVal)) listVal = fieldVal.join(", ");
                html += '<input type="text" name="' + esc(key) + '" data-type="list" class="input-search engine-input" value="' + esc(listVal) + '" placeholder="comma separated" />';
            } else {
                html += '<input type="text" name="' + esc(key) + '" data-type="str" class="input-search engine-input" value="' + esc(fieldVal !== undefined ? String(fieldVal) : "") + '" />';
            }
            html += '</div>';
        }

        if (!hasFields) {
            html += '<div style="color:var(--text-dim);padding:20px 0">No configurable parameters for this engine.</div>';
        }

        html += '<div class="engine-form-actions">';
        if (hasFields) {
            html += '<button type="button" class="btn btn-accent" id="engine-save-btn" data-engine="' + esc(eng.name) + '">Save</button>';
        }
        html += '<span id="engine-save-status" class="engine-save-status"></span>';
        html += '</div>';
        html += '</form>';

        container.innerHTML = html;

        var cfgForm = document.getElementById("engine-config-form");
        if (cfgForm) {
            cfgForm.addEventListener("submit", function (e) { e.preventDefault(); });
        }
        var saveBtn = document.getElementById("engine-save-btn");
        if (saveBtn) {
            saveBtn.addEventListener("click", function () {
                saveEngineConfig(this.getAttribute("data-engine"));
            });
        }
    }

    window.saveEngineConfig = async function (name) {
        var form = document.getElementById("engine-config-form");
        if (!form) return;
        var statusEl = document.getElementById("engine-save-status");
        var inputs = form.querySelectorAll("input[name]");
        var config = {};

        for (var i = 0; i < inputs.length; i++) {
            var inp = inputs[i];
            var key = inp.name;
            var type = inp.getAttribute("data-type");

            if (type === "bool") {
                config[key] = inp.checked;
            } else if (type === "int") {
                config[key] = inp.value !== "" ? parseInt(inp.value, 10) : null;
            } else if (type === "float") {
                config[key] = inp.value !== "" ? parseFloat(inp.value) : null;
            } else if (type === "list") {
                var raw = inp.value.trim();
                if (!raw) {
                    config[key] = [];
                } else {
                    var parts = raw.split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s !== ""; });
                    /** 숫자로만 이루어진 리스트인지 자동 감지 */
                    var allNumbers = parts.every(function (p) { return !isNaN(p) && p !== ""; });
                    if (allNumbers) {
                        config[key] = parts.map(function (p) { return Number(p); });
                    } else {
                        config[key] = parts;
                    }
                }
            } else {
                config[key] = inp.value;
            }
        }

        try {
            statusEl.textContent = "Saving...";
            statusEl.className = "engine-save-status";
            var resp = await authFetch(API + "/api/engines/" + encodeURIComponent(name) + "/config", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(config),
            });
            if (resp.ok) {
                var result = await resp.json();
                if (result.warnings && result.warnings.length > 0) {
                    statusEl.textContent = "Saved (" + result.warnings.join("; ") + ")";
                    statusEl.className = "engine-save-status warning";
                } else {
                    statusEl.textContent = "Saved";
                    statusEl.className = "engine-save-status success";
                }
                loadEngines();
            } else {
                var errData = await resp.json();
                statusEl.textContent = errData.error || "Save failed";
                statusEl.className = "engine-save-status error";
            }
        } catch (e) {
            statusEl.textContent = "Error: " + e.message;
            statusEl.className = "engine-save-status error";
        }

        setTimeout(function () {
            if (statusEl) { statusEl.textContent = ""; statusEl.className = "engine-save-status"; }
        }, 3000);
    };

    async function toggleEngine(name, enabled) {
        try {
            await authFetch(API + "/api/engines/" + encodeURIComponent(name) + "/toggle", {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled: enabled }),
            });
            loadEngines();
        } catch (e) {
            console.error("Failed to toggle engine:", e);
            loadEngines();
        }
    }

    // === STATS ===
    async function loadStats() {
        try {
            var resp = await authFetch(API + "/api/stats");
            var data = await resp.json();
            document.getElementById("stat-critical").textContent = data.events.critical;
            document.getElementById("stat-warning").textContent = data.events.warning;
            document.getElementById("stat-info").textContent = data.events.info;
            document.getElementById("stat-packets").textContent =
                (data.traffic.total_packets || 0).toLocaleString();
        } catch (e) {
            console.error("Failed to load stats:", e);
        }
    }

    // === WEBSOCKET ===
    function connectWS() {
        var proto = location.protocol === "https:" ? "wss:" : "ws:";
        var url = proto + "//" + location.host + "/api/ws/events";
        if (authToken) url += "?token=" + encodeURIComponent(authToken);
        ws = new WebSocket(url);

        ws.onopen = function () {
            $connStatus.className = "status-dot connected";
            $connStatus.title = "WebSocket connected";
            if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        };

        ws.onclose = function () {
            $connStatus.className = "status-dot disconnected";
            $connStatus.title = "WebSocket disconnected";
            reconnectTimer = setTimeout(connectWS, 3000);
        };

        ws.onerror = function () { ws.close(); };

        ws.onmessage = function (e) {
            try {
                var ev = JSON.parse(e.data);

                // Skip non-alert messages (e.g. incident broadcasts)
                if (ev.type === "incident") return;

                // Check if event matches current filters
                var sevFilter = $filterSeverity.value;
                var engFilter = $filterEngine.value;
                var matchesFilter = true;
                if (sevFilter && ev.severity !== sevFilter) matchesFilter = false;
                if (engFilter && ev.engine !== engFilter) matchesFilter = false;

                // Only add to table if on page 0 and matches current filters
                if (eventsPage === 0 && matchesFilter) {
                    var tr = renderEventRow(ev);
                    tr.classList.add("new-event");
                    $eventsBody.insertBefore(tr, $eventsBody.firstChild);

                    var limit = getPageSize();
                    while ($eventsBody.children.length > limit) {
                        $eventsBody.removeChild($eventsBody.lastChild);
                    }
                }

                // Only update pagination total if matches current filters
                if (matchesFilter) {
                    eventsTotal++;
                    renderPagination($eventsPag, eventsPage, eventsTotal, getPageSize(), function (p) { loadEvents(p); });
                }

                // Always update severity stat counters
                if (ev.severity) {
                    var el = document.getElementById("stat-" + ev.severity.toLowerCase());
                    if (el) el.textContent = parseInt(el.textContent || "0") + 1;
                }
            } catch (err) {
                console.error("WS parse error:", err);
            }
        };
    }

    // === CHARTS ===
    var chartColors = {
        blue: "rgba(52, 152, 219, 0.8)",
        blueFill: "rgba(52, 152, 219, 0.1)",
        green: "rgba(46, 213, 115, 0.8)",
        greenFill: "rgba(46, 213, 115, 0.1)",
        orange: "rgba(255, 165, 2, 0.8)",
        orangeFill: "rgba(255, 165, 2, 0.1)",
        red: "rgba(255, 71, 87, 0.8)",
        redFill: "rgba(255, 71, 87, 0.1)",
        purple: "rgba(95, 111, 255, 0.8)",
        purpleFill: "rgba(95, 111, 255, 0.1)",
        teal: "rgba(0, 206, 209, 0.8)",
        tealFill: "rgba(0, 206, 209, 0.1)",
    };

    var chartDefaults = {
        color: "#8b8fa3",
        borderColor: "#2e3348",
        responsive: true,
        maintainAspectRatio: false,
    };

    function chartScaleOpts() {
        return {
            x: { ticks: { color: "#8b8fa3", maxTicksLimit: 12, font: { size: 10 } }, grid: { color: "rgba(46,51,72,0.5)" } },
            y: { ticks: { color: "#8b8fa3", font: { size: 10 } }, grid: { color: "rgba(46,51,72,0.5)" }, beginAtZero: true },
        };
    }

    async function loadCharts() {
        await Promise.all([loadTrafficChart(), loadTrendsCharts()]);
    }

    async function loadTrafficChart() {
        try {
            var resp = await authFetch(API + "/api/stats/traffic?minutes=60");
            var data = await resp.json();
            var items = (data.traffic || []).reverse();

            var labels = items.map(function (t) {
                var d = new Date(t.timestamp);
                return d.getHours().toString().padStart(2, "0") + ":" + d.getMinutes().toString().padStart(2, "0");
            });

            // Traffic timeline
            var ctx1 = document.getElementById("chart-traffic");
            if (!ctx1) return;
            if (trafficChart) trafficChart.destroy();
            trafficChart = new Chart(ctx1, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [{
                        label: "Packets",
                        data: items.map(function (t) { return t.total_packets; }),
                        borderColor: chartColors.blue,
                        backgroundColor: chartColors.blueFill,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 0,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: chartScaleOpts(),
                },
            });

            // Protocol stacked area
            var ctx2 = document.getElementById("chart-protocols");
            if (!ctx2) return;
            if (protocolChart) protocolChart.destroy();
            protocolChart = new Chart(ctx2, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [
                        { label: "TCP", data: items.map(function (t) { return t.tcp_count; }), borderColor: chartColors.blue, backgroundColor: chartColors.blueFill, fill: true, tension: 0.3, pointRadius: 0 },
                        { label: "UDP", data: items.map(function (t) { return t.udp_count; }), borderColor: chartColors.green, backgroundColor: chartColors.greenFill, fill: true, tension: 0.3, pointRadius: 0 },
                        { label: "ARP", data: items.map(function (t) { return t.arp_count; }), borderColor: chartColors.orange, backgroundColor: chartColors.orangeFill, fill: true, tension: 0.3, pointRadius: 0 },
                        { label: "DNS", data: items.map(function (t) { return t.dns_count; }), borderColor: chartColors.purple, backgroundColor: chartColors.purpleFill, fill: true, tension: 0.3, pointRadius: 0 },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: "#8b8fa3", boxWidth: 12, font: { size: 11 } } } },
                    scales: { x: { stacked: true, ticks: { color: "#8b8fa3", maxTicksLimit: 12, font: { size: 10 } }, grid: { color: "rgba(46,51,72,0.5)" } }, y: { stacked: true, ticks: { color: "#8b8fa3", font: { size: 10 } }, grid: { color: "rgba(46,51,72,0.5)" }, beginAtZero: true } },
                },
            });
        } catch (e) {
            console.error("Failed to load traffic charts:", e);
        }
    }

    async function loadTrendsCharts() {
        try {
            var resp = await authFetch(API + "/api/stats/trends?hours=24");
            var data = await resp.json();

            // Severity doughnut
            var bySev = data.by_severity || {};
            var ctx3 = document.getElementById("chart-severity");
            if (!ctx3) return;
            if (severityChart) severityChart.destroy();
            severityChart = new Chart(ctx3, {
                type: "doughnut",
                data: {
                    labels: Object.keys(bySev),
                    datasets: [{
                        data: Object.values(bySev),
                        backgroundColor: Object.keys(bySev).map(function (s) {
                            if (s === "CRITICAL") return chartColors.red;
                            if (s === "WARNING") return chartColors.orange;
                            return chartColors.blue;
                        }),
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: "bottom", labels: { color: "#8b8fa3", boxWidth: 12, font: { size: 11 } } } },
                },
            });

            // Engine bar chart
            var byEng = data.by_engine || {};
            var ctx4 = document.getElementById("chart-engines");
            if (!ctx4) return;
            if (enginesChart) enginesChart.destroy();
            var engLabels = Object.keys(byEng);
            var barColors = engLabels.map(function (_, i) {
                var palette = [chartColors.blue, chartColors.green, chartColors.orange, chartColors.red, chartColors.purple, chartColors.teal];
                return palette[i % palette.length];
            });
            enginesChart = new Chart(ctx4, {
                type: "bar",
                data: {
                    labels: engLabels,
                    datasets: [{
                        label: "Alerts",
                        data: Object.values(byEng),
                        backgroundColor: barColors,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: "y",
                    plugins: { legend: { display: false } },
                    scales: { x: { ticks: { color: "#8b8fa3", font: { size: 10 } }, grid: { color: "rgba(46,51,72,0.5)" }, beginAtZero: true }, y: { ticks: { color: "#8b8fa3", font: { size: 10 } }, grid: { display: false } } },
                },
            });
        } catch (e) {
            console.error("Failed to load trends charts:", e);
        }
    }

    // === EXPORT ===
    function exportEvents(format) {
        var params = new URLSearchParams();
        params.set("format", format);
        if ($filterSeverity.value) params.set("severity", $filterSeverity.value);
        if ($filterEngine.value) params.set("engine", $filterEngine.value);
        if ($filterSince.value) params.set("since", $filterSince.value + "T00:00:00.000000Z");
        if ($filterUntil.value) params.set("until", $filterUntil.value + "T23:59:59.999999Z");
        window.open(API + "/api/events/export?" + params.toString(), "_blank");
    }

    // === EVENT LISTENERS (registered once, before initApp) ===
    $filterSeverity.addEventListener("change", function () { loadEvents(0); });
    $filterEngine.addEventListener("change", function () { loadEvents(0); });
    $filterPagesize.addEventListener("change", function () { loadEvents(0); });
    $filterSince.addEventListener("change", function () { loadEvents(0); });
    $filterUntil.addEventListener("change", function () { loadEvents(0); });
    $filterSearch.addEventListener("input", function () {
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(function () { loadEvents(0); }, 400);
    });
    $btnRefresh.addEventListener("click", function () {
        loadEvents(eventsPage);
        loadStats();
        loadDevices();
    });
    $btnExportCsv.addEventListener("click", function () { exportEvents("csv"); });
    $btnExportJson.addEventListener("click", function () { exportEvents("json"); });

    // Device search
    var devSearchTimer = null;
    $devicesSearch.addEventListener("input", function () {
        clearTimeout(devSearchTimer);
        devSearchTimer = setTimeout(function () {
            filterDevices();
            renderDevicesPage(0);
        }, 300);
    });

    // Blocklist filters
    $blFilterType.addEventListener("change", function () { loadBlocklist(0); });
    $blFilterSource.addEventListener("change", function () { loadBlocklist(0); });
    var blSearchTimer = null;
    $blSearch.addEventListener("input", function () {
        clearTimeout(blSearchTimer);
        blSearchTimer = setTimeout(function () { loadBlocklist(0); }, 400);
    });

    // === INIT ===
    var statsInterval = null;

    function initApp() {
        loadEvents(0);
        loadStats();
        loadDevices();
        populateEngineFilter();
        connectWS();
        if (!statsInterval) {
            statsInterval = setInterval(loadStats, 30000);
        }
    }

    // 인증 확인 후 앱 초기화
    checkAuth();
})();
