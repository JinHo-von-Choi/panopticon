# Engine Config UI Tooltips Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 대시보드 엔진 설정 UI에 각 설정값의 설명/범위/기본값을 JS 동적 툴팁으로 표시하여 Swagger docs 수준의 가독성을 제공한다.

**Architecture:** 백엔드 엔진의 `config_schema`를 tuple → dict 형식으로 확장하여 label/description/min/max 메타데이터를 추가하고, 프론트엔드에서 (?) 아이콘 호버 시 구조화된 툴팁을 표시한다. `schema_utils.py`가 이미 dict 형식을 지원하므로 백엔드 인프라 변경은 불필요하다.

**Tech Stack:** Python (DetectionEngine config_schema), Vanilla JS (동적 툴팁), CSS (툴팁 스타일)

**Critical Bug:** `schema_to_api()`는 `list[dict]`를 반환하지만 `renderEngineDetail()`이 `Object.keys(schema)`로 dict처럼 순회 → 필드명이 배열 인덱스("0","1",...)로 표시되고 config 값 매핑이 깨짐. Task 1에서 이를 먼저 수정한다.

---

### Task 1: Fix renderEngineDetail schema iteration bug + Add tooltip infrastructure

**Files:**
- Modify: `netwatcher/web/static/js/app.js:1035-1102` (renderEngineDetail function)
- Modify: `netwatcher/web/static/css/style.css:808-815` (engine field styles)

**Step 1: Fix renderEngineDetail to iterate schema as array**

`app.js`의 `renderEngineDetail` 함수를 수정한다. schema가 list 형태 `[{key, type, default, label, description, min, max}, ...]`임을 전제로 올바르게 순회하도록 변경한다.

변경 전 (buggy):
```js
var schema = eng.schema || {};
var config = eng.config || {};
var keys = Object.keys(schema);
// ...
for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (key === "enabled") continue;
    var fieldSchema = schema[key];
    var fieldVal = config[key];
    // ...
    html += '<label class="engine-field-label">' + esc(key) + '</label>';
```

변경 후 (fixed):
```js
var schemaList = Array.isArray(eng.schema) ? eng.schema : [];
var config = eng.config || {};

// ...
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
        html += '<span class="engine-tooltip-icon" data-field-key="' + esc(key) + '" '
            + 'data-field-type="' + esc(fieldType) + '" '
            + 'data-field-default="' + esc(String(fieldDefault !== undefined ? fieldDefault : '')) + '" '
            + 'data-field-min="' + esc(fieldMin !== undefined && fieldMin !== null ? String(fieldMin) : '') + '" '
            + 'data-field-max="' + esc(fieldMax !== undefined && fieldMax !== null ? String(fieldMax) : '') + '" '
            + 'data-field-desc="' + esc(fieldDesc) + '"'
            + '>?</span>';
    }
    html += '</div>';
```

나머지 input 렌더링은 기존 로직 유지 (key, fieldType, fieldVal 등 변수명은 동일하므로 input 생성 코드는 그대로 동작).

**Step 2: Add tooltip show/hide JS functions**

`app.js`의 IIFE 상단 (DOM refs 영역 아래, 약 line 160 근처)에 툴팁 함수를 추가한다:

```js
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
    var key = anchor.getAttribute("data-field-key");
    var type = anchor.getAttribute("data-field-type");
    var def = anchor.getAttribute("data-field-default");
    var min = anchor.getAttribute("data-field-min");
    var max = anchor.getAttribute("data-field-max");
    var desc = anchor.getAttribute("data-field-desc");

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

    // Position
    var rect = anchor.getBoundingClientRect();
    var tw = $tooltip.offsetWidth;
    var th = $tooltip.offsetHeight;
    var left = rect.left + rect.width / 2 - tw / 2;
    var top = rect.bottom + 8;

    // Boundary check
    if (left < 8) left = 8;
    if (left + tw > window.innerWidth - 8) left = window.innerWidth - 8 - tw;
    if (top + th > window.innerHeight - 8) {
        top = rect.top - th - 8;
    }

    $tooltip.style.left = left + "px";
    $tooltip.style.top = top + "px";
}

function hideTooltip() {
    if ($tooltip) $tooltip.style.display = "none";
}

// Delegate tooltip events on engine detail container
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
// Mobile touch toggle
document.addEventListener("click", function (e) {
    if (e.target.classList && e.target.classList.contains("engine-tooltip-icon")) {
        if ($tooltip && $tooltip.style.display === "block") {
            hideTooltip();
        } else {
            showTooltip(e.target);
        }
    } else if ($tooltip && $tooltip.style.display === "block") {
        hideTooltip();
    }
});
```

**Step 3: Add tooltip CSS styles**

`style.css`의 engine field 섹션(line 808 근처)에 추가:

```css
.engine-field-header { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
.engine-tooltip-icon {
    display: inline-flex; align-items: center; justify-content: center;
    width: 18px; height: 18px; border-radius: 50%;
    background: var(--surface2); border: 1px solid var(--border);
    color: var(--text-dim); font-size: 11px; font-weight: 700;
    cursor: pointer; flex-shrink: 0; user-select: none;
    transition: background 0.15s, color 0.15s;
}
.engine-tooltip-icon:hover { background: var(--accent); color: #fff; border-color: var(--accent); }
.engine-tooltip {
    position: fixed; z-index: 10000;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 12px 16px;
    max-width: 380px; min-width: 200px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    font-size: 13px; line-height: 1.5;
    pointer-events: none;
}
.tt-key { font-weight: 600; color: var(--accent); margin-bottom: 4px; font-family: var(--font-mono); font-size: 12px; }
.tt-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; font-family: var(--font-mono); }
.tt-desc { color: var(--text); }
```

**Step 4: Verify build**

Run: `.venv/bin/python -m pytest tests/test_detection/test_schema_utils.py -v`
Expected: All existing tests PASS (schema_utils.py 미변경)

**Step 5: Commit**

```bash
git add netwatcher/web/static/js/app.js netwatcher/web/static/css/style.css
git commit -m "fix(web): fix schema list iteration bug + add tooltip infrastructure for engine config UI"
```

---

### Task 2: Add descriptions to engines (Batch 1: arp_spoof, dns_anomaly, dns_response, port_scan, http_suspicious)

**Files:**
- Modify: `netwatcher/detection/engines/arp_spoof.py:27-32`
- Modify: `netwatcher/detection/engines/dns_anomaly.py:155-163`
- Modify: `netwatcher/detection/engines/dns_response.py:30-38`
- Modify: `netwatcher/detection/engines/port_scan.py:50-55`
- Modify: `netwatcher/detection/engines/http_suspicious.py:67-72`

**Step 1: Update arp_spoof.py config_schema**

```python
config_schema = {
    "gratuitous_window_seconds": {
        "type": int, "default": 30, "min": 5, "max": 300,
        "label": "Gratuitous ARP 윈도우(초)",
        "description": "Gratuitous ARP 패킷을 집계하는 슬라이딩 윈도우 길이. "
                       "짧게 설정하면 짧은 버스트만 탐지, 길게 설정하면 느린 스푸핑도 탐지.",
    },
    "gratuitous_threshold": {
        "type": int, "default": 10, "min": 2, "max": 100,
        "label": "Gratuitous ARP 임계값",
        "description": "윈도우 내 Gratuitous ARP 수가 이 값을 초과하면 알림 발생. "
                       "낮추면 민감도 증가(오탐 가능), 높이면 민감도 감소.",
    },
    "cooldown_seconds": {
        "type": int, "default": 300, "min": 10, "max": 3600,
        "label": "재알림 쿨다운(초)",
        "description": "동일 호스트에 대해 알림 재발송까지 대기하는 시간. "
                       "너무 짧으면 알림 폭주, 너무 길면 지속적 공격 누락 가능.",
    },
    "max_tracked_hosts": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 호스트 수",
        "description": "메모리에 유지하는 ARP 테이블 최대 크기. "
                       "네트워크 규모에 맞게 조정. 초과 시 오래된 엔트리부터 제거.",
    },
}
```

**Step 2: Update dns_anomaly.py config_schema**

```python
config_schema = {
    "max_label_length": {
        "type": int, "default": 50, "min": 10, "max": 253,
        "label": "최대 라벨 길이",
        "description": "DNS 라벨(서브도메인 구성요소) 길이가 이 값을 초과하면 DNS 터널링 의심 알림 발생. "
                       "정상 도메인은 보통 30자 미만.",
    },
    "max_subdomain_depth": {
        "type": int, "default": 7, "min": 3, "max": 20,
        "label": "최대 서브도메인 깊이",
        "description": "서브도메인 깊이(점으로 구분된 단계 수)가 이 값을 초과하면 알림 발생. "
                       "CDN/클라우드 도메인은 5~6단계가 정상일 수 있으므로 7 권장.",
    },
    "entropy_threshold": {
        "type": float, "default": 3.8, "min": 2.0, "max": 5.0,
        "label": "Shannon 엔트로피 임계값",
        "description": "DNS 라벨의 Shannon 엔트로피가 이 값을 초과하면 DGA(Domain Generation Algorithm) 의심. "
                       "높은 엔트로피 = 무작위 문자열. 낮추면 오탐 증가, 높이면 미탐 증가.",
    },
    "high_volume_threshold": {
        "type": int, "default": 200, "min": 10, "max": 10000,
        "label": "대량 쿼리 임계값",
        "description": "윈도우 내 단일 호스트의 DNS 쿼리 수가 이 값을 초과하면 알림 발생. "
                       "DNS 터널링이나 데이터 유출 시 대량 쿼리가 발생함.",
    },
    "high_volume_window_seconds": {
        "type": int, "default": 60, "min": 10, "max": 600,
        "label": "대량 쿼리 윈도우(초)",
        "description": "DNS 쿼리 볼륨을 집계하는 시간 윈도우. "
                       "짧으면 순간 버스트 탐지, 길면 평균적 과다 사용 탐지.",
    },
    "dga_min_label_length": {
        "type": int, "default": 10, "min": 4, "max": 30,
        "label": "DGA 최소 라벨 길이",
        "description": "DGA 분석을 수행할 최소 라벨 길이. "
                       "짧은 라벨은 엔트로피 분석이 부정확하므로 10자 이상 권장.",
    },
    "dga_confidence_threshold": {
        "type": float, "default": 0.5, "min": 0.1, "max": 1.0,
        "label": "DGA 신뢰도 임계값",
        "description": "복합 DGA 점수(엔트로피+자음비율+길이)가 이 값을 초과하면 DGA로 판정. "
                       "낮추면 민감도 증가(오탐 증가), 높이면 확실한 DGA만 탐지.",
    },
}
```

**Step 3: Update dns_response.py config_schema**

```python
config_schema = {
    "flux_min_ips": {
        "type": int, "default": 10, "min": 3, "max": 100,
        "label": "Fast-flux 최소 IP 수",
        "description": "단일 도메인에 매핑된 고유 IP 수가 이 값을 초과하면 Fast-flux 의심. "
                       "CDN 도메인도 다수 IP를 사용하므로 화이트리스트와 병행 권장.",
    },
    "flux_max_ttl": {
        "type": int, "default": 300, "min": 10, "max": 3600,
        "label": "Fast-flux 최대 TTL(초)",
        "description": "DNS 응답 TTL이 이 값 이하이면서 다수 IP가 관측되면 Fast-flux로 판정. "
                       "Fast-flux 도메인은 짧은 TTL로 빠르게 IP를 교체함.",
    },
    "flux_window_seconds": {
        "type": int, "default": 3600, "min": 300, "max": 86400,
        "label": "Fast-flux 분석 윈도우(초)",
        "description": "Fast-flux IP 수를 집계하는 시간 윈도우. "
                       "기본값 1시간. 길게 설정하면 느린 flux도 탐지하나 메모리 사용 증가.",
    },
    "nxdomain_threshold": {
        "type": int, "default": 10, "min": 3, "max": 1000,
        "label": "NXDOMAIN 임계값",
        "description": "윈도우 내 단일 IP의 NXDOMAIN 응답 수가 이 값을 초과하면 알림 발생. "
                       "DGA 악성코드는 다수의 무작위 도메인을 질의하여 NXDOMAIN을 유발함.",
    },
    "nxdomain_window_seconds": {
        "type": int, "default": 60, "min": 10, "max": 600,
        "label": "NXDOMAIN 윈도우(초)",
        "description": "NXDOMAIN 응답을 집계하는 시간 윈도우.",
    },
    "max_domains": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 도메인 수",
        "description": "메모리에 유지하는 도메인 추적 테이블 크기. "
                       "네트워크 트래픽 규모에 맞게 조정.",
    },
    "max_tracked_ips": {
        "type": int, "default": 5000, "min": 100, "max": 100000,
        "label": "최대 추적 IP 수",
        "description": "NXDOMAIN 추적용 IP 테이블 크기.",
    },
}
```

**Step 4: Update port_scan.py config_schema**

```python
config_schema = {
    "window_seconds": {
        "type": int, "default": 60, "min": 5, "max": 600,
        "label": "탐지 윈도우(초)",
        "description": "포트 스캔 활동을 집계하는 시간 윈도우. "
                       "짧으면 빠른 스캔만 탐지, 길면 느린 스텔스 스캔도 탐지.",
    },
    "threshold": {
        "type": int, "default": 15, "min": 3, "max": 1000,
        "label": "포트 수 임계값",
        "description": "윈도우 내 (출발지→목적지) 쌍에서 스캔된 고유 포트 수가 이 값을 초과하면 알림 발생. "
                       "낮추면 민감도 증가(소규모 스캔도 탐지), 높이면 대규모 스캔만 탐지.",
    },
    "alerted_cooldown_seconds": {
        "type": int, "default": 300, "min": 10, "max": 3600,
        "label": "재알림 쿨다운(초)",
        "description": "동일 (출발지→목적지) 쌍에 대해 알림 재발송까지 대기 시간.",
    },
    "max_tracked_connections": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 연결 수",
        "description": "메모리에 유지하는 (출발지, 목적지) 쌍의 최대 수. "
                       "대규모 네트워크에서는 증가 필요.",
    },
}
```

**Step 5: Update http_suspicious.py config_schema**

```python
config_schema = {
    "beacon_interval_tolerance": {
        "type": float, "default": 0.15, "min": 0.01, "max": 0.5,
        "label": "비컨 간격 허용 편차",
        "description": "C2 비컨 판정 시 접속 간격의 변동계수(CV) 임계값. "
                       "0.15 = 15% 이내 편차면 규칙적 접속으로 판단. "
                       "낮추면 엄격한 판정(정확한 주기만 탐지), 높이면 느슨한 판정.",
    },
    "min_beacon_count": {
        "type": int, "default": 5, "min": 3, "max": 50,
        "label": "최소 비컨 횟수",
        "description": "C2 비컨 판정에 필요한 최소 접속 횟수. "
                       "낮추면 빠른 탐지(오탐 가능), 높이면 확실한 패턴만 탐지.",
    },
    "beacon_window_seconds": {
        "type": int, "default": 3600, "min": 300, "max": 86400,
        "label": "비컨 분석 윈도우(초)",
        "description": "C2 비컨 패턴을 분석하는 시간 윈도우. "
                       "기본값 1시간. 길게 설정하면 긴 주기 비컨도 탐지.",
    },
    "max_tracked_pairs": {
        "type": int, "default": 5000, "min": 100, "max": 100000,
        "label": "최대 추적 쌍 수",
        "description": "메모리에 유지하는 (출발지IP, 호스트) 쌍의 최대 수.",
    },
}
```

**Step 6: Run tests**

Run: `.venv/bin/python -m pytest tests/test_detection/test_schema_utils.py tests/test_detection/test_arp_spoof.py tests/test_detection/test_dns_anomaly.py tests/test_detection/test_port_scan.py -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add netwatcher/detection/engines/arp_spoof.py netwatcher/detection/engines/dns_anomaly.py \
    netwatcher/detection/engines/dns_response.py netwatcher/detection/engines/port_scan.py \
    netwatcher/detection/engines/http_suspicious.py
git commit -m "feat(engines): add descriptions to config_schema (batch 1: arp, dns, port_scan, http)"
```

---

### Task 3: Add descriptions to engines (Batch 2: traffic_anomaly, tls_fingerprint, icmp_anomaly, dhcp_spoof, lateral_movement, data_exfil)

**Files:**
- Modify: `netwatcher/detection/engines/traffic_anomaly.py:61`
- Modify: `netwatcher/detection/engines/tls_fingerprint.py:425`
- Modify: `netwatcher/detection/engines/icmp_anomaly.py:37`
- Modify: `netwatcher/detection/engines/dhcp_spoof.py:42`
- Modify: `netwatcher/detection/engines/lateral_movement.py:30`
- Modify: `netwatcher/detection/engines/data_exfil.py:25`

**Step 1: Update traffic_anomaly.py config_schema**

```python
config_schema = {
    "volume_threshold_multiplier": {
        "type": float, "default": 3.0, "min": 1.5, "max": 20.0,
        "label": "볼륨 임계 배율",
        "description": "호스트 트래픽이 기준선(평균) 대비 이 배율을 초과하면 알림 발생. "
                       "3.0 = 평균의 3배. 낮추면 민감도 증가, 높이면 극단적 이상만 탐지.",
    },
    "min_baseline_bytes": {
        "type": int, "default": 1000, "min": 100, "max": 1000000,
        "label": "최소 기준선(bytes)",
        "description": "기준선이 이 값 이상인 호스트만 볼륨 이상 탐지 대상. "
                       "너무 낮으면 트래픽이 거의 없는 호스트에서 오탐 발생.",
    },
    "warmup_ticks": {
        "type": int, "default": 30, "min": 5, "max": 600,
        "label": "워밍업 틱 수",
        "description": "이상 탐지가 활성화되기까지 필요한 틱(초) 수. "
                       "기준선 학습에 충분한 시간 확보. 짧으면 부정확한 기준선으로 오탐 발생.",
    },
    "z_score_threshold": {
        "type": float, "default": 3.0, "min": 1.0, "max": 10.0,
        "label": "Z-Score 임계값",
        "description": "Welford 알고리즘 기반 Z-Score가 이 값을 초과하면 이상 탐지. "
                       "3.0 = 표준편차 3배 이상 편차. 통계적 이상치 탐지 기준.",
    },
    "host_eviction_seconds": {
        "type": int, "default": 86400, "min": 3600, "max": 604800,
        "label": "호스트 제거 시간(초)",
        "description": "이 시간 동안 관측되지 않은 호스트를 추적 테이블에서 제거. "
                       "기본값 24시간. 메모리 관리용.",
    },
    "max_tracked_hosts": {
        "type": int, "default": 50000, "min": 100, "max": 1000000,
        "label": "최대 추적 호스트 수",
        "description": "메모리에 유지하는 호스트 통계 테이블 크기.",
    },
}
```

**Step 2: Update tls_fingerprint.py config_schema**

```python
config_schema = {
    "check_ja3": {
        "type": bool, "default": True,
        "label": "JA3 핑거프린트 검사",
        "description": "TLS Client Hello의 JA3 핑거프린트를 수집/분석. "
                       "악성 도구(Cobalt Strike 등)의 알려진 JA3 해시와 매칭.",
    },
    "check_ja3s": {
        "type": bool, "default": True,
        "label": "JA3S 핑거프린트 검사",
        "description": "TLS Server Hello의 JA3S 핑거프린트를 수집/분석. "
                       "C2 서버의 특징적 TLS 응답 패턴을 탐지.",
    },
    "check_ja4": {
        "type": bool, "default": True,
        "label": "JA4 핑거프린트 검사",
        "description": "차세대 TLS 핑거프린트(JA4). JA3보다 정확한 클라이언트 식별 제공.",
    },
    "check_sni": {
        "type": bool, "default": True,
        "label": "SNI 검사",
        "description": "TLS Server Name Indication 필드를 분석. "
                       "SNI 누락 또는 IP 직접 접속 시 알림(정상 HTTPS는 SNI 포함).",
    },
    "check_cert": {
        "type": bool, "default": True,
        "label": "인증서 검사",
        "description": "TLS 인증서의 유효기간, 자체서명 여부, Subject 이상 등을 분석.",
    },
    "detect_tunnels": {
        "type": bool, "default": True,
        "label": "TLS 터널 탐지",
        "description": "TLS 트래픽 패턴으로 VPN/터널 사용을 탐지. "
                       "패킷 크기 분포의 변동계수(CV)가 낮으면 터널 의심.",
    },
    "tunnel_min_packets": {
        "type": int, "default": 30, "min": 10, "max": 500,
        "label": "터널 탐지 최소 패킷 수",
        "description": "터널 분석에 필요한 최소 패킷 수. 충분한 샘플이 있어야 정확한 판정 가능.",
    },
    "tunnel_cv_threshold": {
        "type": float, "default": 0.05, "min": 0.01, "max": 0.5,
        "label": "터널 CV 임계값",
        "description": "패킷 크기 변동계수(CV)가 이 값 이하이면 터널로 판정. "
                       "터널 트래픽은 패킷 크기가 매우 균일(낮은 CV).",
    },
    "max_tracked_flows": {
        "type": int, "default": 5000, "min": 100, "max": 100000,
        "label": "최대 추적 플로우 수",
        "description": "메모리에 유지하는 TLS 플로우 추적 테이블 크기.",
    },
    "detect_esni": {
        "type": bool, "default": True,
        "label": "ESNI/ECH 탐지",
        "description": "Encrypted SNI / Encrypted Client Hello 사용을 탐지. "
                       "정상 용도도 있으나 악성 트래픽 은닉에도 사용될 수 있음.",
    },
}
```

**Step 3: Update icmp_anomaly.py config_schema**

```python
config_schema = {
    "ping_sweep_threshold": {
        "type": int, "default": 20, "min": 3, "max": 1000,
        "label": "Ping Sweep 임계값",
        "description": "단일 출발지에서 윈도우 내 ICMP Echo를 보낸 고유 목적지 IP 수가 이 값을 초과하면 "
                       "네트워크 스캔(Ping Sweep) 알림 발생.",
    },
    "ping_sweep_window_seconds": {
        "type": int, "default": 30, "min": 5, "max": 300,
        "label": "Ping Sweep 윈도우(초)",
        "description": "Ping Sweep 활동을 집계하는 시간 윈도우.",
    },
    "flood_threshold": {
        "type": int, "default": 100, "min": 10, "max": 10000,
        "label": "ICMP Flood 임계값(pps)",
        "description": "윈도우 내 단일 출발지의 ICMP 패킷 수가 이 값을 초과하면 Flood 알림. "
                       "ICMP Flood 공격(DoS)이나 Smurf 공격 탐지용.",
    },
    "flood_window_seconds": {
        "type": int, "default": 1, "min": 1, "max": 60,
        "label": "ICMP Flood 윈도우(초)",
        "description": "ICMP Flood를 감지하는 시간 윈도우. 기본값 1초(초당 패킷 기준).",
    },
    "max_tracked_sources": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 출발지 수",
        "description": "메모리에 유지하는 ICMP 출발지 추적 테이블 크기.",
    },
    "cooldown_seconds": {
        "type": int, "default": 300, "min": 10, "max": 3600,
        "label": "재알림 쿨다운(초)",
        "description": "동일 출발지에 대해 알림 재발송까지 대기 시간.",
    },
}
```

**Step 4: Update dhcp_spoof.py config_schema**

```python
config_schema = {
    "starvation_threshold": {
        "type": int, "default": 50, "min": 5, "max": 1000,
        "label": "DHCP Starvation 임계값",
        "description": "윈도우 내 DHCP DISCOVER 패킷 수가 이 값을 초과하면 "
                       "DHCP 고갈 공격(Starvation) 알림 발생. "
                       "공격자가 모든 IP를 소진시키려는 시도 탐지.",
    },
    "starvation_window_seconds": {
        "type": int, "default": 60, "min": 10, "max": 600,
        "label": "Starvation 윈도우(초)",
        "description": "DHCP Starvation 활동을 집계하는 시간 윈도우.",
    },
    "known_servers": {
        "type": list, "default": [],
        "label": "정상 DHCP 서버 IP 목록",
        "description": "정상 DHCP 서버의 IP 주소 목록 (쉼표 구분). "
                       "비어있으면 처음 관측된 서버를 자동 학습. "
                       "목록에 없는 서버가 DHCP OFFER를 보내면 Rogue DHCP 알림.",
    },
}
```

**Step 5: Update lateral_movement.py config_schema**

```python
config_schema = {
    "lateral_ports": {
        "type": list, "default": [22, 445, 3389, 135, 5985, 5986, 23, 3306, 5432, 1433, 6379, 27017],
        "label": "측면 이동 감시 포트",
        "description": "측면 이동에 사용되는 포트 목록 (쉼표 구분). "
                       "SSH(22), SMB(445), RDP(3389), WinRM(5985), DB 포트 등. "
                       "내부 네트워크에서 이 포트들의 비정상 접근 패턴을 감시.",
    },
    "unique_host_threshold": {
        "type": int, "default": 5, "min": 2, "max": 50,
        "label": "고유 호스트 임계값",
        "description": "단일 출발지가 윈도우 내 접근한 고유 내부 호스트 수가 이 값을 초과하면 알림. "
                       "측면 이동 시 공격자는 여러 내부 호스트를 순차적으로 탐색함.",
    },
    "window_seconds": {
        "type": int, "default": 300, "min": 60, "max": 3600,
        "label": "탐지 윈도우(초)",
        "description": "측면 이동 활동을 집계하는 시간 윈도우. 기본값 5분.",
    },
    "chain_depth_threshold": {
        "type": int, "default": 3, "min": 2, "max": 10,
        "label": "체인 깊이 임계값",
        "description": "A→B→C→D 형태의 접근 체인 깊이가 이 값을 초과하면 알림. "
                       "측면 이동의 전형적인 패턴(피벗 체인) 탐지.",
    },
    "max_tracked_connections": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 연결 수",
        "description": "메모리에 유지하는 연결 추적 테이블 크기.",
    },
}
```

**Step 6: Update data_exfil.py config_schema**

```python
config_schema = {
    "byte_threshold": {
        "type": int, "default": 104857600, "min": 1048576, "max": 10737418240,
        "label": "전송량 임계값(bytes)",
        "description": "윈도우 내 단일 (출발지→목적지) 쌍의 전송량이 이 값을 초과하면 데이터 유출 의심 알림. "
                       "기본값 100MB/시간. 네트워크 정상 트래픽 규모에 맞게 조정.",
    },
    "window_seconds": {
        "type": int, "default": 3600, "min": 300, "max": 86400,
        "label": "분석 윈도우(초)",
        "description": "데이터 전송량을 집계하는 시간 윈도우. 기본값 1시간.",
    },
    "dns_txt_size_threshold": {
        "type": int, "default": 500, "min": 50, "max": 5000,
        "label": "DNS TXT 크기 임계값(bytes)",
        "description": "DNS TXT 레코드 크기가 이 값을 초과하면 DNS 터널링 통한 데이터 유출 의심. "
                       "정상 TXT 레코드는 보통 수십~수백 bytes.",
    },
    "max_tracked_pairs": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 쌍 수",
        "description": "메모리에 유지하는 (출발지, 목적지) 쌍의 최대 수.",
    },
}
```

**Step 7: Run tests**

Run: `.venv/bin/python -m pytest tests/test_detection/ -v --tb=short`
Expected: All PASS

**Step 8: Commit**

```bash
git add netwatcher/detection/engines/traffic_anomaly.py netwatcher/detection/engines/tls_fingerprint.py \
    netwatcher/detection/engines/icmp_anomaly.py netwatcher/detection/engines/dhcp_spoof.py \
    netwatcher/detection/engines/lateral_movement.py netwatcher/detection/engines/data_exfil.py
git commit -m "feat(engines): add descriptions to config_schema (batch 2: traffic, tls, icmp, dhcp, lateral, exfil)"
```

---

### Task 4: Add descriptions to engines (Batch 3: protocol_anomaly, mac_spoof, protocol_inspect, behavior_profile, signature)

**Files:**
- Modify: `netwatcher/detection/engines/protocol_anomaly.py:38`
- Modify: `netwatcher/detection/engines/mac_spoof.py:52`
- Modify: `netwatcher/detection/engines/protocol_inspect.py:127`
- Modify: `netwatcher/detection/engines/behavior_profile.py:119`
- Modify: `netwatcher/detection/engines/signature.py:274`

**Step 1: Update protocol_anomaly.py config_schema**

```python
config_schema = {
    "ttl_change_threshold": {
        "type": int, "default": 10, "min": 1, "max": 128,
        "label": "TTL 변화 임계값",
        "description": "동일 출발지 IP의 TTL 값 변화가 이 값을 초과하면 알림. "
                       "TTL 급변은 경로 변경 또는 중간자 공격(MITM)을 의미할 수 있음.",
    },
    "min_ttl_samples": {
        "type": int, "default": 5, "min": 2, "max": 100,
        "label": "최소 TTL 샘플 수",
        "description": "TTL 이상 탐지 전 수집해야 하는 최소 패킷 수. "
                       "샘플이 적으면 정상적인 TTL 변동도 이상으로 오탐할 수 있음.",
    },
}
```

**Step 2: Update mac_spoof.py config_schema**

```python
config_schema = {
    "max_ips_per_mac": {
        "type": int, "default": 5, "min": 2, "max": 50,
        "label": "MAC당 최대 IP 수",
        "description": "단일 MAC 주소에서 윈도우 내 사용된 고유 IP 수가 이 값을 초과하면 MAC 스푸핑 의심. "
                       "DHCP 환경에서는 IP 변경이 정상이므로 적절히 조정.",
    },
    "ip_window_seconds": {
        "type": int, "default": 300, "min": 60, "max": 3600,
        "label": "IP 추적 윈도우(초)",
        "description": "MAC-IP 바인딩을 추적하는 시간 윈도우. 기본값 5분.",
    },
    "max_tracked_macs": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 MAC 수",
        "description": "메모리에 유지하는 MAC 추적 테이블 크기.",
    },
}
```

**Step 3: Update protocol_inspect.py config_schema**

```python
config_schema = {
    "suspicious_user_agents": {
        "type": list, "default": _DEFAULT_SUSPICIOUS_UAS,
        "label": "의심 User-Agent 목록",
        "description": "HTTP User-Agent에 이 문자열이 포함되면 보안 도구 사용 의심 알림. "
                       "Nmap, sqlmap, Nikto 등 공격 도구의 기본 UA 패턴.",
    },
    "sensitive_paths": {
        "type": list, "default": _DEFAULT_SENSITIVE_PATHS,
        "label": "민감 경로 목록",
        "description": "이 경로에 대한 HTTP 요청 시 알림. "
                       "/admin, /.env, /wp-login.php 등 공격 대상이 되는 경로.",
    },
    "check_response": {
        "type": bool, "default": True,
        "label": "HTTP 응답 분석",
        "description": "HTTP 응답도 분석하여 에러 코드 패턴(다수 403/404) 탐지. "
                       "비활성화하면 요청만 분석.",
    },
    "max_tracked_responses": {
        "type": int, "default": 5000, "min": 100, "max": 100000,
        "label": "최대 추적 응답 수",
        "description": "메모리에 유지하는 HTTP 응답 추적 테이블 크기.",
    },
    "smtp_ports": {
        "type": list, "default": [25, 587, 465],
        "label": "SMTP 포트 목록",
        "description": "SMTP 프로토콜로 분석할 포트 번호 (쉼표 구분).",
    },
    "ftp_ports": {
        "type": list, "default": [20, 21],
        "label": "FTP 포트 목록",
        "description": "FTP 프로토콜로 분석할 포트 번호 (쉼표 구분).",
    },
    "ssh_port": {
        "type": int, "default": 22, "min": 1, "max": 65535,
        "label": "SSH 포트",
        "description": "SSH 프로토콜로 분석할 포트 번호.",
    },
    "sensitive_files": {
        "type": list, "default": _DEFAULT_SENSITIVE_FILES,
        "label": "민감 파일 목록",
        "description": "FTP에서 이 파일에 대한 접근 시 알림. "
                       ".env, passwd, id_rsa 등 민감 파일.",
    },
    "smtp_auth_threshold": {
        "type": int, "default": 5, "min": 2, "max": 100,
        "label": "SMTP 인증 실패 임계값",
        "description": "윈도우 내 SMTP 인증 실패 횟수가 이 값을 초과하면 무차별 대입 공격 의심.",
    },
    "smtp_auth_window": {
        "type": int, "default": 300, "min": 60, "max": 3600,
        "label": "SMTP 인증 윈도우(초)",
        "description": "SMTP 인증 실패를 집계하는 시간 윈도우. 기본값 5분.",
    },
    "ftp_fail_threshold": {
        "type": int, "default": 5, "min": 2, "max": 100,
        "label": "FTP 실패 임계값",
        "description": "윈도우 내 FTP 로그인 실패 횟수가 이 값을 초과하면 무차별 대입 공격 의심.",
    },
    "ftp_fail_window": {
        "type": int, "default": 300, "min": 60, "max": 3600,
        "label": "FTP 실패 윈도우(초)",
        "description": "FTP 로그인 실패를 집계하는 시간 윈도우. 기본값 5분.",
    },
    "max_tracked_sources": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 출발지 수",
        "description": "메모리에 유지하는 프로토콜 분석 출발지 추적 테이블 크기.",
    },
}
```

**Step 4: Update behavior_profile.py config_schema**

```python
config_schema = {
    "warmup_ticks": {
        "type": int, "default": 300, "min": 30, "max": 3600,
        "label": "워밍업 틱 수",
        "description": "행위 프로파일링이 활성화되기까지 필요한 틱(초) 수. "
                       "호스트별 정상 행위 기준선 학습에 필요한 시간. "
                       "짧으면 부정확한 프로파일로 오탐 발생.",
    },
    "z_threshold": {
        "type": float, "default": 3.5, "min": 1.0, "max": 10.0,
        "label": "Z-Score 임계값",
        "description": "호스트 행위의 Z-Score가 이 값을 초과하면 이상 행위 알림. "
                       "3.5 = 표준편차 3.5배 이상 편차. 낮추면 민감도 증가.",
    },
    "max_tracked_hosts": {
        "type": int, "default": 10000, "min": 100, "max": 1000000,
        "label": "최대 추적 호스트 수",
        "description": "메모리에 유지하는 행위 프로파일 테이블 크기.",
    },
    "eviction_seconds": {
        "type": int, "default": 86400, "min": 3600, "max": 604800,
        "label": "호스트 제거 시간(초)",
        "description": "이 시간 동안 관측되지 않은 호스트의 프로파일을 제거. 기본값 24시간.",
    },
}
```

**Step 5: Update signature.py config_schema**

```python
config_schema = {
    "rules_dir": {
        "type": str, "default": "config/rules",
        "label": "규칙 디렉토리 경로",
        "description": "YAML 시그니처 규칙 파일이 위치한 디렉토리. "
                       "이 경로의 *.yaml 파일을 모두 로드함.",
    },
    "hot_reload": {
        "type": bool, "default": True,
        "label": "핫 리로드",
        "description": "활성화 시 규칙 파일 변경을 자동 감지하여 리로드. "
                       "비활성화하면 엔진 재시작 시에만 규칙 로드.",
    },
}
```

**Step 6: Run full test suite**

Run: `.venv/bin/python -m pytest tests/test_detection/ -v --tb=short`
Expected: All PASS

**Step 7: Commit**

```bash
git add netwatcher/detection/engines/protocol_anomaly.py netwatcher/detection/engines/mac_spoof.py \
    netwatcher/detection/engines/protocol_inspect.py netwatcher/detection/engines/behavior_profile.py \
    netwatcher/detection/engines/signature.py
git commit -m "feat(engines): add descriptions to config_schema (batch 3: protocol, mac, inspect, behavior, signature)"
```

---

### Task 5: Final integration test + commit

**Step 1: Run full test suite**

Run: `.venv/bin/python -m pytest tests/ -v --tb=short`
Expected: All PASS

**Step 2: Manual verification checklist**

서버를 시작하고 브라우저에서 확인:
- Engines 탭에서 각 엔진 클릭 시 config 필드가 올바른 label로 표시되는지
- (?) 아이콘 호버 시 툴팁에 type, default, range, description이 표시되는지
- config 값 변경 후 Save가 정상 동작하는지
- 모바일(또는 좁은 화면)에서 툴팁이 화면 밖으로 나가지 않는지

**Step 3: Commit design doc + plan**

```bash
git add docs/plans/2026-02-23-engine-config-tooltips-design.md docs/plans/2026-02-23-engine-config-tooltips.md
git commit -m "docs: add engine config tooltips design and implementation plan"
```
