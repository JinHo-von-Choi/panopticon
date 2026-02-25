# Enterprise IDS Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** NetWatcher에 6개 엔터프라이즈 IDS 기능을 추가하여 탐지 범위와 대응 능력을 확장한다.

**Architecture:** 기존 DetectionEngine 플러그인 구조를 최대한 활용한다. 각 기능은 독립적인 엔진/모듈로 구현되며, 기존 파이프라인(캡처 → 분석 → 알림 → 저장)에 자연스럽게 통합된다. 새 모듈은 `netwatcher/` 하위에 기능별 패키지로 분리한다.

**Tech Stack:** Python 3.12, Scapy (TLS layer), asyncio, iptables/nftables CLI, yara-python (optional), tshark (optional)

**Priority Order:**
1. ETA (암호화 트래픽 분석) — 기존 TLS 엔진 확장
2. IRS (반응형 차단) — iptables 연동
3. Signature Engine (YAML 룰셋)
4. Protocol Parsers (HTTP/SMTP/FTP/SSH)
5. Behavioral Profiling (다차원 통계)
6. File Extraction (PCAP 후처리 + YARA)

---

## Feature 1: Encrypted Traffic Analysis (ETA)

### Task 1.1: JA3S (Server Fingerprint)

**Files:**
- Modify: `netwatcher/detection/engines/tls_fingerprint.py`
- Test: `tests/test_detection/test_tls_eta.py`

**Step 1: Write failing test for compute_ja3s**

```python
# tests/test_detection/test_tls_eta.py
import pytest
from netwatcher.detection.engines.tls_fingerprint import compute_ja3s

class TestJA3S:
    def test_compute_ja3s_basic(self):
        """JA3S = MD5(SSLVersion,Cipher,Extensions)"""
        class FakeServerHello:
            version = 0x0303  # TLS 1.2
            cipher = 0xC02F   # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            ext = []
        result = compute_ja3s(FakeServerHello())
        assert result is not None
        assert len(result) == 32  # MD5 hex digest

    def test_compute_ja3s_with_extensions(self):
        class FakeExt:
            def __init__(self, t):
                self.type = t
        class FakeServerHello:
            version = 0x0303
            cipher = 0xC02F
            ext = [FakeExt(0), FakeExt(11), FakeExt(65281)]
        result = compute_ja3s(FakeServerHello())
        assert result is not None

    def test_compute_ja3s_grease_filtered(self):
        class FakeExt:
            def __init__(self, t):
                self.type = t
        class FakeServerHello:
            version = 0x0303
            cipher = 0xC02F
            ext = [FakeExt(0x0A0A), FakeExt(11)]  # 0x0A0A = GREASE
        result = compute_ja3s(FakeServerHello())
        # GREASE extension should be filtered
        assert result is not None
```

Run: `.venv/bin/python -m pytest tests/test_detection/test_tls_eta.py::TestJA3S -v`
Expected: FAIL — `compute_ja3s` not defined

**Step 2: Implement compute_ja3s**

Add to `netwatcher/detection/engines/tls_fingerprint.py` after `compute_ja3()`:

```python
def compute_ja3s(server_hello) -> str | None:
    """Compute JA3S hash from a TLS ServerHello layer.

    JA3S = MD5(SSLVersion,Cipher,Extensions)
    """
    try:
        version = server_hello.version
        if version is None:
            return None

        cipher = server_hello.cipher
        if cipher is None:
            return None
        cipher_val = cipher if isinstance(cipher, int) else int(cipher)

        extensions = []
        if server_hello.ext:
            for ext in server_hello.ext:
                ext_type = getattr(ext, "type", None)
                if ext_type is None:
                    continue
                ext_val = ext_type if isinstance(ext_type, int) else int(ext_type)
                if not _is_grease(ext_val):
                    extensions.append(str(ext_val))

        ja3s_str = ",".join([
            str(version),
            str(cipher_val),
            "-".join(extensions),
        ])
        return hashlib.md5(ja3s_str.encode()).hexdigest()
    except Exception:
        logger.debug("Failed to compute JA3S hash", exc_info=True)
        return None
```

Run: `.venv/bin/python -m pytest tests/test_detection/test_tls_eta.py::TestJA3S -v`
Expected: PASS

**Step 3: Integrate JA3S into TLSFingerprintEngine.analyze()**

In `TLSFingerprintEngine`:
- Add `_get_server_hello()` static method (mirrors `_get_client_hello`)
- Track `(src_ip, dst_ip) -> ja3_hash` in dict for client-server pairing
- On ServerHello: compute JA3S, combine with stored JA3 for correlation
- Add `ja3s_hash` to alert metadata when JA3 match fires

**Step 4: Commit**

```bash
git add netwatcher/detection/engines/tls_fingerprint.py tests/test_detection/test_tls_eta.py
git commit -m "feat(eta): add JA3S server fingerprinting"
```

---

### Task 1.2: TLS Certificate Chain Analysis

**Files:**
- Modify: `netwatcher/detection/engines/tls_fingerprint.py`
- Test: `tests/test_detection/test_tls_eta.py`

**Step 1: Write failing tests for certificate analysis**

```python
class TestCertAnalysis:
    def test_self_signed_detected(self):
        engine = _make_engine({"check_cert": True})
        # Simulate Certificate message with issuer == subject
        cert_info = {"issuer": "CN=evil.com", "subject": "CN=evil.com", "not_after": "2027-01-01"}
        alert = engine._analyze_certificate(cert_info, "1.2.3.4", "5.6.7.8")
        assert alert is not None
        assert "self-signed" in alert.title.lower()

    def test_expired_cert_detected(self):
        engine = _make_engine({"check_cert": True})
        cert_info = {"issuer": "CN=CA", "subject": "CN=test.com", "not_after": "2020-01-01"}
        alert = engine._analyze_certificate(cert_info, "1.2.3.4", "5.6.7.8")
        assert alert is not None
        assert "expired" in alert.title.lower()

    def test_valid_cert_no_alert(self):
        engine = _make_engine({"check_cert": True})
        cert_info = {"issuer": "CN=DigiCert", "subject": "CN=google.com", "not_after": "2027-01-01"}
        alert = engine._analyze_certificate(cert_info, "1.2.3.4", "5.6.7.8")
        assert alert is None
```

**Step 2: Implement `_analyze_certificate()` method**

Extract certificate info from Scapy's `TLSCertificate` layer:
- Self-signed detection: `issuer == subject`
- Expiry check: `not_after < now`
- SNI mismatch: certificate CN/SAN vs ClientHello SNI
- Short validity period (< 30 days): suspicious

**Step 3: Add `check_cert` config option**

```python
config_schema = {
    "check_ja3": (bool, True),
    "check_sni": (bool, True),
    "check_cert": (bool, True),
}
```

**Step 4: Commit**

```bash
git commit -m "feat(eta): add TLS certificate chain analysis"
```

---

### Task 1.3: JA4+ Fingerprinting

**Files:**
- Modify: `netwatcher/detection/engines/tls_fingerprint.py`
- Test: `tests/test_detection/test_tls_eta.py`

**Step 1: Write failing test for JA4 computation**

```python
class TestJA4:
    def test_compute_ja4_basic(self):
        from netwatcher.detection.engines.tls_fingerprint import compute_ja4
        class FakeClientHello:
            version = 0x0303
            ciphers = [0xC02F, 0xC030]
            ext = []
        result = compute_ja4(FakeClientHello())
        assert result is not None
        # JA4 format: t{version}{sni}{ciphers_count}{ext_count}_{cipher_hash}_{ext_hash}
        assert "_" in result
```

**Step 2: Implement JA4 computation**

JA4 algorithm:
1. Protocol type (t=TCP, q=QUIC)
2. TLS version (12=TLS1.2, 13=TLS1.3)
3. SNI presence (d=domain, i=IP, x=none)
4. Cipher count (2 digits)
5. Extension count (2 digits)
6. ALPN first value (first 2 chars)
7. `_` separator
8. SHA256 of sorted cipher suites (first 12 hex chars)
9. `_` separator
10. SHA256 of sorted extensions + sig algorithms (first 12 hex chars)

**Step 3: Add JA4 to blocked fingerprint set and alert metadata**

**Step 4: Commit**

```bash
git commit -m "feat(eta): add JA4+ fingerprinting"
```

---

### Task 1.4: Encrypted Tunnel Detection (Packet Size/Timing)

**Files:**
- Modify: `netwatcher/detection/engines/tls_fingerprint.py`
- Test: `tests/test_detection/test_tls_eta.py`

**Step 1: Write failing test**

```python
class TestTunnelDetection:
    def test_uniform_packet_size_detected(self):
        """VPN/tunnel traffic has very uniform packet sizes."""
        engine = _make_engine({"detect_tunnels": True})
        # Feed 50 packets of nearly identical size to same dst
        for _ in range(50):
            pkt = _make_tls_packet(size=1400)  # ±5 bytes
            engine.analyze(pkt)
        alerts = engine.on_tick(0)
        assert any("tunnel" in a.title.lower() for a in alerts)
```

**Step 2: Implement tunnel detection in on_tick()**

Track per-flow: `(src_ip, dst_ip, dst_port)` -> deque of `(timestamp, pkt_size)`
- Coefficient of variation (CV) < 0.05 over 30+ packets → tunnel suspect
- Regular inter-packet timing (CV of intervals < 0.1) → beacon/tunnel
- Memory bound: max 5000 flows, evict LRU

**Step 3: Add ESNI/ECH detection**

In `analyze()`, check for encrypted_client_hello extension (type 0xFE0D):
- If present, log as INFO (not inherently malicious, but visibility)

**Step 4: Commit**

```bash
git commit -m "feat(eta): add encrypted tunnel and ESNI/ECH detection"
```

---

### Task 1.5: Update config/default.yaml for ETA

Add new config keys under `engines.tls_fingerprint`:
```yaml
tls_fingerprint:
  enabled: true
  check_ja3: true
  check_ja3s: true
  check_ja4: true
  check_sni: true
  check_cert: true
  detect_tunnels: true
  tunnel_min_packets: 30
  tunnel_cv_threshold: 0.05
  max_tracked_flows: 5000
```

**Commit:**
```bash
git commit -m "feat(eta): add ETA configuration options"
```

---

## Feature 2: Intrusion Response System (IRS)

### Task 2.1: BlockManager Core

**Files:**
- Create: `netwatcher/response/__init__.py`
- Create: `netwatcher/response/blocker.py`
- Test: `tests/test_response/test_blocker.py`

**Step 1: Write failing tests**

```python
# tests/test_response/test_blocker.py
import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from netwatcher.response.blocker import BlockManager, BlockEntry

class TestBlockManager:
    def test_block_entry_creation(self):
        entry = BlockEntry(ip="1.2.3.4", reason="Port scan", duration=3600)
        assert entry.ip == "1.2.3.4"
        assert entry.duration == 3600
        assert entry.active is True

    @pytest.mark.asyncio
    async def test_block_ip(self):
        mgr = BlockManager(enabled=True, backend="mock")
        result = await mgr.block("1.2.3.4", reason="test", duration=60)
        assert result is True
        assert mgr.is_blocked("1.2.3.4")

    @pytest.mark.asyncio
    async def test_unblock_ip(self):
        mgr = BlockManager(enabled=True, backend="mock")
        await mgr.block("1.2.3.4", reason="test", duration=60)
        await mgr.unblock("1.2.3.4")
        assert not mgr.is_blocked("1.2.3.4")

    @pytest.mark.asyncio
    async def test_whitelist_prevents_block(self):
        mgr = BlockManager(enabled=True, backend="mock", whitelist=["1.2.3.4"])
        result = await mgr.block("1.2.3.4", reason="test", duration=60)
        assert result is False

    @pytest.mark.asyncio
    async def test_auto_expire(self):
        mgr = BlockManager(enabled=True, backend="mock")
        await mgr.block("1.2.3.4", reason="test", duration=0)  # immediate expire
        mgr.cleanup_expired()
        assert not mgr.is_blocked("1.2.3.4")
```

**Step 2: Implement BlockManager**

```python
# netwatcher/response/blocker.py
"""Intrusion Response System: reactive IP blocking via iptables/nftables."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("netwatcher.response.blocker")


@dataclass
class BlockEntry:
    ip: str
    reason: str
    duration: int  # seconds, 0 = permanent
    created_at: float = field(default_factory=time.time)
    alert_id: int | None = None
    active: bool = True

    @property
    def expires_at(self) -> float:
        if self.duration == 0:
            return float("inf")
        return self.created_at + self.duration

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class BlockManager:
    """Manages IP blocking via system firewall."""

    def __init__(
        self,
        enabled: bool = False,
        backend: str = "iptables",
        chain_name: str = "NETWATCHER_BLOCK",
        whitelist: list[str] | None = None,
        max_blocks: int = 1000,
        default_duration: int = 3600,
    ) -> None:
        self._enabled = enabled
        self._backend = backend
        self._chain_name = chain_name
        self._whitelist = set(whitelist or [])
        self._max_blocks = max_blocks
        self._default_duration = default_duration
        self._blocks: dict[str, BlockEntry] = {}

    @property
    def enabled(self) -> bool:
        return self._enabled

    def is_blocked(self, ip: str) -> bool:
        entry = self._blocks.get(ip)
        return entry is not None and entry.active and not entry.is_expired

    async def block(
        self, ip: str, reason: str, duration: int | None = None, alert_id: int | None = None,
    ) -> bool:
        if not self._enabled:
            return False
        if ip in self._whitelist:
            logger.warning("Block rejected: %s is whitelisted", ip)
            return False
        if self.is_blocked(ip):
            return True  # already blocked

        dur = duration if duration is not None else self._default_duration
        entry = BlockEntry(ip=ip, reason=reason, duration=dur, alert_id=alert_id)

        if self._backend != "mock":
            success = await self._apply_block(ip)
            if not success:
                return False

        self._blocks[ip] = entry
        logger.info("Blocked %s for %ds: %s", ip, dur, reason)
        return True

    async def unblock(self, ip: str) -> bool:
        entry = self._blocks.get(ip)
        if not entry:
            return False
        entry.active = False

        if self._backend != "mock":
            await self._remove_block(ip)

        del self._blocks[ip]
        logger.info("Unblocked %s", ip)
        return True

    def cleanup_expired(self) -> list[str]:
        expired = [ip for ip, e in self._blocks.items() if e.is_expired]
        for ip in expired:
            self._blocks[ip].active = False
            del self._blocks[ip]
        return expired

    def get_active_blocks(self) -> list[dict]:
        return [
            {"ip": e.ip, "reason": e.reason, "duration": e.duration,
             "created_at": e.created_at, "expires_at": e.expires_at}
            for e in self._blocks.values() if e.active
        ]

    async def _apply_block(self, ip: str) -> bool:
        cmd = ["iptables", "-A", self._chain_name, "-s", ip, "-j", "DROP"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error("iptables block failed for %s: %s", ip, stderr.decode())
                return False
            return True
        except Exception:
            logger.exception("Failed to execute iptables block for %s", ip)
            return False

    async def _remove_block(self, ip: str) -> bool:
        cmd = ["iptables", "-D", self._chain_name, "-s", ip, "-j", "DROP"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            logger.exception("Failed to remove iptables block for %s", ip)
            return False

    async def init_chain(self) -> None:
        """Create the NETWATCHER_BLOCK chain if it doesn't exist."""
        if self._backend == "mock":
            return
        cmds = [
            ["iptables", "-N", self._chain_name],
            ["iptables", "-C", "INPUT", "-j", self._chain_name],
        ]
        # Create chain (ignore error if exists)
        proc = await asyncio.create_subprocess_exec(
            *cmds[0], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        # Insert jump rule if not present
        proc = await asyncio.create_subprocess_exec(
            *cmds[1], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            proc2 = await asyncio.create_subprocess_exec(
                "iptables", "-I", "INPUT", "1", "-j", self._chain_name,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc2.communicate()
```

**Step 3: Run tests**

Run: `.venv/bin/python -m pytest tests/test_response/test_blocker.py -v`
Expected: PASS

**Step 4: Commit**

```bash
git commit -m "feat(irs): add BlockManager core with iptables backend"
```

---

### Task 2.2: Dispatcher Integration

**Files:**
- Modify: `netwatcher/alerts/dispatcher.py`
- Modify: `netwatcher/app.py`
- Modify: `config/default.yaml`

**Step 1: Add auto-block trigger to AlertDispatcher**

After alert is persisted, check if severity == CRITICAL and auto_block enabled:

```python
# In AlertDispatcher._process_alert(), after DB insert:
if (
    self._block_manager
    and self._block_manager.enabled
    and alert.severity == Severity.CRITICAL
    and alert.source_ip
    and self._auto_block_engines
    and alert.engine in self._auto_block_engines
):
    blocked = await self._block_manager.block(
        ip=alert.source_ip,
        reason=f"[{alert.engine}] {alert.title}",
        alert_id=event_id,
    )
    if blocked:
        logger.info("Auto-blocked %s due to %s", alert.source_ip, alert.title)
```

**Step 2: Add BlockManager cleanup loop to app.py**

```python
async def _block_cleanup_loop(self) -> None:
    """Periodically clean up expired IP blocks."""
    while True:
        await asyncio.sleep(60)
        if self._block_manager:
            expired = self._block_manager.cleanup_expired()
            for ip in expired:
                await self._block_manager.unblock(ip)
```

**Step 3: Add config section**

```yaml
response:
  enabled: false                    # IRS 비활성 상태 (명시적 활성화 필요)
  backend: "iptables"               # iptables | nftables | mock
  chain_name: "NETWATCHER_BLOCK"
  default_duration: 3600            # 기본 차단 시간 (초)
  max_blocks: 1000
  whitelist: []                     # 절대 차단하지 않을 IP
  auto_block_engines:               # 자동 차단 트리거 엔진
    - "threat_intel"
    - "port_scan"
    - "arp_spoof"
```

**Step 4: Commit**

```bash
git commit -m "feat(irs): integrate BlockManager with alert dispatcher"
```

---

### Task 2.3: Block Management API Routes

**Files:**
- Create: `netwatcher/web/routes/blocks.py`
- Modify: `netwatcher/web/server.py`
- Test: `tests/test_web/test_blocks_api.py`

Endpoints:
- `GET /api/blocks` — 활성 차단 목록
- `POST /api/blocks` — 수동 IP 차단
- `DELETE /api/blocks/{ip}` — 차단 해제
- `GET /api/blocks/history` — 차단 이력

**Commit:**
```bash
git commit -m "feat(irs): add block management API routes"
```

---

## Feature 3: YAML Signature Engine

### Task 3.1: Rule Model and Parser

**Files:**
- Create: `netwatcher/detection/engines/signature.py`
- Create: `config/rules/`
- Create: `config/rules/example.yaml`
- Test: `tests/test_detection/test_signature.py`

**Step 1: Write failing tests**

```python
# tests/test_detection/test_signature.py
import pytest
from netwatcher.detection.engines.signature import SignatureRule, RuleParser

class TestRuleParser:
    def test_parse_basic_rule(self):
        raw = {
            "id": "CUSTOM-001",
            "name": "SSH Brute Force",
            "severity": "CRITICAL",
            "protocol": "tcp",
            "dst_port": 22,
            "flags": "SYN",
            "threshold": {"count": 10, "seconds": 60},
        }
        rule = RuleParser.parse(raw)
        assert rule.id == "CUSTOM-001"
        assert rule.protocol == "tcp"
        assert rule.dst_port == 22

    def test_parse_content_rule(self):
        raw = {
            "id": "CUSTOM-002",
            "name": "SQL Injection Attempt",
            "severity": "CRITICAL",
            "protocol": "tcp",
            "dst_port": [80, 8080],
            "content": ["UNION SELECT", "OR 1=1", "DROP TABLE"],
            "content_nocase": True,
        }
        rule = RuleParser.parse(raw)
        assert len(rule.content_patterns) == 3

    def test_parse_regex_rule(self):
        raw = {
            "id": "CUSTOM-003",
            "name": "Base64 Encoded Command",
            "severity": "WARNING",
            "protocol": "tcp",
            "pcre": r"/[A-Za-z0-9+/]{50,}={0,2}/",
        }
        rule = RuleParser.parse(raw)
        assert rule.regex is not None
```

**Step 2: Implement rule data model**

```python
@dataclass
class SignatureRule:
    id: str
    name: str
    severity: Severity
    protocol: str | None = None          # tcp, udp, icmp, any
    src_ip: str | None = None            # CIDR or "any"
    dst_ip: str | None = None
    src_port: int | list[int] | None = None
    dst_port: int | list[int] | None = None
    flags: str | None = None             # SYN, FIN, etc.
    content: list[bytes] = field(default_factory=list)
    content_nocase: bool = False
    regex: re.Pattern | None = None
    threshold: dict | None = None        # {"count": N, "seconds": S}
    enabled: bool = True
```

**Step 3: Implement SignatureEngine extending DetectionEngine**

- `__init__`: Load rules from `config/rules/*.yaml`
- `analyze()`: For each rule, check protocol/port/flags match, then content/regex
- `on_tick()`: Process threshold-based rules
- Hot-reload: Watch config/rules/ directory (mtime check on tick)

**Step 4: Example rule file**

```yaml
# config/rules/example.yaml
rules:
  - id: "NW-001"
    name: "SSH Brute Force Attempt"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: 22
    flags: "SYN"
    threshold:
      count: 10
      seconds: 60
      by: "src_ip"

  - id: "NW-002"
    name: "SQL Injection in HTTP"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: [80, 443, 8080, 8443]
    content:
      - "UNION SELECT"
      - "OR 1=1"
      - "' OR '"
    content_nocase: true

  - id: "NW-003"
    name: "Suspicious PowerShell Download"
    severity: "WARNING"
    protocol: "tcp"
    dst_port: [80, 443]
    content:
      - "powershell"
      - "Invoke-WebRequest"
      - "IEX("
    content_nocase: true

  - id: "NW-004"
    name: "Outbound IRC Traffic"
    severity: "WARNING"
    protocol: "tcp"
    dst_port: [6667, 6668, 6669, 6697]

  - id: "NW-005"
    name: "DNS Zone Transfer Attempt"
    severity: "CRITICAL"
    protocol: "tcp"
    dst_port: 53
    content:
      - "\x00\xfc"  # AXFR query type
```

**Step 5: Commit**

```bash
git commit -m "feat(sig): add YAML-based signature detection engine"
```

---

### Task 3.2: Add rule management API

**Files:**
- Create: `netwatcher/web/routes/rules.py`
- Modify: `netwatcher/web/server.py`

Endpoints:
- `GET /api/rules` — 로드된 룰 목록
- `GET /api/rules/{id}` — 룰 상세
- `PUT /api/rules/{id}/toggle` — 활성/비활성 토글
- `POST /api/rules/reload` — 룰 핫리로드

**Commit:**
```bash
git commit -m "feat(sig): add rule management API"
```

---

## Feature 4: Protocol Parsers

### Task 4.1: Protocol Parser Framework + HTTP Parser

**Files:**
- Create: `netwatcher/protocols/__init__.py`
- Create: `netwatcher/protocols/http.py`
- Create: `netwatcher/detection/engines/protocol_inspect.py`
- Test: `tests/test_detection/test_protocol_inspect.py`

**Step 1: Write failing tests**

```python
# tests/test_detection/test_protocol_inspect.py
import pytest
from scapy.all import IP, TCP, Raw, Ether
from netwatcher.protocols.http import parse_http_request, parse_http_response

class TestHTTPParser:
    def test_parse_get_request(self):
        payload = b"GET /admin HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: Nmap\r\n\r\n"
        result = parse_http_request(payload)
        assert result["method"] == "GET"
        assert result["path"] == "/admin"
        assert result["host"] == "evil.com"
        assert result["user_agent"] == "Nmap"

    def test_parse_post_request(self):
        payload = b"POST /login HTTP/1.1\r\nHost: site.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=test"
        result = parse_http_request(payload)
        assert result["method"] == "POST"
        assert result["content_type"] == "application/x-www-form-urlencoded"

    def test_parse_response(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache\r\n\r\n<html>"
        result = parse_http_response(payload)
        assert result["status_code"] == 200
        assert result["server"] == "Apache"

    def test_non_http_returns_none(self):
        result = parse_http_request(b"\x00\x01\x02\x03")
        assert result is None
```

**Step 2: Implement HTTP parser**

```python
# netwatcher/protocols/http.py
"""Lightweight HTTP/1.x parser for single-packet inspection."""

from __future__ import annotations

_HTTP_METHODS = frozenset({b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"})


def parse_http_request(payload: bytes) -> dict | None:
    """Parse HTTP request from raw TCP payload. Returns None if not HTTP."""
    if not payload or len(payload) < 16:
        return None
    # Check if starts with HTTP method
    space_idx = payload.find(b" ")
    if space_idx < 0 or space_idx > 7:
        return None
    method = payload[:space_idx]
    if method not in _HTTP_METHODS:
        return None

    try:
        header_end = payload.find(b"\r\n\r\n")
        header_bytes = payload[:header_end] if header_end > 0 else payload[:2048]
        lines = header_bytes.split(b"\r\n")

        # Request line
        request_line = lines[0].decode("utf-8", errors="replace")
        parts = request_line.split(" ", 2)
        result = {
            "method": parts[0],
            "path": parts[1] if len(parts) > 1 else "",
            "version": parts[2] if len(parts) > 2 else "",
        }

        # Headers
        for line in lines[1:]:
            decoded = line.decode("utf-8", errors="replace")
            if ":" not in decoded:
                continue
            key, val = decoded.split(":", 1)
            key_lower = key.strip().lower()
            val_stripped = val.strip()
            if key_lower == "host":
                result["host"] = val_stripped
            elif key_lower == "user-agent":
                result["user_agent"] = val_stripped
            elif key_lower == "content-type":
                result["content_type"] = val_stripped
            elif key_lower == "content-length":
                result["content_length"] = val_stripped

        return result
    except Exception:
        return None


def parse_http_response(payload: bytes) -> dict | None:
    """Parse HTTP response from raw TCP payload."""
    if not payload or not payload.startswith(b"HTTP/"):
        return None
    try:
        header_end = payload.find(b"\r\n\r\n")
        header_bytes = payload[:header_end] if header_end > 0 else payload[:2048]
        lines = header_bytes.split(b"\r\n")

        status_line = lines[0].decode("utf-8", errors="replace")
        parts = status_line.split(" ", 2)
        result = {
            "version": parts[0],
            "status_code": int(parts[1]) if len(parts) > 1 else 0,
            "reason": parts[2] if len(parts) > 2 else "",
        }

        for line in lines[1:]:
            decoded = line.decode("utf-8", errors="replace")
            if ":" not in decoded:
                continue
            key, val = decoded.split(":", 1)
            key_lower = key.strip().lower()
            if key_lower == "server":
                result["server"] = val.strip()
            elif key_lower == "content-type":
                result["content_type"] = val.strip()

        return result
    except Exception:
        return None
```

**Step 3: Commit**

```bash
git commit -m "feat(proto): add HTTP/1.x request/response parser"
```

---

### Task 4.2: SMTP, FTP, SSH Parsers

**Files:**
- Create: `netwatcher/protocols/smtp.py`
- Create: `netwatcher/protocols/ftp.py`
- Create: `netwatcher/protocols/ssh.py`
- Test: `tests/test_detection/test_protocol_inspect.py` (extend)

**SMTP parser** — extract: EHLO hostname, MAIL FROM, RCPT TO, AUTH attempts
**FTP parser** — extract: USER, PASS, PORT, PASV, RETR/STOR filenames
**SSH parser** — extract: banner string, version, implementation

Each parser follows same pattern: `parse_<proto>(payload: bytes) -> dict | None`

**Step 4: ProtocolInspectEngine**

New detection engine that uses all parsers:
- Suspicious User-Agent (Nmap, sqlmap, Nikto, etc.)
- Open relay SMTP attempts (RCPT TO with external domain)
- FTP anonymous login attempts
- Outdated SSH versions (< 2.0)
- HTTP requests to sensitive paths (/admin, /wp-login, /.env, /actuator)

**Commit:**
```bash
git commit -m "feat(proto): add SMTP/FTP/SSH parsers and ProtocolInspectEngine"
```

---

## Feature 5: Behavioral Profiling

### Task 5.1: Multi-Dimensional Host Profile

**Files:**
- Create: `netwatcher/detection/engines/behavior_profile.py`
- Test: `tests/test_detection/test_behavior_profile.py`

**Step 1: Write failing tests**

```python
class TestBehaviorProfile:
    def test_normal_traffic_no_alert(self):
        engine = BehaviorProfileEngine({"warmup_hours": 0, "warmup_ticks": 10})
        # Feed 100 packets of normal varied traffic
        for i in range(100):
            pkt = _make_tcp_packet(src="192.168.1.10", dst=f"1.2.3.{i % 20}",
                                   dport=443, size=100 + i * 10)
            engine.analyze(pkt)
        # After warmup, normal traffic should not alert
        for _ in range(20):
            alerts = engine.on_tick(0)
        assert not any(a.engine == "behavior_profile" for a in alerts)

    def test_sudden_behavior_change_alerts(self):
        engine = BehaviorProfileEngine({"warmup_ticks": 10, "z_threshold": 2.0})
        # Phase 1: establish baseline (only web traffic)
        for i in range(200):
            pkt = _make_tcp_packet(src="192.168.1.10", dst="1.2.3.4",
                                   dport=443, size=500)
            engine.analyze(pkt)
        for _ in range(15):
            engine.on_tick(0)
        # Phase 2: sudden switch to scanning many hosts on port 22
        for i in range(100):
            pkt = _make_tcp_packet(src="192.168.1.10", dst=f"10.0.0.{i}",
                                   dport=22, size=60)
            engine.analyze(pkt)
        alerts = engine.on_tick(0)
        assert len(alerts) > 0
```

**Step 2: Implement HostProfile dataclass**

```python
@dataclass
class HostProfile:
    """Multi-dimensional Welford statistics per host."""
    # Volume
    bytes_per_tick: _WelfordStats = field(default_factory=_WelfordStats)
    packets_per_tick: _WelfordStats = field(default_factory=_WelfordStats)
    # Diversity
    unique_dst_ips: _WelfordStats = field(default_factory=_WelfordStats)
    unique_dst_ports: _WelfordStats = field(default_factory=_WelfordStats)
    unique_protocols: _WelfordStats = field(default_factory=_WelfordStats)
    # Packet characteristics
    avg_pkt_size: _WelfordStats = field(default_factory=_WelfordStats)
    # DNS
    dns_queries_per_tick: _WelfordStats = field(default_factory=_WelfordStats)
    # Current tick accumulators
    _tick_bytes: int = 0
    _tick_packets: int = 0
    _tick_dst_ips: set = field(default_factory=set)
    _tick_dst_ports: set = field(default_factory=set)
    _tick_protocols: set = field(default_factory=set)
    _tick_pkt_sizes: list = field(default_factory=list)
    _tick_dns_count: int = 0
    ticks_seen: int = 0
    last_seen: float = 0.0
```

**Step 3: Implement BehaviorProfileEngine**

`analyze()`: Accumulate per-tick counters for each src_ip
`on_tick()`:
1. For each host profile, compute Z-score across all dimensions
2. Composite anomaly score = max(z_scores) or sum(z > threshold)
3. Alert if composite score exceeds threshold
4. Reset tick accumulators
5. Feed current values into Welford stats (update baseline)

**Step 4: Commit**

```bash
git commit -m "feat(behavior): add multi-dimensional host behavior profiling engine"
```

---

## Feature 6: File Extraction (PCAP Post-Processing)

### Task 6.1: PCAP Analyzer with tshark

**Files:**
- Create: `netwatcher/analysis/__init__.py`
- Create: `netwatcher/analysis/pcap_analyzer.py`
- Test: `tests/test_analysis/test_pcap_analyzer.py`

**Step 1: Write failing tests**

```python
class TestPCAPAnalyzer:
    def test_check_tshark_available(self):
        from netwatcher.analysis.pcap_analyzer import PcapAnalyzer
        analyzer = PcapAnalyzer()
        # Should not raise even if tshark is not installed
        result = analyzer.is_available()
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_extract_files_from_pcap(self, tmp_path):
        analyzer = PcapAnalyzer(output_dir=str(tmp_path))
        # Create a minimal PCAP with HTTP transfer
        pcap_path = tmp_path / "test.pcap"
        # ... write test PCAP
        if analyzer.is_available():
            files = await analyzer.extract_files(str(pcap_path))
            assert isinstance(files, list)
```

**Step 2: Implement PcapAnalyzer**

```python
class PcapAnalyzer:
    """Extract files from PCAP captures using tshark."""

    def __init__(self, output_dir: str = "data/extracted") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def is_available(self) -> bool:
        return shutil.which("tshark") is not None

    async def extract_files(self, pcap_path: str) -> list[dict]:
        """Extract files from PCAP using tshark --export-objects."""
        export_dir = self._output_dir / f"export_{int(time.time())}"
        export_dir.mkdir()
        cmd = [
            "tshark", "-r", pcap_path,
            "--export-objects", f"http,{export_dir}",
            "-Q",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        results = []
        for f in export_dir.iterdir():
            sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
            results.append({
                "filename": f.name,
                "path": str(f),
                "size": f.stat().st_size,
                "sha256": sha256,
            })
        return results
```

**Step 3: Commit**

```bash
git commit -m "feat(analysis): add PCAP file extraction via tshark"
```

---

### Task 6.2: YARA Scanner Integration

**Files:**
- Create: `netwatcher/analysis/yara_scanner.py`
- Create: `config/yara/` directory
- Test: `tests/test_analysis/test_yara_scanner.py`

**Step 1: Implement YARA scanner**

```python
class YaraScanner:
    """Scan extracted files against YARA rules."""

    def __init__(self, rules_dir: str = "config/yara") -> None:
        self._rules_dir = Path(rules_dir)
        self._compiled: yara.Rules | None = None
        self._available = False
        try:
            import yara
            self._available = True
            self._load_rules()
        except ImportError:
            logger.warning("yara-python not installed — YARA scanning disabled")

    def _load_rules(self) -> None:
        import yara
        rule_files = {}
        for f in self._rules_dir.glob("*.yar"):
            rule_files[f.stem] = str(f)
        if rule_files:
            self._compiled = yara.compile(filepaths=rule_files)

    def scan_file(self, file_path: str) -> list[dict]:
        if not self._available or not self._compiled:
            return []
        import yara
        matches = self._compiled.match(file_path)
        return [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]
```

**Step 2: Integrate into alert pipeline**

In `AlertDispatcher`, after PCAP capture step:
- If file extraction enabled, run `PcapAnalyzer.extract_files()`
- For each extracted file, run `YaraScanner.scan_file()`
- If YARA match found, enqueue additional alert with file details

**Step 3: Commit**

```bash
git commit -m "feat(analysis): add YARA rule scanning for extracted files"
```

---

## Configuration Updates

### Task 7.1: Update config/default.yaml

Add all new sections:

```yaml
# Signature engine
engines:
  signature:
    enabled: true
    rules_dir: "config/rules"
    hot_reload: true

  # Protocol inspection
  protocol_inspect:
    enabled: true
    suspicious_user_agents:
      - "Nmap"
      - "sqlmap"
      - "Nikto"
      - "DirBuster"
      - "Hydra"
    sensitive_paths:
      - "/admin"
      - "/wp-login.php"
      - "/.env"
      - "/actuator"
      - "/phpmyadmin"

  # Behavioral profiling
  behavior_profile:
    enabled: true
    warmup_ticks: 300           # 5분 워밍업
    z_threshold: 3.5
    max_tracked_hosts: 10000
    eviction_seconds: 86400

# Intrusion Response System
response:
  enabled: false
  backend: "iptables"
  chain_name: "NETWATCHER_BLOCK"
  default_duration: 3600
  max_blocks: 1000
  whitelist: []
  auto_block_engines:
    - "threat_intel"
    - "port_scan"

# File analysis
analysis:
  enabled: false
  extract_files: true
  yara_rules_dir: "config/yara"
  max_file_size: 10485760       # 10MB
  vt_api_key: ""                # VirusTotal API key (optional)
```

**Commit:**
```bash
git commit -m "feat: add configuration for all new features"
```

---

## Dependency Updates

### Task 8.1: Update requirements.txt

```
# Optional dependencies (install for extended features)
# yara-python>=4.3.0    # YARA rule scanning
# scikit-learn>=1.3.0   # ML-based detection (future)
```

No mandatory new dependencies. All features use:
- Standard library (asyncio, hashlib, re, subprocess)
- Existing deps (scapy, fastapi)
- Optional external tools (tshark, iptables)

---

## Testing Strategy

각 Feature는 독립적인 테스트 모듈을 가진다:

| Feature | Test File | Key Test Cases |
|---------|-----------|----------------|
| ETA | `tests/test_detection/test_tls_eta.py` | JA3S 계산, 인증서 분석, JA4, 터널 탐지 |
| IRS | `tests/test_response/test_blocker.py` | 차단/해제, 화이트리스트, 만료, mock backend |
| Signature | `tests/test_detection/test_signature.py` | 룰 파싱, 콘텐츠 매칭, threshold, 핫리로드 |
| Protocol | `tests/test_detection/test_protocol_inspect.py` | HTTP/SMTP/FTP/SSH 파싱, 의심 패턴 탐지 |
| Behavior | `tests/test_detection/test_behavior_profile.py` | 정상 트래픽 무알림, 행동 변화 탐지 |
| File Ext. | `tests/test_analysis/test_pcap_analyzer.py` | tshark 가용성, 파일 추출, YARA 매칭 |

전체 테스트: `.venv/bin/python -m pytest tests/ -v`
