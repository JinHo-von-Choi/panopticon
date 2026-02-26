# AIAnalyzer MISSED_THREAT 기능 구현 계획

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** AIAnalyzerService에 MISSED_THREAT verdict를 추가하여 탐지 엔진이 놓친 위협을 감지하고, 임계값을 자동 하향하며, AI 판단 근거(reasoning)를 DB에 저장한다.

**Architecture:** 기존 FALSE_POSITIVE 처리 구조와 대칭 형태로 MISSED_THREAT 분기를 추가한다. DB 스키마는 Alembic 마이그레이션으로, 내부 구조는 AnalysisResult 확장 + 신규 메서드 _try_lower_threshold()로 처리한다. 모든 변경은 기존 테스트를 깨지 않는 하위 호환성 유지 방식으로 적용한다.

**Tech Stack:** Python 3.12, asyncpg, Alembic, pytest-asyncio, pytest

---

### Task 1: Alembic 마이그레이션 — events.reasoning 컬럼 추가

**Files:**
- Create: `alembic/versions/003_events_reasoning.py`

**Step 1: 마이그레이션 파일 작성**

```python
"""events 테이블에 reasoning TEXT 컬럼 추가

Revision ID: 003_events_reasoning
Revises: 002_asset_inventory
Create Date: 2026-02-27
"""
from typing import Sequence, Union

from alembic import op

revision: str = "003_events_reasoning"
down_revision: Union[str, None] = "002_asset_inventory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE events
            ADD COLUMN IF NOT EXISTS reasoning TEXT
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE events
            DROP COLUMN IF EXISTS reasoning
    """)
```

**Step 2: 마이그레이션 실행**

```bash
.venv/bin/alembic upgrade head
```

Expected output: `Running upgrade 002_asset_inventory -> 003_events_reasoning, events 테이블에 reasoning TEXT 컬럼 추가`

**Step 3: 컬럼 존재 확인 (psql)**

```sql
-- psql -h localhost -p 35432 -U bee -d bee_db -c "\d+ events"
-- reasoning 컬럼이 text 타입으로 나타나야 함
```

**Step 4: 커밋**

```bash
git add alembic/versions/003_events_reasoning.py
git commit -m "feat(db): add reasoning TEXT column to events table"
```

---

### Task 2: EventRepository.insert() — reasoning 파라미터 추가

**Files:**
- Modify: `netwatcher/storage/repositories.py:51-76`
- Test: `tests/test_storage/test_repositories.py` (있다면)

**Step 1: 실패 테스트 작성 (test_ai_analyzer.py에 추가)**

아래 테스트를 `tests/test_services/test_ai_analyzer.py`의 `TestAnalysisLoop` 클래스에 추가:

```python
@pytest.mark.asyncio
async def test_confirmed_threat_saves_reasoning_to_db(self):
    svc = self._make_service()
    result = AnalysisResult(
        verdict="CONFIRMED_THREAT",
        engine="port_scan",
        reason="Real port scan.",
        reasoning="1. SYN packets to 25 ports.\n2. Source IP never seen before.",
    )
    await svc._apply_result(result)
    call_kwargs = svc._event_repo.insert.call_args.kwargs
    assert "reasoning" in call_kwargs
    assert call_kwargs["reasoning"] == result.reasoning
```

**Step 2: 테스트 실행하여 실패 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestAnalysisLoop::test_confirmed_threat_saves_reasoning_to_db -v
```

Expected: `FAILED` — `AnalysisResult` has no `reasoning` field yet (Task 3에서 추가), 또는 `insert()` call에 reasoning 키가 없음.

**Step 3: repositories.py 수정**

`insert()` 메서드 시그니처에 `reasoning: str | None = None` 추가:

```python
async def insert(
    self,
    engine: str,
    severity: str,
    title: str,
    description: str = "",
    source_ip: str | None = None,
    source_mac: str | None = None,
    dest_ip: str | None = None,
    dest_mac: str | None = None,
    metadata: dict[str, Any] | None = None,
    packet_info: dict[str, Any] | None = None,
    reasoning: str | None = None,          # ← 신규
) -> int:
    """새 이벤트를 삽입하고 해당 id를 반환한다."""
    row_id = await self._db.pool.fetchval(
        """INSERT INTO events
           (engine, severity, title, description, source_ip, source_mac,
            dest_ip, dest_mac, metadata, packet_info, reasoning)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING id""",
        engine, severity,
        _sanitize(title), _sanitize(description),
        source_ip, source_mac, dest_ip, dest_mac,
        _sanitize(metadata or {}), _sanitize(packet_info or {}),
        reasoning,
    )
    return row_id
```

**Step 4: 기존 테스트 전체 실행하여 회귀 없음 확인**

```bash
.venv/bin/python -m pytest tests/ -v
```

Expected: 기존 918 테스트 모두 pass (reasoning은 nullable이므로 기존 호출 영향 없음)

**Step 5: 커밋**

```bash
git add netwatcher/storage/repositories.py
git commit -m "feat(storage): add reasoning param to EventRepository.insert()"
```

---

### Task 3: AnalysisResult 확장 + _parse_response() MISSED_THREAT/REASONING 파싱

**Files:**
- Modify: `netwatcher/services/ai_analyzer.py:38-108`
- Test: `tests/test_services/test_ai_analyzer.py`

**Step 1: 실패 테스트 작성**

`TestParseResponse` 클래스에 추가:

```python
def test_missed_threat_verdict(self):
    text = (
        "VERDICT: MISSED_THREAT\n"
        "ENGINE: dns_anomaly\n"
        "REASON: Low-entropy DNS requests form C2 beacon pattern.\n"
        "REASONING:\n"
        "1. 7 requests to same subdomain in 5 minutes.\n"
        "2. Consistent 60-second interval.\n"
        "3. INFO severity masks the pattern.\n"
        "ADJUST: entropy_threshold=3.2\n"
    )
    result = self._parse(text)
    assert result.verdict == "MISSED_THREAT"
    assert result.engine == "dns_anomaly"
    assert result.adjustments == {"entropy_threshold": 3.2}
    assert "1." in result.reasoning
    assert "2." in result.reasoning

def test_reasoning_parsed_multiline(self):
    text = (
        "VERDICT: FALSE_POSITIVE\n"
        "ENGINE: port_scan\n"
        "REASON: Normal scan.\n"
        "REASONING:\n"
        "1. Source is internal CI runner.\n"
        "2. All destination ports are known services.\n"
    )
    result = self._parse(text)
    assert "1." in result.reasoning
    assert "2." in result.reasoning

def test_no_reasoning_returns_empty_string(self):
    text = (
        "VERDICT: CONFIRMED_THREAT\n"
        "ENGINE: port_scan\n"
        "REASON: Real scan.\n"
    )
    result = self._parse(text)
    assert result.reasoning == ""
```

**Step 2: 실패 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestParseResponse -v
```

Expected: 3개 신규 테스트 FAIL

**Step 3: AnalysisResult 확장**

```python
@dataclass
class AnalysisResult:
    """AI CLI 응답 파싱 결과."""

    verdict:     str              # CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | UNCERTAIN
    engine:      str              # 대상 엔진 이름
    reason:      str = ""
    reasoning:   str = ""         # 번호 목록 형식 판단 근거 (신규)
    adjustments: dict[str, float] = field(default_factory=dict)
```

**Step 4: _parse_response() 수정**

```python
@staticmethod
def _parse_response(text: str) -> AnalysisResult:
    upper = text.upper()

    # VERDICT — MISSED_THREAT 추가
    verdict = "UNCERTAIN"
    for candidate in ("CONFIRMED_THREAT", "FALSE_POSITIVE", "MISSED_THREAT", "UNCERTAIN"):
        if re.search(rf"\b{candidate}\b", upper):
            verdict = candidate
            break

    # ENGINE
    engine = ""
    engine_match = re.search(r"(?i)^ENGINE:\s*(\S+)", text, re.MULTILINE)
    if engine_match:
        engine = engine_match.group(1).strip()

    # REASON (한 줄)
    reason = ""
    reason_match = re.search(r"(?i)^REASON:\s*(.+)", text, re.MULTILINE)
    if reason_match:
        reason = reason_match.group(1).strip()

    # REASONING (번호 목록 블록 — ADJUST: 또는 끝까지)
    reasoning = ""
    reasoning_match = re.search(
        r"(?i)^REASONING:\s*\n((?:.*\n?)*?)(?=(?:ADJUST:|$))",
        text,
        re.MULTILINE,
    )
    if reasoning_match:
        reasoning = reasoning_match.group(1).strip()

    # ADJUST (여러 줄 가능)
    adjustments: dict[str, float] = {}
    for m in re.finditer(r"(?i)^ADJUST:\s*(\w+)=([\d.]+)", text, re.MULTILINE):
        key, raw = m.group(1), m.group(2)
        try:
            adjustments[key] = float(raw)
        except ValueError:
            logger.warning("ADJUST 파싱 실패: %s=%s", key, raw)

    return AnalysisResult(
        verdict=verdict,
        engine=engine,
        reason=reason,
        reasoning=reasoning,
        adjustments=adjustments,
    )
```

**Step 5: 테스트 통과 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestParseResponse -v
```

Expected: 모든 TestParseResponse 테스트 PASS

**Step 6: 커밋**

```bash
git add netwatcher/services/ai_analyzer.py tests/test_services/test_ai_analyzer.py
git commit -m "feat(ai): add MISSED_THREAT verdict and reasoning parsing"
```

---

### Task 4: _build_prompt() 수정 — MISSED_THREAT 지시 및 REASONING 형식 추가

**Files:**
- Modify: `netwatcher/services/ai_analyzer.py:265-289`
- Test: `tests/test_services/test_ai_analyzer.py`

**Step 1: 실패 테스트 작성**

`TestBuildPrompt` 클래스에 추가:

```python
def test_prompt_contains_missed_threat(self):
    svc = self._make_service()
    prompt = svc._build_prompt([])
    assert "MISSED_THREAT" in prompt

def test_prompt_contains_reasoning_instruction(self):
    svc = self._make_service()
    prompt = svc._build_prompt([])
    assert "REASONING:" in prompt

def test_prompt_mentions_info_events(self):
    svc = self._make_service()
    prompt = svc._build_prompt([])
    assert "INFO" in prompt
```

**Step 2: 실패 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestBuildPrompt -v
```

Expected: 3개 신규 테스트 FAIL

**Step 3: _build_prompt() 수정**

```python
def _build_prompt(self, events: list[dict]) -> str:
    """분석 대상 이벤트를 구조화된 AI 프롬프트로 변환한다."""
    slim = [
        {
            "engine":    e.get("engine", ""),
            "severity":  e.get("severity", ""),
            "title":     e.get("title", ""),
            "source_ip": str(e.get("source_ip", "")),
            "timestamp": str(e.get("timestamp", "")),
        }
        for e in events
    ]
    events_json = json.dumps(slim, ensure_ascii=False, indent=2)

    return (
        f"Analyze these network security events from a home/office LAN monitor "
        f"(lookback: {self._lookback_minutes} minutes). "
        f"Events include CRITICAL, WARNING, and INFO severity levels. "
        f"Perform TWO checks: "
        f"(1) Are any CRITICAL/WARNING alerts actually false positives? "
        f"(2) Do any INFO/low-confidence events indicate a more serious missed threat? "
        f"Return the single most important finding. "
        f"EVENTS: {events_json} "
        f"Respond ONLY in this exact format: "
        f"VERDICT: CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | UNCERTAIN "
        f"ENGINE: <engine_name> "
        f"REASON: <one sentence> "
        f"REASONING: "
        f"1. <reason 1> "
        f"2. <reason 2> "
        f"3. <reason 3> "
        f"ADJUST: <param>=<numeric_value> (FALSE_POSITIVE: raise value, MISSED_THREAT: lower value, can repeat)"
    )
```

**Step 4: 통과 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestBuildPrompt -v
```

Expected: 모든 TestBuildPrompt 테스트 PASS

**Step 5: 커밋**

```bash
git add netwatcher/services/ai_analyzer.py tests/test_services/test_ai_analyzer.py
git commit -m "feat(ai): update prompt with MISSED_THREAT and REASONING format"
```

---

### Task 5: _fetch_recent_events() — INFO 이벤트 추가

**Files:**
- Modify: `netwatcher/services/ai_analyzer.py:364-388`
- Test: `tests/test_services/test_ai_analyzer.py`

**Step 1: 실패 테스트 작성**

`TestAnalysisLoop` 클래스에 추가:

```python
@pytest.mark.asyncio
async def test_fetch_recent_events_includes_info(self):
    """_fetch_recent_events()가 INFO 이벤트를 max_events//3개 포함해야 한다."""
    svc = self._make_service()

    # list_recent 호출별 반환값 설정
    async def mock_list_recent(severity, since, limit):
        if severity == "CRITICAL":
            return [{"id": 1, "severity": "CRITICAL", "engine": "port_scan",
                     "title": "t", "source_ip": None, "timestamp": "2026-02-27"}]
        if severity == "WARNING":
            return [{"id": 2, "severity": "WARNING", "engine": "dns_anomaly",
                     "title": "t", "source_ip": None, "timestamp": "2026-02-27"}]
        if severity == "INFO":
            return [{"id": 3, "severity": "INFO", "engine": "traffic_anomaly",
                     "title": "t", "source_ip": None, "timestamp": "2026-02-27"}]
        return []

    svc._event_repo.list_recent = mock_list_recent

    events = await svc._fetch_recent_events()

    severities = {e["severity"] for e in events}
    assert "INFO" in severities
```

**Step 2: 실패 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestAnalysisLoop::test_fetch_recent_events_includes_info -v
```

Expected: FAIL — INFO 이벤트가 결과에 없음

**Step 3: _fetch_recent_events() 수정**

```python
async def _fetch_recent_events(self) -> list[dict]:
    """최근 lookback_minutes 내 CRITICAL/WARNING/INFO 이벤트를 조회한다.

    CRITICAL + WARNING은 각 max_events // 2개, INFO는 max_events // 3개.
    """
    from datetime import datetime, timedelta, timezone
    since = (
        datetime.now(timezone.utc) - timedelta(minutes=self._lookback_minutes)
    ).isoformat()

    half = self._max_events // 2
    info_limit = self._max_events // 3
    try:
        criticals = await self._event_repo.list_recent(
            severity="CRITICAL", since=since, limit=half,
        )
        warnings = await self._event_repo.list_recent(
            severity="WARNING", since=since, limit=half,
        )
        info_events = await self._event_repo.list_recent(
            severity="INFO", since=since, limit=info_limit,
        )
    except Exception:
        logger.exception("[ai_analyzer] 이벤트 조회 실패")
        return []

    merged = criticals + warnings + info_events
    merged.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return merged[: self._max_events]
```

**Step 4: 통과 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py -v
```

Expected: 모든 테스트 PASS

**Step 5: 커밋**

```bash
git add netwatcher/services/ai_analyzer.py tests/test_services/test_ai_analyzer.py
git commit -m "feat(ai): include INFO events in analysis context"
```

---

### Task 6: __init__() + _try_lower_threshold() 신규 메서드

**Files:**
- Modify: `netwatcher/services/ai_analyzer.py:110-143, 145-222`
- Test: `tests/test_services/test_ai_analyzer.py`

**Step 1: 실패 테스트 작성**

`TestAnalysisLoop` 클래스에 `TestTryLowerThreshold` 클래스를 추가:

```python
class TestTryLowerThreshold:
    """_try_lower_threshold() 연속 카운터 및 하한 캡 검증."""

    def _make_service(self, consecutive_mt_threshold: int = 2,
                      max_decrease_pct: int = 10) -> AIAnalyzerService:
        cfg_data = {
            "enabled": True,
            "interval_minutes": 15,
            "lookback_minutes": 30,
            "max_events": 50,
            "consecutive_fp_threshold": 2,
            "max_threshold_increase_pct": 20,
            "consecutive_mt_threshold": consecutive_mt_threshold,
            "max_threshold_decrease_pct": max_decrease_pct,
            "copilot_timeout_seconds": 60,
        }
        config = MagicMock()
        config.section.return_value = cfg_data
        svc = AIAnalyzerService(
            config=config,
            event_repo=AsyncMock(),
            registry=MagicMock(),
            dispatcher=MagicMock(),
            yaml_editor=MagicMock(),
        )
        return svc

    def test_no_adjust_below_threshold(self):
        svc = self._make_service(consecutive_mt_threshold=2)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 15}
        adjustments = {"threshold": 10}

        svc._try_lower_threshold("port_scan", adjustments)  # 1회차

        svc._yaml_editor.update_engine_config.assert_not_called()
        assert svc._consecutive_mt["port_scan"] == 1

    def test_lowers_on_threshold_reached(self):
        svc = self._make_service(consecutive_mt_threshold=2, max_decrease_pct=10)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 15}
        svc._registry.reload_engine.return_value = (True, None, [])
        adjustments = {"threshold": 10}

        svc._try_lower_threshold("port_scan", adjustments)  # 1회차
        svc._try_lower_threshold("port_scan", adjustments)  # 2회차 → 적용

        # cap: max(10, 15 * (1 - 10/100)) = max(10, 13.5) = 13.5
        svc._yaml_editor.update_engine_config.assert_called_once_with(
            "port_scan", {"threshold": 13.5}
        )
        assert svc._consecutive_mt["port_scan"] == 0

    def test_cap_prevents_extreme_decrease(self):
        """요청값이 cap보다 낮으면 cap값(덜 낮은 쪽)을 사용한다."""
        svc = self._make_service(consecutive_mt_threshold=1, max_decrease_pct=10)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 15}
        svc._registry.reload_engine.return_value = (True, None, [])

        # requested=5 (너무 낮음), cap = 15 * 0.9 = 13.5 → max(5, 13.5) = 13.5
        svc._try_lower_threshold("port_scan", {"threshold": 5})

        svc._yaml_editor.update_engine_config.assert_called_once_with(
            "port_scan", {"threshold": 13.5}
        )

    def test_counter_resets_after_adjust(self):
        svc = self._make_service(consecutive_mt_threshold=1)
        svc._yaml_editor.get_engine_config.return_value = {"threshold": 15}
        svc._registry.reload_engine.return_value = (True, None, [])

        svc._try_lower_threshold("port_scan", {"threshold": 12})
        assert svc._consecutive_mt.get("port_scan", 0) == 0

    def test_yaml_editor_none_skips(self):
        svc = self._make_service(consecutive_mt_threshold=1)
        svc._yaml_editor = None

        svc._try_lower_threshold("port_scan", {"threshold": 10})

        svc._registry.reload_engine.assert_not_called()
```

**Step 2: 실패 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestTryLowerThreshold -v
```

Expected: FAIL — `_try_lower_threshold` 메서드 없음, `_consecutive_mt` 속성 없음

**Step 3: __init__() 확장**

`__init__()` 끝에 추가:

```python
        self._mt_threshold:    int = int(ai_cfg.get("consecutive_mt_threshold",    2))
        self._max_decrease_pct: int = int(ai_cfg.get("max_threshold_decrease_pct", 10))

        self._consecutive_fp: dict[str, int] = {}
        self._consecutive_mt: dict[str, int] = {}   # ← 신규
        self._task: asyncio.Task | None       = None
```

**Step 4: _try_lower_threshold() 메서드 추가**

`_try_adjust_threshold()` 메서드 바로 뒤에 추가:

```python
    def _try_lower_threshold(
        self, engine: str, adjustments: dict[str, float],
    ) -> None:
        """연속 미탐 카운터를 증가시키고, 임계값에 달하면 설정을 하향한다.

        - 연속 미탐 횟수가 mt_threshold 미만이면 카운터만 증가
        - 임계값 달성 시 cap 적용 후 YamlConfigEditor + registry.reload_engine()
        - cap 방향: max(requested, current * (1 - pct/100)) — 너무 급격한 하향 방지
        - yaml_editor가 None이면 WARNING 로그 후 skip
        """
        key = engine
        self._consecutive_mt[key] = self._consecutive_mt.get(key, 0) + 1

        if self._consecutive_mt[key] < self._mt_threshold:
            logger.info(
                "[ai_analyzer] %s 미탐 카운터 %d/%d",
                engine, self._consecutive_mt[key], self._mt_threshold,
            )
            return

        if self._yaml_editor is None:
            logger.warning("[ai_analyzer] yaml_editor 없음 — 임계값 하향 불가")
            return

        try:
            current_cfg = self._yaml_editor.get_engine_config(engine) or {}
        except Exception:
            logger.exception("[ai_analyzer] 엔진 설정 조회 실패: %s", engine)
            return

        capped: dict[str, float] = {}
        for param, requested in adjustments.items():
            current_val = current_cfg.get(param)
            if current_val is None or not isinstance(current_val, (int, float)):
                capped[param] = requested
                continue
            # 너무 급격한 하향 방지: requested와 cap 중 큰 값 선택
            cap_val = current_val * (1 - self._max_decrease_pct / 100)
            capped[param] = max(requested, cap_val)

        try:
            self._yaml_editor.update_engine_config(engine, capped)
        except Exception:
            logger.exception("[ai_analyzer] config 하향 업데이트 실패: %s", engine)
            return

        new_cfg = self._yaml_editor.get_engine_config(engine) or {}
        ok, err, _ = self._registry.reload_engine(engine, new_cfg)
        if ok:
            logger.info("[ai_analyzer] 엔진 민감도 하향 완료: %s %s", engine, capped)
        else:
            logger.error("[ai_analyzer] 엔진 핫리로드 실패: %s — %s", engine, err)

        self._consecutive_mt[key] = 0

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            asyncio.create_task(
                self._event_repo.insert(
                    engine="ai_adjustment",
                    severity="WARNING",
                    title=f"[AI 미탐조정] {engine} 임계값 자동 하향",
                    description=str(capped),
                    metadata={
                        "engine": engine,
                        "adjusted": capped,
                        "provider": self._provider,
                    },
                )
            )
```

**Step 5: 통과 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestTryLowerThreshold -v
```

Expected: 모든 TestTryLowerThreshold 테스트 PASS

**Step 6: 커밋**

```bash
git add netwatcher/services/ai_analyzer.py tests/test_services/test_ai_analyzer.py
git commit -m "feat(ai): add _try_lower_threshold and consecutive_mt counter"
```

---

### Task 7: _apply_result() — MISSED_THREAT 분기 추가 + reasoning 전달

**Files:**
- Modify: `netwatcher/services/ai_analyzer.py:295-358`
- Test: `tests/test_services/test_ai_analyzer.py`

**Step 1: 실패 테스트 작성**

`TestAnalysisLoop` 클래스에 추가:

```python
@pytest.mark.asyncio
async def test_missed_threat_enqueues_critical_alert(self):
    svc = self._make_service()
    result = AnalysisResult(
        verdict="MISSED_THREAT",
        engine="dns_anomaly",
        reason="C2 beacon pattern in INFO events.",
        reasoning="1. Consistent 60s interval.\n2. Same subdomain repeated.",
    )
    await svc._apply_result(result)
    svc._dispatcher.enqueue.assert_called_once()
    alert_arg = svc._dispatcher.enqueue.call_args[0][0]
    assert alert_arg.severity.value == "CRITICAL"
    assert "미탐" in alert_arg.title

@pytest.mark.asyncio
async def test_missed_threat_saves_event_with_reasoning(self):
    svc = self._make_service()
    result = AnalysisResult(
        verdict="MISSED_THREAT",
        engine="dns_anomaly",
        reason="Missed C2.",
        reasoning="1. Reason one.\n2. Reason two.",
    )
    await svc._apply_result(result)
    svc._event_repo.insert.assert_awaited()
    call_kwargs = svc._event_repo.insert.call_args.kwargs
    assert call_kwargs["severity"] == "CRITICAL"
    assert call_kwargs["reasoning"] == result.reasoning

@pytest.mark.asyncio
async def test_missed_threat_calls_try_lower_threshold(self):
    svc = self._make_service()
    svc._yaml_editor.get_engine_config.return_value = {"threshold": 15}
    svc._registry.reload_engine.return_value = (True, None, [])
    result = AnalysisResult(
        verdict="MISSED_THREAT",
        engine="dns_anomaly",
        reason="Missed C2.",
        adjustments={"entropy_threshold": 3.2},
    )
    await svc._apply_result(result)
    svc._yaml_editor.update_engine_config.assert_called_once()

@pytest.mark.asyncio
async def test_confirmed_threat_saves_reasoning(self):
    svc = self._make_service()
    result = AnalysisResult(
        verdict="CONFIRMED_THREAT",
        engine="port_scan",
        reason="Real scan.",
        reasoning="1. 25 distinct ports.\n2. SYN only.",
    )
    await svc._apply_result(result)
    call_kwargs = svc._event_repo.insert.call_args.kwargs
    assert call_kwargs.get("reasoning") == result.reasoning
```

**Step 2: 실패 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py::TestAnalysisLoop -v
```

Expected: 4개 신규 테스트 FAIL

**Step 3: _apply_result() 수정**

```python
async def _apply_result(self, result: AnalysisResult) -> None:
    """파싱된 분석 결과에 따라 알림 재전송 또는 임계값 조정을 수행한다."""
    if result.verdict == "CONFIRMED_THREAT":
        from netwatcher.detection.models import Alert, Severity
        alert = Alert(
            engine="ai_analyzer",
            severity=Severity.CRITICAL,
            title=f"[AI 확인] {result.engine} — 실제 위협",
            description=result.reason,
            confidence=1.0,
            metadata={"ai_confirmed": True, "original_engine": result.engine},
        )
        self._dispatcher.enqueue(alert)
        await self._event_repo.insert(
            engine="ai_analyzer",
            severity="CRITICAL",
            title=f"[AI 확인] {result.engine} — 실제 위협",
            description=result.reason,
            reasoning=result.reasoning or None,
            metadata={
                "verdict": "CONFIRMED_THREAT",
                "original_engine": result.engine,
                "provider": self._provider,
            },
        )
        logger.warning(
            "[ai_analyzer] CONFIRMED_THREAT: engine=%s reason=%s",
            result.engine, result.reason,
        )

    elif result.verdict == "FALSE_POSITIVE":
        logger.info(
            "[ai_analyzer] FALSE_POSITIVE: engine=%s adjustments=%s",
            result.engine, result.adjustments,
        )
        await self._event_repo.insert(
            engine="ai_analyzer",
            severity="WARNING",
            title=f"[AI 오탐] {result.engine} — 오탐 판정",
            description=result.reason,
            reasoning=result.reasoning or None,
            metadata={
                "verdict": "FALSE_POSITIVE",
                "original_engine": result.engine,
                "adjustments": result.adjustments,
                "provider": self._provider,
            },
        )
        self._try_adjust_threshold(result.engine, result.adjustments)

    elif result.verdict == "MISSED_THREAT":
        from netwatcher.detection.models import Alert, Severity
        alert = Alert(
            engine="ai_analyzer",
            severity=Severity.CRITICAL,
            title=f"[AI 미탐] {result.engine} — 탐지 누락 의심",
            description=result.reason,
            confidence=0.8,
            metadata={"missed_threat": True, "original_engine": result.engine},
        )
        self._dispatcher.enqueue(alert)
        await self._event_repo.insert(
            engine="ai_analyzer",
            severity="CRITICAL",
            title=f"[AI 미탐] {result.engine} — 탐지 누락 의심",
            description=result.reason,
            reasoning=result.reasoning or None,
            metadata={
                "verdict": "MISSED_THREAT",
                "original_engine": result.engine,
                "provider": self._provider,
            },
        )
        logger.warning(
            "[ai_analyzer] MISSED_THREAT: engine=%s reason=%s",
            result.engine, result.reason,
        )
        self._try_lower_threshold(result.engine, result.adjustments)

    else:  # UNCERTAIN
        logger.info(
            "[ai_analyzer] UNCERTAIN: engine=%s reason=%s",
            result.engine, result.reason,
        )
        await self._event_repo.insert(
            engine="ai_analyzer",
            severity="INFO",
            title=f"[AI 불확실] {result.engine} — 판단 불가",
            description=result.reason,
            reasoning=result.reasoning or None,
            metadata={
                "verdict": "UNCERTAIN",
                "original_engine": result.engine,
                "provider": self._provider,
            },
        )
```

**Step 4: 통과 확인**

```bash
.venv/bin/python -m pytest tests/test_services/test_ai_analyzer.py -v
```

Expected: 모든 테스트 PASS

**Step 5: 전체 테스트 실행**

```bash
.venv/bin/python -m pytest tests/ -v
```

Expected: 전체 PASS (회귀 없음)

**Step 6: 커밋**

```bash
git add netwatcher/services/ai_analyzer.py tests/test_services/test_ai_analyzer.py
git commit -m "feat(ai): add MISSED_THREAT branch in _apply_result with reasoning"
```

---

### Task 8: config/default.yaml — 미탐 관련 파라미터 추가

**Files:**
- Modify: `config/default.yaml:290-298`

**Step 1: 설정 파일 수정**

`ai_analyzer` 섹션에 2개 파라미터 추가:

```yaml
  ai_analyzer:
    enabled: true
    provider: "copilot"
    interval_minutes: 15
    lookback_minutes: 30
    max_events: 50
    consecutive_fp_threshold: 2
    max_threshold_increase_pct: 20
    consecutive_mt_threshold: 2      # 연속 미탐 판정 횟수 → 임계값 하향
    max_threshold_decrease_pct: 10   # 임계값 자동 하향 최대 폭 (%)
    copilot_timeout_seconds: 60
```

**Step 2: 전체 테스트 실행**

```bash
.venv/bin/python -m pytest tests/ -v
```

Expected: 전체 PASS

**Step 3: 서비스 재시작하여 설정 로드 확인**

```bash
sudo systemctl restart netwatcher.service
sudo journalctl -u netwatcher.service -n 20 --no-pager
```

Expected: `AIAnalyzerService started` 로그 확인, 에러 없음

**Step 4: 커밋**

```bash
git add config/default.yaml
git commit -m "feat(config): add consecutive_mt_threshold and max_threshold_decrease_pct"
```

---

### Task 9: 최종 확인 및 push

**Step 1: 전체 테스트 최종 실행**

```bash
.venv/bin/python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

Expected: 전체 PASS, 신규 테스트 포함 926+ passed

**Step 2: 서비스 상태 최종 확인**

```bash
sudo systemctl is-active netwatcher.service
sudo journalctl -u netwatcher.service -n 30 --no-pager
```

Expected: `active`, 에러 로그 없음

**Step 3: push**

```bash
git push origin main
```

---

## 변경 파일 요약

| 파일 | 변경 유형 | 주요 내용 |
|------|----------|-----------|
| `alembic/versions/003_events_reasoning.py` | 신규 | events.reasoning TEXT 컬럼 마이그레이션 |
| `netwatcher/storage/repositories.py` | 수정 | insert()에 reasoning 파라미터 추가 |
| `netwatcher/services/ai_analyzer.py` | 수정 | AnalysisResult, 파싱, 프롬프트, 이벤트 조회, __init__, _try_lower_threshold, _apply_result |
| `config/default.yaml` | 수정 | consecutive_mt_threshold, max_threshold_decrease_pct |
| `tests/test_services/test_ai_analyzer.py` | 수정 | 신규 케이스 추가 (MISSED_THREAT, reasoning, INFO 이벤트) |
