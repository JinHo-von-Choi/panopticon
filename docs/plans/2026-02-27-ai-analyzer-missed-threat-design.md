# AIAnalyzer 미탐 감지 및 판단 근거 저장 — 설계 문서

**작성자**: 최진호
**작성일**: 2026-02-27

---

## 목표

AIAnalyzerService가 기존의 오탐(FP) 처리 외에, 탐지 엔진이 놓친 위협(미탐, MISSED_THREAT)을 감지하고 경고하며 탐지 민감도를 자동으로 상향 조정한다. 또한 AI 판단 근거를 구조화하여 DB에 저장한다.

---

## 변경 요약

| 구분 | 기존 | 변경 후 |
|------|------|---------|
| verdict 종류 | CONFIRMED_THREAT / FALSE_POSITIVE / UNCERTAIN | + MISSED_THREAT 추가 |
| 분석 대상 이벤트 | CRITICAL + WARNING | + INFO 이벤트 추가 (max_events // 3) |
| 임계값 조정 방향 | 오탐 시 상향만 | 오탐 시 상향 + 미탐 시 하향 |
| 판단 근거 저장 | description 필드 단문 | reasoning 전용 컬럼 (번호 목록) |
| DB 스키마 | - | events 테이블에 reasoning TEXT 컬럼 추가 |

---

## 설계

### 1. 새 verdict: MISSED_THREAT

```
CONFIRMED_THREAT  — 탐지된 알림이 실제 위협
FALSE_POSITIVE    — 탐지된 알림이 오탐 → 임계값 상향
MISSED_THREAT     — INFO/낮은 confidence 이벤트가 실제로 더 심각 → 임계값 하향 + 알림
UNCERTAIN         — 판단 불가
```

### 2. 이벤트 컨텍스트 확장

`_fetch_recent_events()`에서 INFO 이벤트를 최대 `max_events // 3`개 추가로 가져온다.

```python
info_events = await self._event_repo.list_recent(
    severity="INFO", since=since, limit=max_events // 3,
)
merged = criticals + warnings + info_events
```

AI는 INFO 이벤트를 보고 "이것이 실제로는 더 위험한 것 아닌가"를 판단할 수 있다.

### 3. 프롬프트 형식 변경

응답 포맷에 `MISSED_THREAT` verdict와 `REASONING:` 항목 추가:

```
VERDICT: CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | UNCERTAIN
ENGINE: <engine_name>
REASON: <한 줄 요약>
REASONING:
1. <근거 1>
2. <근거 2>
3. <근거 3>
ADJUST: <param>=<numeric_value>  (FALSE_POSITIVE 시 상향값, MISSED_THREAT 시 하향값)
```

프롬프트 지시사항에 두 가지 분석 방향을 명시:
1. CRITICAL/WARNING 알림 중 오탐이 있는가 (→ FALSE_POSITIVE)
2. INFO/낮은 confidence 이벤트 중 실제 더 심각한 위협이 있는가 (→ MISSED_THREAT)

### 4. AnalysisResult 확장

```python
@dataclass
class AnalysisResult:
    verdict:   str
    engine:    str
    reason:    str = ""
    reasoning: str = ""          # 번호 목록 형식 판단 근거 (신규)
    adjustments: dict[str, float] = field(default_factory=dict)
```

### 5. DB 마이그레이션

`events` 테이블에 `reasoning TEXT` 컬럼 추가 (nullable).

```sql
ALTER TABLE netwatcher.events ADD COLUMN reasoning TEXT;
```

Alembic 마이그레이션 파일 생성.

`EventRepository.insert()`에 `reasoning: str | None = None` 파라미터 추가.

### 6. _try_lower_threshold() 신규 메서드

`_try_adjust_threshold()`의 대칭 구조.

```
_consecutive_mt: dict[str, int]  — 연속 미탐 카운터

동작:
1. _consecutive_mt[engine] += 1
2. consecutive_mt_threshold 미만이면 카운터만 증가
3. 임계값 도달 시:
   - yaml_editor.get_engine_config(engine)으로 현재값 조회
   - cap 적용: max(requested, current * (1 - max_threshold_decrease_pct / 100))
   - yaml_editor.update_engine_config(engine, capped)
   - registry.reload_engine(engine, new_cfg)
   - _consecutive_mt[engine] = 0
   - DB insert (engine="ai_adjustment", severity="WARNING")
```

하향 cap 적용 방향 (오탐과 반대):
- AI 제안값과 `current * (1 - pct/100)` 중 **큰 쪽** 선택 (너무 급격한 하향 방지)

### 7. _apply_result() MISSED_THREAT 분기 추가

```python
elif result.verdict == "MISSED_THREAT":
    # CRITICAL 알림 발생
    alert = Alert(engine="ai_analyzer", severity=Severity.CRITICAL,
                  title=f"[AI 미탐] {result.engine} — 탐지 누락 의심",
                  description=result.reason, confidence=0.8, ...)
    self._dispatcher.enqueue(alert)

    # DB 저장 (reasoning 포함)
    await self._event_repo.insert(
        engine="ai_analyzer", severity="CRITICAL",
        title=f"[AI 미탐] {result.engine} — 탐지 누락 의심",
        description=result.reason,
        reasoning=result.reasoning,
        metadata={"verdict": "MISSED_THREAT", ...},
    )

    # 임계값 하향 시도
    self._try_lower_threshold(result.engine, result.adjustments)
```

기존 CONFIRMED_THREAT, FALSE_POSITIVE, UNCERTAIN에도 `reasoning=result.reasoning` 추가.

### 8. 설정 추가

```yaml
ai_analyzer:
  consecutive_mt_threshold: 2      # 연속 미탐 판정 횟수 → 임계값 하향
  max_threshold_decrease_pct: 10   # 임계값 자동 하향 최대 폭 (%)
```

---

## 영향 범위

| 파일 | 변경 유형 |
|------|----------|
| `netwatcher/services/ai_analyzer.py` | 수정 (주요) |
| `netwatcher/storage/repositories.py` | 수정 (reasoning 파라미터) |
| `alembic/versions/xxxx_add_reasoning.py` | 신규 |
| `config/default.yaml` | 수정 (2개 파라미터 추가) |
| `tests/test_services/test_ai_analyzer.py` | 수정 (신규 케이스 추가) |
| `tests/test_storage/` | 수정 (reasoning 파라미터) |

---

## 비고

- AI CLI 미설치 / 타임아웃 시 기존과 동일하게 해당 사이클 건너뜀 (비치명적)
- 임계값 하향은 `consecutive_mt_threshold` 연속 도달 시에만 적용 — 단발 오감지에 의한 과민화 방지
- `reasoning` 컬럼은 nullable — 기존 이벤트 호환성 유지
