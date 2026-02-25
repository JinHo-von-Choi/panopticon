# Engine Configuration UI Design

## Goal

대시보드에서 각 탐지 엔진의 설정을 실시간으로 조회/수정/토글할 수 있는 기능 구현.

## Architecture

Schema-Driven Dynamic Form 방식. 각 엔진의 `config_schema`를 API로 노출하고, 프론트엔드에서 스키마 기반으로 폼을 자동 생성한다. 설정 변경 시 YAML 파일을 직접 수정하고 엔진을 즉시 핫리로드한다.

## Tech Stack

- Backend: FastAPI (기존)
- YAML 수정: ruamel.yaml (주석/구조 보존)
- Frontend: Vanilla JS (기존 패턴)

---

## 1. config_schema 확장

기존 tuple 형식 `(type, default)`에 dict 형식 추가:

```python
config_schema = {
    "window_seconds": {
        "type": int,
        "default": 60,
        "label": "Detection Window",
        "description": "Time window for scan detection (seconds)",
        "min": 5,
        "max": 3600,
    },
}
```

하위 호환성: `DetectionEngine`에서 tuple/dict 모두 처리. tuple은 label=key name, description=없음으로 폴백.

## 2. Backend API

| Method | Path | 설명 |
|--------|------|------|
| `GET` | `/api/engines` | 전체 엔진 목록 (이름, enabled, 설정값, 스키마) |
| `GET` | `/api/engines/{name}` | 단일 엔진 상세 |
| `PUT` | `/api/engines/{name}/config` | 설정값 변경 + YAML 저장 + 핫리로드 |
| `PATCH` | `/api/engines/{name}/toggle` | enabled 토글 |

### 핫리로드 흐름

1. schema 타입/범위 검증
2. config/default.yaml 백업 (`.bak`)
3. ruamel.yaml로 해당 엔진 섹션만 업데이트
4. EngineRegistry에서 엔진 shutdown → 새 config로 재생성
5. 실패 시 이전 config로 롤백

### 토글 흐름

- `enabled: false` → registry에서 엔진 shutdown + 제거
- `enabled: true` → 새 config로 엔진 생성 + registry에 등록

## 3. Frontend UI

대시보드에 **Engines 탭** 추가:

- 엔진 목록: 카드 리스트, 각 카드에 이름 + enabled 토글
- 설정 폼: 선택한 엔진의 schema 기반 자동 생성
  - `int`/`float` → number input (min/max)
  - `bool` → toggle switch
  - `str` → text input
  - `list` → 태그 입력 (쉼표 구분)
- 저장 버튼 + 성공/실패 피드백

## 4. 안전장치

- YAML 수정 전 `.bak` 백업
- schema 타입/범위 검증 실패 시 400, YAML 미수정
- 엔진 재생성 실패 시 이전 config로 롤백
