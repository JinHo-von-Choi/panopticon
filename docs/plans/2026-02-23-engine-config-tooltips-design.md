# Engine Config UI Tooltips Design

작성자: 최진호
작성일: 2026-02-23

## 목적

대시보드 엔진 설정 UI에서 각 설정값의 의미와 변경 시 영향을 알 수 없는 문제 해결.
Swagger docs처럼 각 필드에 대한 구조화된 설명을 제공한다.

## 현재 상태

- 17개 엔진의 `config_schema`가 `(type, default)` 튜플 형식만 사용
- `schema_utils.py`에 dict 형식(description, label, min, max) 지원 코드가 이미 존재하나 미활용
- UI에 `engine-field-desc` 렌더링 코드가 있으나 description이 빈 문자열

## 설계

### 1. 백엔드: config_schema 확장

17개 엔진의 config_schema를 dict 형식으로 전환:

```python
# Before
config_schema = {
    "gratuitous_threshold": (int, 10),
}

# After
config_schema = {
    "gratuitous_threshold": {
        "type": int, "default": 10, "min": 1, "max": 100,
        "label": "Gratuitous ARP 임계값",
        "description": "슬라이딩 윈도우 내 Gratuitous ARP 패킷 수가 이 값을 초과하면 알림 발생. "
                       "낮추면 민감도 증가(오탐 증가), 높이면 민감도 감소.",
    },
}
```

### 2. 프론트엔드: JS 동적 툴팁

- 각 필드 label 옆에 `(?)` 아이콘 배치
- `label` 값이 있으면 key 대신 label 표시
- 호버/클릭 시 구조화된 툴팁 표시 (타입, 기본값, 범위, 설명)
- 화면 경계 자동 조정
- 모바일: 클릭으로 토글

### 3. 변경 파일

| 파일 | 변경 |
|------|------|
| `netwatcher/detection/engines/*.py` (17개) | config_schema dict 형식 + 메타데이터 |
| `netwatcher/web/static/js/app.js` | 툴팁 렌더링 + label 표시 |
| `netwatcher/web/static/css/style.css` | 툴팁 스타일 |

변경 불필요: `schema_utils.py`, `registry.py`, `web/routes/engines.py`
