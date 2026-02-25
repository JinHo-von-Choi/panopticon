"""config_schema 정규화 유틸리티.

엔진의 config_schema를 tuple 형식과 확장 dict 형식 모두에서
통일된 구조로 정규화하고, API 응답용 직렬화를 제공한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

from typing import Any

# 지원하는 타입 → API 직렬화 문자열 매핑
_TYPE_NAMES: dict[type, str] = {
    int:   "int",
    float: "float",
    bool:  "bool",
    str:   "str",
    list:  "list",
}


def normalize_schema_field(key: str, spec: tuple | dict) -> dict[str, Any]:
    """단일 스키마 필드를 정규화된 dict로 변환한다.

    Args:
        key: 설정 키 이름.
        spec: tuple ``(type, default)`` 또는 확장 dict 형식.

    Returns:
        정규화된 필드 정의::

            {
                "type":        <type>,
                "default":     <value>,
                "label":       <str>,
                "description": <str>,
                "min":         <number | None>,
                "max":         <number | None>,
            }

    Raises:
        ValueError: spec가 tuple이나 dict가 아니거나 필수 키가 누락된 경우.
    """
    if isinstance(spec, tuple):
        if len(spec) != 2:
            raise ValueError(
                f"Invalid tuple schema spec for '{key}': "
                f"expected (type, default), got tuple of length {len(spec)}"
            )
        field_type, default = spec
        return {
            "type":        field_type,
            "default":     default,
            "label":       key,
            "description": "",
            "min":         None,
            "max":         None,
        }

    if isinstance(spec, dict):
        for required in ("type", "default"):
            if required not in spec:
                raise ValueError(
                    f"Dict schema spec for '{key}' missing required key '{required}'"
                )
        return {
            "type":        spec["type"],
            "default":     spec["default"],
            "label":       spec.get("label", key),
            "description": spec.get("description", ""),
            "min":         spec.get("min", None),
            "max":         spec.get("max", None),
        }

    raise ValueError(
        f"Invalid schema spec for '{key}': expected tuple or dict, "
        f"got {type(spec).__name__}"
    )


def normalize_schema(schema: dict) -> dict[str, dict]:
    """전체 config_schema를 정규화한다.

    Args:
        schema: 엔진의 ``config_schema`` dict.

    Returns:
        키 순서가 보존된 정규화된 스키마 dict.
    """
    return {
        key: normalize_schema_field(key, spec)
        for key, spec in schema.items()
    }


def schema_to_api(schema: dict) -> list[dict]:
    """스키마를 API 직렬화 가능한 리스트로 변환한다.

    type 객체를 문자열로 변환하고, 각 필드에 ``key``를 추가한다.

    Args:
        schema: 엔진의 ``config_schema`` dict (tuple 또는 dict 형식 모두 지원).

    Returns:
        API 응답용 필드 리스트::

            [
                {
                    "key":         "threshold",
                    "type":        "int",
                    "default":     15,
                    "label":       "threshold",
                    "description": "",
                    "min":         None,
                    "max":         None,
                },
                ...
            ]
    """
    normalized = normalize_schema(schema)
    result: list[dict] = []
    for key, field in normalized.items():
        field_type = field["type"]
        type_name  = _TYPE_NAMES.get(field_type, field_type.__name__)
        result.append({
            "key":         key,
            "type":        type_name,
            "default":     field["default"],
            "label":       field["label"],
            "description": field["description"],
            "min":         field["min"],
            "max":         field["max"],
        })
    return result
