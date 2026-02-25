"""ruamel.yaml 기반 YAML 설정 편집기.

주석, 포맷팅, 키 순서를 보존하면서 엔진 설정 섹션을 안전하게 수정한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


class YamlConfigEditor:
    """YAML 설정 파일의 엔진 섹션을 주석 보존 방식으로 편집한다.

    ruamel.yaml의 round-trip 모드를 사용하여 주석, 인라인 주석,
    키 순서, 포맷팅을 모두 보존한다.
    """

    def __init__(self, yaml_path: str) -> None:
        self._path = Path(yaml_path)
        self._yaml = YAML()
        self._yaml.preserve_quotes = True

    def get_engine_config(self, engine_name: str) -> dict | None:
        """지정된 엔진의 설정을 dict 복사본으로 반환한다.

        Args:
            engine_name: 엔진 이름 (예: "port_scan", "dns_anomaly")

        Returns:
            엔진 설정 dict 복사본. 엔진이 존재하지 않으면 None.
        """
        data = self._load()
        engines = data.get("netwatcher", {}).get("engines", {})
        engine_section = engines.get(engine_name)
        if engine_section is None:
            return None
        return dict(engine_section)

    def update_engine_config(self, engine_name: str, updates: dict[str, Any]) -> None:
        """지정된 엔진의 설정을 부분 업데이트한다.

        업데이트 전 .bak 백업 파일을 생성한다. 지정된 키만 변경하며,
        나머지 키와 주석/포맷팅은 보존된다.

        Args:
            engine_name: 엔진 이름
            updates: 업데이트할 키-값 쌍

        Raises:
            KeyError: 엔진이 YAML에 존재하지 않는 경우
        """
        shutil.copy2(str(self._path), str(self._path) + ".bak")

        data = self._load()
        engines = data.get("netwatcher", {}).get("engines", {})
        engine_section = engines.get(engine_name)
        if engine_section is None:
            raise KeyError(f"Engine '{engine_name}' not found in config")

        for key, value in updates.items():
            engine_section[key] = value

        self._save(data)

    def _load(self) -> Any:
        """YAML 파일을 round-trip 모드로 로드한다."""
        with open(self._path, encoding="utf-8") as f:
            return self._yaml.load(f)

    def _save(self, data: Any) -> None:
        """YAML 데이터를 파일에 저장한다 (주석/포맷팅 보존)."""
        with open(self._path, "w", encoding="utf-8") as f:
            self._yaml.dump(data, f)
