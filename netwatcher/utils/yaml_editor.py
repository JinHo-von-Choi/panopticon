"""ruamel.yaml 기반 YAML 설정 편집기.

주석, 포맷팅, 키 순서를 보존하면서 엔진 설정 섹션을 안전하게 수정한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import shutil
import os
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


class ConfigurationReadOnlyError(PermissionError):
    """배포의 읽기 전용 설정 계약."""


class YamlConfigEditor:
    """YAML 설정 파일의 엔진 섹션을 주석 보존 방식으로 편집한다.

    ruamel.yaml의 round-trip 모드를 사용하여 주석, 인라인 주석,
    키 순서, 포맷팅을 모두 보존한다.
    """

    def __init__(self, yaml_path: str) -> None:
        self._path = Path(yaml_path)
        self._lock = threading.RLock()
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

    def ensure_writable(self) -> None:
        """런타임 적용 전에 읽기 전용 파일/볼륨을 명시적으로 거부한다."""
        parent = self._path.parent
        if (os.statvfs(parent).f_flag & os.ST_RDONLY
                or not self._path.stat().st_mode & 0o222
                or not parent.stat().st_mode & 0o222
                or not os.access(parent, os.W_OK)):
            raise ConfigurationReadOnlyError("Configuration is read-only")

    def update_engine_config(self, engine_name: str, updates: dict[str, Any]) -> None:
        with self._lock:
            self.ensure_writable()
            data = self._load()
            engine = data.get("netwatcher", {}).get("engines", {}).get(engine_name)
            if engine is None:
                raise KeyError(f"Engine '{engine_name}' not found in config")
            engine.update(updates)
            self._save(data)

    def update_whitelist_config(self, updates: dict[str, Any]) -> None:
        with self._lock:
            self.ensure_writable()
            data = self._load()
            section = data.setdefault("netwatcher", {}).setdefault("whitelist", {})
            for key, value in updates.items():
                section[key] = [str(v) for v in value] if isinstance(value, list) else value
            self._save(data)

    def _load(self) -> Any:
        """YAML 파일을 round-trip 모드로 로드한다."""
        with open(self._path, encoding="utf-8") as f:
            return self._yaml.load(f)

    def _save(self, data: Any) -> None:
        """완성된 임시 파일만 동일 디렉터리에서 원자적으로 교체한다."""
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self._path.parent,
                                              prefix=".netwatcher-", delete=False) as stream:
                temporary = stream.name
                os.fchmod(stream.fileno(), stat.S_IMODE(self._path.stat().st_mode))
                self._yaml.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            shutil.copy2(self._path, str(self._path) + ".bak")
            os.replace(temporary, self._path)
            temporary = None
        except OSError as exc:
            if exc.errno in (13, 30):
                raise ConfigurationReadOnlyError("Configuration is read-only") from exc
            raise
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)
