"""ML 모델 디스크 저장 및 로드 모듈.

pickle은 sklearn IsolationForest 직렬화를 위해 의도적으로 사용한다.
모델 파일은 자체 생성 데이터만 포함하며 외부 입력을 역직렬화하지 않는다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import json
import logging
import pickle  # noqa: S403 — ML 모델 직렬화 전용, 외부 입력 아님
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("netwatcher.ml.model_manager")


class ModelManager:
    """ML 모델을 디스크에 저장하고 로드한다.

    모델은 pickle 형식으로 직렬화되며, 메타데이터는 JSON으로 별도 보관한다.
    sklearn 모델의 표준 직렬화 방법이며, 자체 생성 파일만 처리한다.
    """

    def __init__(self, models_dir: str = "data/models") -> None:
        """모델 매니저를 초기화한다.

        Args:
            models_dir: 모델 파일을 저장할 디렉토리 경로.
        """
        self._models_dir = Path(models_dir)

    def save(self, name: str, model: Any, metadata: dict[str, Any] | None = None) -> Path:
        """모델과 메타데이터를 디스크에 저장한다.

        Args:
            name:     모델 이름 (파일명 접두사).
            model:    직렬화할 모델 객체.
            metadata: 모델과 함께 저장할 메타데이터 딕셔너리.

        Returns:
            저장된 모델 파일의 Path.
        """
        self._models_dir.mkdir(parents=True, exist_ok=True)

        model_path = self._models_dir / f"{name}.pkl"
        meta_path  = self._models_dir / f"{name}.meta.json"

        with open(model_path, "wb") as f:
            pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)

        meta = metadata or {}
        meta.setdefault("saved_at", datetime.now(timezone.utc).isoformat())
        meta.setdefault("name", name)

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

        logger.info("Model '%s' saved to %s", name, model_path)
        return model_path

    def load(self, name: str) -> tuple[Any, dict[str, Any]] | None:
        """디스크에서 모델과 메타데이터를 로드한다.

        자체 생성한 모델 파일만 로드하며, 외부 제공 파일을 역직렬화하지 않는다.

        Args:
            name: 모델 이름 (파일명 접두사).

        Returns:
            (model, metadata) 튜플. 파일이 없으면 None.
        """
        model_path = self._models_dir / f"{name}.pkl"
        meta_path  = self._models_dir / f"{name}.meta.json"

        if not model_path.exists():
            logger.debug("Model '%s' not found at %s", name, model_path)
            return None

        with open(model_path, "rb") as f:
            model = pickle.load(f)  # noqa: S301 — 자체 생성 모델 파일만 역직렬화

        metadata: dict[str, Any] = {}
        if meta_path.exists():
            with open(meta_path, encoding="utf-8") as f:
                metadata = json.load(f)

        logger.info("Model '%s' loaded from %s", name, model_path)
        return model, metadata
