"""실험용 모델을 사용자 전용 저장소에 인증하여 보관한다.

이전 서명 없는 모델과 다른 저장소의 모델은 로드하지 않는다. 다시 학습한다.
저장소와 서명 키를 관리하는 실행 사용자는 신뢰해야 한다.
"""

from __future__ import annotations

import json
import logging
import os
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netwatcher.ml import artifact_store as store

logger = logging.getLogger("netwatcher.ml.model_manager")


class ModelManager:
    def __init__(self, models_dir: str = "data/models") -> None:
        self._models_dir = Path(models_dir)

    def save(self, name: str, model: Any, metadata: dict[str, Any] | None = None) -> Path:
        store.validate_name(name)
        meta = dict(metadata or {})
        meta.setdefault("saved_at", datetime.now(timezone.utc).isoformat())
        meta.setdefault("name", name)
        # 모델과 학습 정보를 함께 인증한다. JSON 파일은 사람이 읽는 사본이다.
        payload = pickle.dumps((model, meta), protocol=pickle.HIGHEST_PROTOCOL)
        directory = store.open_directory(self._models_dir, create=True)
        try:
            key = store.get_key(directory, create=True)
            store.atomic_write(directory, f"{name}.pkl", store.sign(name, payload, key))
            store.atomic_write(directory, f"{name}.meta.json",
                               json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))
        finally:
            os.close(directory)
        logger.info("Authenticated model '%s' saved", name)
        return self._models_dir / f"{name}.pkl"

    def load(self, name: str) -> tuple[Any, dict[str, Any]] | None:
        store.validate_name(name)
        try:
            directory = store.open_directory(self._models_dir)
        except FileNotFoundError:
            return None
        try:
            try:
                key = store.get_key(directory)
                data = store.read_private(directory, f"{name}.pkl", store.MAX_BYTES + len(store.MAGIC) + 32)
                payload = store.verify(name, data, key)
            except FileNotFoundError:
                return None
            except (ValueError, OSError):
                logger.warning("Model '%s' rejected; retrain the experimental model", name)
                return None
            # 인증은 역직렬화 전에 끝난다. 저장소 실행 사용자가 만든 모델만 허용한다.
            model, metadata = pickle.loads(payload)
            if not isinstance(metadata, dict):
                raise ValueError("Invalid authenticated model metadata")
            logger.info("Authenticated model '%s' loaded", name)
            return model, metadata
        finally:
            os.close(directory)
