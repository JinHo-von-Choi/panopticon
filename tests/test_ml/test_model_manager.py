"""ModelManager 단위 테스트.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import json

import pytest

from netwatcher.ml.model_manager import ModelManager


class TestModelManager:
    """ModelManager 저장/로드 동작 검증."""

    def test_save_creates_files(self, tmp_path):
        """save()가 .pkl과 .meta.json 파일을 생성한다."""
        mgr = ModelManager(models_dir=str(tmp_path))
        model = {"type": "test", "weights": [1.0, 2.0, 3.0]}
        path = mgr.save("test_model", model, {"version": "1.0"})

        assert path.exists()
        assert (tmp_path / "test_model.pkl").exists()
        assert (tmp_path / "test_model.meta.json").exists()

    def test_save_metadata_contains_defaults(self, tmp_path):
        """메타데이터에 saved_at와 name이 자동 포함된다."""
        mgr = ModelManager(models_dir=str(tmp_path))
        mgr.save("my_model", [1, 2, 3])

        meta_path = tmp_path / "my_model.meta.json"
        with open(meta_path) as f:
            meta = json.load(f)
        assert "saved_at" in meta
        assert meta["name"] == "my_model"

    def test_load_returns_none_for_missing(self, tmp_path):
        """존재하지 않는 모델에 대해 None을 반환한다."""
        mgr = ModelManager(models_dir=str(tmp_path))
        assert mgr.load("nonexistent") is None

    def test_save_then_load_roundtrip(self, tmp_path):
        """저장한 모델과 메타데이터를 정확히 로드한다."""
        mgr = ModelManager(models_dir=str(tmp_path))
        original_model = {"weights": [0.1, 0.2], "bias": 0.5}
        original_meta  = {"epochs": 10, "accuracy": 0.95}

        mgr.save("roundtrip", original_model, original_meta)
        result = mgr.load("roundtrip")

        assert result is not None
        loaded_model, loaded_meta = result
        assert loaded_model == original_model
        assert loaded_meta["epochs"] == 10
        assert loaded_meta["accuracy"] == 0.95

    def test_load_without_metadata_file(self, tmp_path):
        """메타데이터 파일이 없어도 모델은 로드된다."""
        mgr = ModelManager(models_dir=str(tmp_path))
        mgr.save("no_meta", {"data": 42})

        # 메타데이터 파일 삭제
        (tmp_path / "no_meta.meta.json").unlink()

        result = mgr.load("no_meta")
        assert result is not None
        model, meta = result
        assert model == {"data": 42}
        assert meta == {}

    def test_save_creates_directory(self, tmp_path):
        """models_dir이 없으면 자동 생성한다."""
        nested = tmp_path / "deep" / "nested" / "dir"
        mgr = ModelManager(models_dir=str(nested))
        mgr.save("deep_model", [1])
        assert (nested / "deep_model.pkl").exists()

    def test_overwrite_existing_model(self, tmp_path):
        """같은 이름으로 저장하면 기존 모델을 덮어쓴다."""
        mgr = ModelManager(models_dir=str(tmp_path))
        mgr.save("overwrite", {"v": 1})
        mgr.save("overwrite", {"v": 2})

        result = mgr.load("overwrite")
        assert result is not None
        model, _ = result
        assert model == {"v": 2}
