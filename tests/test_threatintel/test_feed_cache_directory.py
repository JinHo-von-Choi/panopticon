"""위협 피드 캐시 디렉터리 선택."""

from pathlib import Path

from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.utils.config import Config


def _manager(tmp_path, **threatfeeds):
    return FeedManager(Config({"threatfeeds": {"config_path": str(tmp_path / "unused.yaml"), **threatfeeds}}))


def test_configured_cache_dir_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    manager = _manager(tmp_path, cache_dir=str(tmp_path / "explicit"))
    assert manager._cache_dir == tmp_path / "explicit"
    assert manager._cache_dir.is_dir()


def test_xdg_cache_home_used_when_working_directory_is_read_only(tmp_path, monkeypatch):
    readonly = tmp_path / "source"
    readonly.mkdir()
    readonly.chmod(0o555)
    monkeypatch.chdir(readonly)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "state" / "cache"))
    try:
        manager = _manager(tmp_path)
    finally:
        readonly.chmod(0o755)
    assert manager._cache_dir == tmp_path / "state" / "cache" / "threatfeeds"
    assert manager._cache_dir.is_dir()
    assert not (readonly / "data").exists()


def test_default_cache_dir_without_overrides(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    assert _manager(tmp_path)._cache_dir == Path("data/threatfeeds")
