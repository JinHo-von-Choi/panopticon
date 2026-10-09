"""인증되지 않은 모델은 역직렬화 전에 거부한다."""

import pickle
from pathlib import Path

import pytest

from netwatcher.ml.model_manager import ModelManager


class ExecutableModel:
    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return Path.write_text, (self.marker, "executed")


def write_private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


@pytest.mark.parametrize("attack", ["unsigned", "modified", "other_store", "renamed"])
def test_untrusted_pickle_never_executes(tmp_path, attack):
    first = tmp_path / "first"
    second = tmp_path / "second"
    owner = ModelManager(str(first))
    owner.save("model", {"safe": True})
    marker = tmp_path / "executed"
    malicious = pickle.dumps((ExecutableModel(marker), {}))
    target = first / "model.pkl"
    if attack == "unsigned":
        write_private(target, malicious)
    elif attack == "modified":
        original = target.read_bytes()
        write_private(target, original[:50] + malicious)
    elif attack == "other_store":
        other = ModelManager(str(second))
        foreign = other.save("model", ExecutableModel(marker))
        write_private(target, foreign.read_bytes())
    else:
        signed = owner.save("different", ExecutableModel(marker))
        write_private(target, signed.read_bytes())
    assert owner.load("model") is None
    assert not marker.exists()


@pytest.mark.parametrize("name", ["../escape", "a/b", "", ".artifact-key", "a" * 101])
def test_names_cannot_escape_storage(tmp_path, name):
    manager = ModelManager(str(tmp_path))
    with pytest.raises(ValueError, match="name"):
        manager.save(name, {})
    with pytest.raises(ValueError, match="name"):
        manager.load(name)


@pytest.mark.parametrize("entry", ["model.pkl", ".artifact-key"])
def test_symbolic_links_are_rejected(tmp_path, entry):
    manager = ModelManager(str(tmp_path / "models"))
    manager.save("model", {"safe": True})
    artifact = tmp_path / "models" / entry
    outside = tmp_path / "outside"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)
    assert manager.load("model") is None
    assert outside.read_bytes()


def test_world_readable_directory_is_rejected(tmp_path):
    directory = tmp_path / "models"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    manager = ModelManager(str(directory))
    with pytest.raises(ValueError, match="0700"):
        manager.save("model", {})


def test_json_metadata_cannot_override_authenticated_training_state(tmp_path):
    manager = ModelManager(str(tmp_path))
    manager.save("model", {}, {"trained_at_epoch": 123})
    (tmp_path / "model.meta.json").write_text('{"trained_at_epoch": 999}')
    _, metadata = manager.load("model")
    assert metadata["trained_at_epoch"] == 123
    assert (tmp_path / ".artifact-key").stat().st_mode & 0o777 == 0o600
