"""배포물은 태그의 커밋과 버전을 묶고 작업 사본의 파일을 제외한다."""

import hashlib
import io
import json
import subprocess
import tarfile

import pytest

from scripts.build_release import build


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def release_repository(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "netwatcher").mkdir()
    (root / "netwatcher/__init__.py").write_text('__version__ = "0.5.0"\n')
    (root / "requirements.lock").write_text("example==1.0\n")
    for args in [("init", "-q"), ("config", "user.name", "Release test"),
                 ("config", "user.email", "release@example.invalid"),
                 ("add", "."), ("commit", "-qm", "release fixture"), ("tag", "v0.5.0")]:
        git(root, *args)
    return root


def test_archive_excludes_worktree_and_manifest_matches_content(release_repository, tmp_path):
    root = release_repository
    (root / "private.env").write_text("PRIVATE_FIXTURE=not-for-distribution\n")
    (root / "netwatcher/__init__.py").write_text('__version__ = "99.0.0"\n')
    output = tmp_path / "release"
    manifest = build(root, output, "v0.5.0")
    archive = (output / "panopticon-0.5.0.tar.gz").read_bytes()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        assert not any(name.endswith("private.env") for name in bundle.getnames())
        assert b'"0.5.0"' in bundle.extractfile("panopticon-0.5.0/netwatcher/__init__.py").read()
    assert manifest["source_archive_sha256"] == hashlib.sha256(archive).hexdigest()
    bom = json.loads((output / "sbom.cdx.json").read_text())
    assert bom["components"][0]["purl"] == "pkg:pypi/example@1.0"
    for line in (output / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        assert checksum == hashlib.sha256((output / name).read_bytes()).hexdigest()


def test_tag_must_match_application_version(release_repository, tmp_path):
    git(release_repository, "tag", "v0.6.0")
    with pytest.raises(ValueError, match="version differ"):
        build(release_repository, tmp_path / "release", "v0.6.0")
    assert not (tmp_path / "release").exists()


def test_tag_must_match_checkout(release_repository, tmp_path):
    (release_repository / "new.txt").write_text("new commit")
    git(release_repository, "add", ".")
    git(release_repository, "commit", "-qm", "new commit")
    with pytest.raises(ValueError, match="Checkout"):
        build(release_repository, tmp_path / "release", "v0.5.0")


def test_existing_output_is_never_overwritten(release_repository, tmp_path):
    output = tmp_path / "release"
    output.mkdir()
    sentinel = output / "SHA256SUMS"
    sentinel.write_text("preserve")
    with pytest.raises(FileExistsError):
        build(release_repository, output, "v0.5.0")
    assert sentinel.read_text() == "preserve"
