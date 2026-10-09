"""변조된 이미지 자료는 배포 체크섬 생성 전에 거절한다."""

import hashlib
import io
import json
import tarfile

import pytest

from scripts.release_image_manifest import TARGETS, write_manifest


@pytest.fixture
def image_release(tmp_path):
    release = tmp_path / 'release'
    metadata = tmp_path / 'metadata'
    release.mkdir()
    metadata.mkdir()
    (release / 'release.json').write_text(json.dumps({'version': '0.5.0', 'source_commit': '1' * 40}))
    (release / 'SHA256SUMS').write_text('original checksums\n')
    content = b'{"schemaVersion":2,"manifests":[]}'
    digest = 'sha256:' + hashlib.sha256(content).hexdigest()
    for target in TARGETS:
        (metadata / (target + '-image.json')).write_text(json.dumps({'containerimage.digest': digest}))
    return release, metadata, content, digest


def archive(release, target, content, digest, index_digest=None):
    data = {'index.json': json.dumps({'manifests': [{'digest': index_digest or digest}]}).encode(),
            'blobs/sha256/' + digest.split(':')[1]: content}
    with tarfile.open(release / f'panopticon-0.5.0-{target}.oci.tar', 'w') as bundle:
        for name, value in data.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            bundle.addfile(member, io.BytesIO(value))


@pytest.mark.parametrize('change', ['blob', 'index', 'metadata'])
def test_modified_oci_identity_is_rejected_without_replacing_checksums(image_release, change):
    release, metadata, content, digest = image_release
    for target in TARGETS:
        archive(release, target, content, digest)
    if change == 'blob':
        archive(release, TARGETS[0], b'{"changed":true}', digest)
    elif change == 'index':
        archive(release, TARGETS[0], content, digest, 'sha256:' + '0' * 64)
    else:
        (metadata / (TARGETS[0] + '-image.json')).write_text(json.dumps({'containerimage.digest': '../unexpected'}))
    with pytest.raises(ValueError):
        write_manifest(release, metadata)
    assert not (release / 'images.json').exists()
    assert (release / 'SHA256SUMS').read_text() == 'original checksums\n'


def test_existing_image_manifest_is_preserved(image_release):
    release, metadata, _, _ = image_release
    (release / 'images.json').write_text('existing manifest\n')
    with pytest.raises(FileExistsError):
        write_manifest(release, metadata)
    assert (release / 'images.json').read_text() == 'existing manifest\n'


@pytest.mark.parametrize('change', ['commit', 'platform'])
def test_valid_hashes_cannot_hide_wrong_source_or_platform(image_release, change):
    release, metadata, _, _ = image_release
    configuration = {'architecture': 'amd64', 'os': 'linux', 'config': {'Labels': {
        'org.opencontainers.image.revision': '1' * 40,
        'org.opencontainers.image.version': '0.5.0'}}}
    if change == 'commit':
        configuration['config']['Labels']['org.opencontainers.image.revision'] = '2' * 40
    else:
        configuration['architecture'] = 'arm64'
    config_bytes = json.dumps(configuration).encode()
    config_digest = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
    image_bytes = json.dumps({'schemaVersion': 2, 'config': {'digest': config_digest}}).encode()
    image_digest = 'sha256:' + hashlib.sha256(image_bytes).hexdigest()
    target = TARGETS[0]
    (metadata / (target + '-image.json')).write_text(json.dumps({'containerimage.digest': image_digest}))
    with tarfile.open(release / f'panopticon-0.5.0-{target}.oci.tar', 'w') as bundle:
        for name, content in {'index.json': json.dumps({'manifests': [{'digest': image_digest}]}).encode(),
                'blobs/sha256/' + image_digest.split(':')[1]: image_bytes,
                'blobs/sha256/' + config_digest.split(':')[1]: config_bytes}.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
    with pytest.raises(ValueError, match='differs from release metadata'):
        write_manifest(release, metadata)
    assert not (release / 'images.json').exists()
    assert (release / 'SHA256SUMS').read_text() == 'original checksums\n'
