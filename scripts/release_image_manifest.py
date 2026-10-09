"""OCI 배포 이미지의 digest를 확인하고 릴리스 체크섬에 포함한다."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


TARGETS = ('eve', 'native-console', 'native')


def checksum(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_blob(bundle, digest):
    if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('Invalid OCI blob digest')
    member = bundle.getmember('blobs/sha256/' + digest.split(':')[1])
    if not member.isfile() or member.size > 16 * 1024 * 1024:
        raise ValueError('Invalid OCI manifest blob')
    with bundle.extractfile(member) as stream:
        content = stream.read()
    if hashlib.sha256(content).hexdigest() != digest.split(':')[1]:
        raise ValueError('OCI manifest digest differs from build metadata')
    return json.loads(content)


def write_manifest(release_directory, metadata_directory):
    release = json.loads((release_directory / 'release.json').read_text())
    version, commit = release['version'], release['source_commit']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Invalid release identity')
    output = release_directory / 'images.json'
    if output.exists():
        raise FileExistsError('Image manifest already exists')
    images = []
    for target in TARGETS:
        metadata_path = metadata_directory / (target + '-image.json')
        if metadata_path.stat().st_size > 1024 * 1024:
            raise ValueError('Image metadata exceeds limit')
        metadata = json.loads(metadata_path.read_text())
        digest = metadata['containerimage.digest']
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('Invalid OCI image digest')
        archive_name = f'panopticon-{version}-{target}.oci.tar'
        archive = release_directory / archive_name
        if not 0 < archive.stat().st_size < 2 * 1024**3:
            raise ValueError('OCI archive exceeds release asset limit')
        # 압축 해제 없이 BuildKit이 반환한 digest의 실제 OCI blob을 확인한다.
        with tarfile.open(archive, 'r:') as bundle:
            index_member = bundle.getmember('index.json')
            if not index_member.isfile() or index_member.size > 1024 * 1024:
                raise ValueError('Invalid OCI index')
            with bundle.extractfile(index_member) as stream:
                index = json.load(stream)
            if not any(item.get('digest') == digest for item in index.get('manifests', [])):
                raise ValueError('Build digest is absent from OCI index')
            image = read_blob(bundle, digest)
            if 'config' not in image:
                descriptors = [item for item in image.get('manifests', [])
                    if item.get('platform') == {'architecture': 'amd64', 'os': 'linux'}]
                if len(descriptors) != 1:
                    raise ValueError('Expected one linux/amd64 image')
                image = read_blob(bundle, descriptors[0]['digest'])
            configuration = read_blob(bundle, image['config']['digest'])
            labels = configuration.get('config', {}).get('Labels', {})
            if configuration.get('architecture') != 'amd64' or configuration.get('os') != 'linux':
                raise ValueError('Image platform differs from release metadata')
            if (labels.get('org.opencontainers.image.revision') != commit
                    or labels.get('org.opencontainers.image.version') != version):
                raise ValueError('Image source identity differs from release metadata')
        images.append({'target': target, 'platform': 'linux/amd64',
                       'source_commit': commit, 'oci_digest': digest,
                       'archive': archive_name, 'archive_sha256': checksum(archive)})
    output.write_text(json.dumps({'version': version, 'images': images}, indent=2) + '\n')
    sums = ''.join(checksum(path) + '  ' + path.name + '\n'
                   for path in sorted(release_directory.iterdir())
                   if path.name != 'SHA256SUMS' and path.is_file())
    (release_directory / 'SHA256SUMS').write_text(sums)
    return images


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-directory', type=Path, required=True)
    parser.add_argument('--metadata-directory', type=Path, required=True)
    args = parser.parse_args()
    write_manifest(args.release_directory, args.metadata_directory)
