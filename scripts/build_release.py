"""태그의 소스·잠금 의존성·체크섬을 배포 산출물로 묶는다."""

import argparse
import ast
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def version_of(source):
    tree = ast.parse(source)
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__version__' for t in statement.targets):
            version = ast.literal_eval(statement.value)
            if isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
                return version
    raise ValueError('Missing release version')


def dependency_components(lock):
    components = {}
    for line in lock.splitlines():
        if not line.strip() or line.startswith('#') or line[:1].isspace():
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s;]+)(?:\s*;[^\\]*)?\s*\\?', line)
        if match is None:
            raise ValueError('Dependency lock contains an unsupported input')
        name, version = match.groups()
        name = re.sub(r'[-_.]+', '-', name).lower()
        reference = f'pkg:pypi/{name}@{version}'
        components[reference] = {'type': 'library', 'name': name, 'version': version,
                                 'bom-ref': reference, 'purl': reference}
    if not components:
        raise ValueError('Dependency lock is empty')
    return [components[key] for key in sorted(components)]


def build(root, output, tag):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('Use an exact version tag')
    commit = git(root, 'rev-parse', '--verify', tag + '^{commit}').decode().strip()
    if git(root, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('Checkout must match the release tag')
    version = version_of(git(root, 'show', commit + ':netwatcher/__init__.py').decode())
    if tag != 'v' + version:
        raise ValueError('Tag and application version differ')
    lock = git(root, 'show', commit + ':requirements.lock')
    components = dependency_components(lock.decode())
    output.mkdir(parents=True, exist_ok=False)
    archive_name = f'panopticon-{version}.tar.gz'
    archive = git(root, 'archive', '--format=tar', '--prefix=panopticon-' + version + '/', commit)
    (output / archive_name).write_bytes(gzip.compress(archive, mtime=0))
    project_ref = f'panopticon@{commit}'
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
           'serialNumber': 'urn:uuid:' + str(uuid.uuid4()),
           'metadata': {'timestamp': datetime.now(timezone.utc).isoformat(),
                        'component': {'type': 'application', 'name': 'panopticon', 'version': version,
                                      'bom-ref': project_ref},
                        'properties': [{'name': 'panopticon:source-commit', 'value': commit},
                                       {'name': 'panopticon:scope', 'value': 'Python runtime lock; conditional packages included; OS packages excluded'}]},
           'components': components,
           'dependencies': [{'ref': project_ref, 'dependsOn': [c['bom-ref'] for c in components]}]}
    (output / 'sbom.cdx.json').write_text(json.dumps(bom, ensure_ascii=False, indent=2) + '\n')
    (output / 'requirements.lock').write_bytes(lock)
    manifest = {'version': version, 'tag': tag, 'source_commit': commit,
                'runtime_lock_sha256': hashlib.sha256(lock).hexdigest(),
                'source_archive_sha256': hashlib.sha256((output / archive_name).read_bytes()).hexdigest(),
                'dependency_inventory_scope': 'Python runtime lock including conditional packages; no OS inventory'}
    (output / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
    checksums = ''.join(hashlib.sha256(file.read_bytes()).hexdigest() + '  ' + file.name + '\n'
                        for file in sorted(output.iterdir()))
    (output / 'SHA256SUMS').write_text(checksums)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    build(Path.cwd(), arguments.output.resolve(), arguments.tag)
