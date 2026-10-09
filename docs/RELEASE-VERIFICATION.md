# 릴리스 검증

릴리스 파일을 설치하기 전에 소스 커밋, 파일 해시, 빌드 증명을 대조합니다. 하나라도 실패하면 설치하지 않습니다.

```mermaid
flowchart LR
    D[릴리스 다운로드] --> A[빌드 증명 검증<br/>gh attestation]
    A --> H[체크섬 확인<br/>SHA256SUMS]
    H --> M[release.json의<br/>태그·커밋 대조]
    M --> S[의존성 목록 증명<br/>SBOM]
    S --> I[설치]
```

필요한 것: `gh attestation verify`를 지원하는 GitHub CLI, Python 3.12 이상. 증명 파일이 없는 릴리스는 이 절차로 검증할 수 없습니다.

## 1. 다운로드와 빌드 증명

빈 디렉터리에서 실행합니다. `COMMIT`에는 태그가 가리키는 40자리 커밋 해시를 넣습니다.

```bash
REPOSITORY=JinHo-von-Choi/panopticon
TAG=vX.Y.Z
COMMIT=<40자리 커밋>
gh release download "$TAG" --repo "$REPOSITORY" --dir .

for artifact in release.json images.json requirements.lock sbom.cdx.json SHA256SUMS panopticon-*.tar.gz panopticon-*.oci.tar; do
  gh attestation verify "$artifact" \
    --bundle provenance.sigstore.json \
    --repo "$REPOSITORY" \
    --signer-workflow "$REPOSITORY/.github/workflows/release.yml" \
    --source-digest "$COMMIT" || exit 1
done
```

태그 이름이나 체크섬만 맞는다고 빌드 주체까지 확인된 것은 아닙니다.

## 2. 내용과 의존성 목록

```bash
sha256sum --check SHA256SUMS

python - "$TAG" "$COMMIT" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path('release.json').read_text())
if manifest['tag'] != sys.argv[1] or manifest['source_commit'] != sys.argv[2]:
    raise SystemExit('릴리스 태그 또는 소스 커밋이 다릅니다')
print('버전:', manifest['version'])
print('소스 커밋:', manifest['source_commit'])
PY

for archive in panopticon-*.tar.gz; do
  gh attestation verify "$archive" \
    --bundle dependencies.sigstore.json \
    --repo "$REPOSITORY" \
    --signer-workflow "$REPOSITORY/.github/workflows/release.yml" \
    --source-digest "$COMMIT" \
    --predicate-type https://cyclonedx.org/bom || exit 1
done
```

## 증명이 보장하는 범위

| 파일 | 보장하는 것 | 보장하지 않는 것 |
| --- | --- | --- |
| `provenance.sigstore.json` | 산출물이 해당 커밋에서 공식 워크플로로 빌드됨 | 취약점 없음 |
| `sbom.cdx.json` | Python 운영 의존성의 고정 목록 | OS 패키지, 컨테이너 전체 구성 |

검증한 소스 압축 파일을 풀고 [설치 가이드](INSTALL.md)를 따릅니다. 기존 설치를 갱신할 때는 먼저 백업합니다.
