# 릴리스 검증

릴리스 파일을 실행하기 전 소스 커밋, 파일 해시, 빌드 증명을 차례대로 대조해야 합니다. 작업에는 GitHub CLI 도구인 `gh attestation verify`와 Python 3.12 이상의 환경이 필요하며, 증명 파일이 누락된 릴리스는 이 절차로 검증할 수 없습니다.

## 다운로드와 빌드 증명 확인

검증 대상 태그와 예상 소스 커밋을 먼저 지정한 뒤 빈 디렉터리에서 명령을 실행합니다. `COMMIT` 변수에는 해당 태그가 직접 가리키는 40자리 Git 커밋 해시를 입력합니다.

```bash
REPOSITORY=JinHo-von-Choi/panopticon
TAG=vX.Y.Z
COMMIT=검증할_40자리_커밋
gh release download "$TAG" --repo "$REPOSITORY" --dir .

for artifact in release.json images.json requirements.lock sbom.cdx.json SHA256SUMS panopticon-*.tar.gz panopticon-*.oci.tar; do
  gh attestation verify "$artifact" \
    --bundle provenance.sigstore.json \
    --repo "$REPOSITORY" \
    --signer-workflow "$REPOSITORY/.github/workflows/release.yml" \
    --source-digest "$COMMIT" || exit 1
done
```

오류가 발생하면 즉시 설치를 중단해야 합니다. 태그 이름이나 체크섬 파일만 확인하고 빌드 주체까지 검증되었다고 속단해서는 안 됩니다.

## 내용과 의존성 목록 확인

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

`sbom.cdx.json` 파일은 Python 운영 의존성 패키지들의 고정 목록입니다. 플랫폼별 조건부 패키지도 들어 있지만 OS 단위 패키지나 컨테이너 전체 목록까지는 담지 않으며, 빌드 증명 역시 배포 산출물과 원본 소스의 일치를 입증하는 수단일 뿐 보안 취약점 점검을 대신해 주지는 못합니다.

검증을 마친 소스 압축 파일은 압축을 푼 뒤 [설치 안내](INSTALL.md) 문서에 따라 설치를 진행합니다. 기존 환경을 갱신하는 상황이라면 작업 전에 데이터를 백업하고 복구 절차도 함께 검토해 두어야 합니다.