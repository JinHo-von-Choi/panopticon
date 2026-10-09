#!/usr/bin/env bash
# Panopticon 설치 진입점.
#
# 이 스크립트는 판단하고 호출만 한다. 설정·자격증명 생성의 실제 일은
# scripts/install_eve.py 와 scripts/install_native.py 가 이미 하고 있으므로
# 여기서 복제하지 않는다. 로직을 복제하면 두 설치기가 서로 어긋난다.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
OUTPUT="${PANOPTICON_INSTALL_DIR:-$ROOT/installation-demo}"

usage() {
  cat <<'TEXT'
사용법: ./install.sh <경로>

  demo       Suricata 없이 저장소 샘플 EVE 로그로 화면까지 (권한 불필요)
  eve        실제 Suricata EVE 로그를 읽는 무권한 콘솔
  native     센서와 콘솔을 분리 배포 (권한 분리 · 패킷 캡처)
  capture    원시 패킷을 직접 캡처 (루트/CAP_NET_RAW 필요)
  preflight  설치 없이 선행 조건만 확인

환경변수:
  PANOPTICON_INSTALL_DIR   설치 디렉터리 (기본: ./installation-demo)
  PANOPTICON_EVE_FILE      eve 경로에서 사용할 EVE 로그 (기본: samples/eve.json)
  PYTHON                   사용할 파이썬 (기본: python3)
TEXT
}

preflight() { "$PYTHON" "$ROOT/scripts/preflight.py" "$1"; }

up_demo() {
  echo "==> 선행 조건 확인"
  preflight demo
  echo
  echo "==> 설치 설정 생성 (자격증명·DB·로그인 생성)"
  "$PYTHON" "$ROOT/scripts/install_eve.py" \
    --eve-file "${PANOPTICON_EVE_FILE:-$ROOT/samples/eve.json}" \
    --output "$OUTPUT"
  echo
  echo "==> 컨테이너 기동 (DB + 마이그레이션 + 콘솔)"
  docker compose --env-file "$OUTPUT/.env" --profile demo up -d --build
  echo
  echo "==> http://127.0.0.1:38585"
  echo "    로그인: $(grep '^NETWATCHER_LOGIN_USERNAME=' "$OUTPUT/.env" | cut -d= -f2- | tr -d "'")"
  echo "    비밀번호: $(grep '^NETWATCHER_LOGIN_PASSWORD=' "$OUTPUT/.env" | cut -d= -f2- | tr -d "'")"
  echo
  echo "정지: docker compose --env-file $OUTPUT/.env --profile demo down     제거: 같은 명령에 -v"
}

case "${1:-}" in
  demo)
    up_demo
    ;;
  eve)
    if [ -z "${PANOPTICON_EVE_FILE:-}" ]; then
      echo "eve 경로에는 실제 로그가 필요합니다: PANOPTICON_EVE_FILE=/var/log/suricata/eve.json ./install.sh eve" >&2
      exit 2
    fi
    preflight eve
    "$PYTHON" "$ROOT/scripts/install_eve.py" --eve-file "$PANOPTICON_EVE_FILE" --output "$OUTPUT"
    docker compose --env-file "$OUTPUT/.env" --profile db --profile migrate up -d --build
    echo "http://127.0.0.1:38585  (자격증명: $OUTPUT/.env)"
    ;;
  native)
    # 권한 분리는 native 설치기가 이미 강제한다. 여기서는 선행 조건만 본다.
    preflight native
    exec "$PYTHON" "$ROOT/scripts/install_native.py" --interface "${PANOPTICON_INTERFACE:-eth0}" --output "$OUTPUT"
    ;;
  capture)
    preflight capture
    ;;
  preflight)
    preflight "${2:-demo}"
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    echo "알 수 없는 경로: $1" >&2
    usage >&2
    exit 2
    ;;
esac