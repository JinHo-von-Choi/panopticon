#!/bin/bash
# NetWatcher systemd service 설치 스크립트
# 실행: sudo bash install-service.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/netwatcher.service"
DEST="/etc/systemd/system/netwatcher.service"

if [ "$EUID" -ne 0 ]; then
    echo "root 권한이 필요합니다: sudo bash $0"
    exit 1
fi

# 기존 프로세스 정리
echo "[1/5] 기존 netwatcher 프로세스 종료..."
pkill -f "python.*-m netwatcher" 2>/dev/null || true
sleep 2

# 서비스 파일 복사
echo "[2/5] 서비스 파일 설치..."
cp "$SERVICE_FILE" "$DEST"

# systemd 리로드
echo "[3/5] systemd 리로드..."
systemctl daemon-reload

# 서비스 활성화 + 시작
echo "[4/5] 서비스 활성화 및 시작..."
systemctl enable netwatcher
systemctl start netwatcher

# 상태 확인
echo "[5/5] 서비스 상태 확인..."
sleep 2
systemctl status netwatcher --no-pager

echo ""
echo "=== 설치 완료 ==="
echo "관리 명령어:"
echo "  sudo systemctl status netwatcher    # 상태 확인"
echo "  sudo systemctl restart netwatcher   # 재시작"
echo "  sudo systemctl stop netwatcher      # 중지"
echo "  sudo journalctl -u netwatcher -f    # 로그 실시간 확인"
