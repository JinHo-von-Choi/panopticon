"""설치 전 선행 조건을 확인하고, 실패하면 원인과 대안을 함께 알린다.

각 검사는 계측 가능한 하나의 사실만 판정한다. 설치 도구 자체를 복제하지
않고, 여기서 실패한 항목만 다음 단계가 되돌아갈 이유를 만들지 않는다.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB_PORT = 38585


class Result:
    def __init__(self, ok: bool, message: str, remedy: str = "") -> None:
        self.ok, self.message, self.remedy = ok, message, remedy


def check_python() -> Result:
    if sys.version_info >= (3, 12):
        return Result(True, f"Python {sys.version_info.major}.{sys.version_info.minor}")
    return Result(False, f"Python {sys.version_info.major}.{sys.version_info.minor} — 3.12 이상이 필요합니다",
                  "python3.12 이상이 설치된 환경에서 다시 실행하십시오.")


def check_docker() -> Result:
    if not shutil.which("docker"):
        return Result(False, "docker 를 찾을 수 없습니다", "Docker Engine 을 설치하십시오.")
    if not shutil.which("docker-compose") and not _compose_v2():
        return Result(False, "docker compose 플러그인이 없습니다", "'docker compose version' 으로 확인하십시오.")
    return Result(True, "docker 사용 가능")


def _compose_v2() -> bool:
    import subprocess
    try:
        completed = subprocess.run(["docker", "compose", "version"],
                                   capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def check_port_free(port: int) -> Result:
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return Result(False, f"포트 {port} 이(가) 이미 사용 중입니다",
                          "기존 서비스를 끝내거나 config의 web.port 를 바꾸십시오.")
    return Result(True, f"포트 {port} 사용 가능")


def check_config_writable() -> Result:
    """콘솔이 설정을 되돌려 써야 하는 경로다(엔진 설정 저장)."""
    config = ROOT / "config" / "default.yaml"
    if not config.exists():
        return Result(False, f"{config} 이(가) 없습니다", "저장소 루트에서 실행하십시오.")
    if not os.access(config, os.W_OK):
        return Result(False, f"{config} 에 쓸 수 없습니다 (소유자 {config.stat().st_uid})",
                      f"sudo chown $(id -u):$(id -g) {config} 를 실행하십시오.")
    return Result(True, "설정 파일 쓰기 가능")


def check_eve_sample() -> Result:
    """데모 경로가 Suricata 없이 동작하려면 샘플이 읽기 가능해야 한다."""
    sample = ROOT / "samples" / "eve.json"
    if not sample.exists():
        return Result(False, "samples/eve.json 이(가) 없습니다 (데모 경로 필요)",
                      "git clone 이 완전한 상태인지 확인하십시오.")
    mode = sample.stat().st_mode
    if not mode & stat.S_IROTH and mode & stat.S_IRGRP == 0:
        return Result(False, "samples/eve.json 을 컨테이너 그룹이 읽을 수 없습니다",
                      "chmod o+r samples/eve.json 또는 컨테이너 GID 를 맞추십시오.")
    return Result(True, "샘플 EVE 로그 사용 가능 (Suricata 불필요)")


def check_capture_privilege() -> Result:
    """원시 패킷 캡처 경로 전용 검사. 데모/EVE 경로에서는 무시된다."""
    try:
        import socket as socket_module
        raw = socket_module.socket(socket_module.AF_PACKET, socket_module.SOCK_RAW, 3)
    except (AttributeError, PermissionError, OSError):
        return Result(False, "패킷 캡처 권한이 없습니다 (AF_NETLINK/CAP_NET_RAW)",
                      "EVE 모드를 사용하거나 sudo 로 실행하십시오. 데모는 권한이 필요 없습니다.")
    raw.close()
    return Result(True, "패킷 캡처 권한 보유")


CHECKS = {
    "python": check_python,
    "docker": check_docker,
    "port": check_port_free,
    "config": check_config_writable,
    "sample": check_eve_sample,
    "capture": check_capture_privilege,
}


def run(names, *, ignore=(), port: int = WEB_PORT) -> list[tuple[str, Result]]:
    report = []
    for name in names:
        if name in ignore:
            report.append((name, Result(True, "건너뜀")))
            continue
        check = CHECKS[name]
        report.append((name, check() if name != "port" else check(port)))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="설치 전 선행 조건을 확인합니다.")
    parser.add_argument("mode", choices=["demo", "eve", "native", "capture"], nargs="?", default="demo")
    parser.add_argument("--port", type=int, default=WEB_PORT)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()

    ignore = set()
    if arguments.mode == "demo":
        # 데모는 무권한 EVE 경로다. 캡처 권한을 요구하지 않는다.
        ignore = {"capture"}
    results = run(list(CHECKS), ignore=ignore, port=arguments.port)
    failed = [(name, result) for name, result in results if not result.ok]

    if arguments.json:
        import json
        print(json.dumps({name: {"ok": r.ok, "message": r.message, "remedy": r.remedy}
                          for name, r in results}, ensure_ascii=False, indent=2))
    else:
        for name, result in results:
            mark = "OK  " if result.ok else "FAIL"
            print(f"[{mark}] {name:8s} {result.message}")
            if result.remedy and not result.ok:
                print(f"         → {result.remedy}")
    if failed:
        print(f"\n{len(failed)}개 항목이 준비되지 않았습니다. 위 대안을 먼저 처리하십시오.")
        return 1
    print("\n모든 선행 조건이 충족되었습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())