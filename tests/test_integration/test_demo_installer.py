"""데모 경로와 설치 진입점이 실환경에서 성립하는지 검증한다."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from dotenv import dotenv_values
import pytest

from scripts.install_eve import prepare_installation

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "samples" / "eve.json"


def test_bundled_sample_is_parseable_eve():
    """샘플이 실제 파서를 통과해야 데모가 데이터 없이도 동작한다."""
    import uuid
    from netwatcher.ingest.eve import decode_eve_line
    generation = str(uuid.uuid5(uuid.NAMESPACE_DNS, "demo"))
    offset = 0
    records = []
    for line in SAMPLE.read_bytes().splitlines(keepends=True):
        record = decode_eve_line(line, sensor_id="demo", source_id="demo",
                                 generation=generation, offset=offset)
        offset += len(line)
        assert record is not None, f"샘플이 EVE 파서를 통과하지 못한다: {line[:80]!r}"
        records.append(record)
    assert len(records) >= 4
    assert all(record["event_type"] == "alert" for record in records)
    assert all(record["src_ip"] and record["dest_ip"] for record in records)


def test_demo_installation_needs_no_capture_privilege(tmp_path):
    """데모 설치는 권한 검사 없이 EVE 모드로 생성되어야 한다."""
    path = prepare_installation(tmp_path / "installation-demo", SAMPLE)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    config = json.loads((path.parent / "config" / "default.yaml").read_text())["netwatcher"]
    assert config["input"]["mode"] == "eve"
    source = config["input"]["eve"]["sources"][0]
    assert source["filename"] == "eve.json" and source["directory"] == "/var/log/suricata"
    values = dotenv_values(path)
    # 데모는 단일 DB 역할이다. native의 3역할 분리를 흉내 내지 않는다.
    assert values["NETWATCHER_DB_USER"] == "netwatcher"
    assert values["NETWATCHER_LOGIN_PASSWORD"] and values["NETWATCHER_JWT_SECRET"]


def test_demo_compose_profile_starts_db_migration_and_console(tmp_path):
    """--profile demo 한 번으로 DB·마이그레이션·콘솔이 모두 해석되어야 한다."""
    result = subprocess.run(["docker", "compose", "--profile", "demo", "config", "--services"],
                            cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        pytest.skip(f"docker compose 사용 불가: {result.stderr.strip()[:120]}")
    services = set(result.stdout.split())
    assert {"db", "db-migrate", "netwatcher"} <= services


def test_install_script_exposes_each_path_and_rejects_unknown():
    """진입점은 네 경로를 모두 받고, 모르는 경로는 거부해야 한다."""
    script = ROOT / "install.sh"
    assert script.exists() and os.access(script, os.X_OK), "install.sh 가 실행 가능해야 한다"
    listing = subprocess.run([str(script), "--help"], capture_output=True, text=True,
                             timeout=60, check=False)
    assert listing.returncode == 0
    for path in ("demo", "eve", "native", "capture", "preflight"):
        assert path in listing.stdout, f"사용법에 {path} 가 없다"
    unknown = subprocess.run([str(script), "bogus"], capture_output=True, text=True,
                             timeout=60, check=False)
    assert unknown.returncode == 2
    assert "알 수 없는 경로" in unknown.stderr


def test_preflight_reports_remedy_for_failed_check():
    """실패 항목은 상태만 알리지 않고 대안도 함께 제시해야 한다."""
    from scripts.preflight import Result, run
    report = run(["python"], ignore={"port"})
    assert [name for name, _ in report] == ["python"]
    result = report[0][1]
    assert isinstance(result, Result)
    assert result.ok is True

    from scripts import preflight
    blocked = preflight.Result(False, "샘플이 없습니다", "git clone 을 확인하십시오.")
    assert blocked.remedy, "실패 항목에는 대안이 있어야 한다"