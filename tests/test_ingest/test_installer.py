"""신규 설치 설정의 권한·자격증명·실패 경계를 검증한다."""

import json
import stat
import subprocess
import sys

import pytest
from dotenv import dotenv_values

from scripts.install_eve import prepare_installation


def source(tmp_path):
    directory = tmp_path / "logs"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    path = directory / "eve.json"
    path.write_text(json.dumps({"timestamp": "2026-10-08T01:00:00Z", "event_type": "flow", "flow": {}}) + "\n")
    path.chmod(0o644)
    return path


def test_preparation_creates_private_credentials_without_changing_source(tmp_path):
    path = source(tmp_path)
    original = path.read_bytes()
    destination = tmp_path / "new installation"
    environment = prepare_installation(destination, path)
    assert stat.S_IMODE(environment.stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    values = dotenv_values(environment)
    assert values["NETWATCHER_DB_HOST"] == "db"
    assert values["NETWATCHER_LOGIN_ENABLED"] == "true"
    assert len(values["NETWATCHER_DB_PASSWORD"]) == 64
    assert values["NETWATCHER_DB_PASSWORD"] != values["NETWATCHER_JWT_SECRET"]
    other = dotenv_values(prepare_installation(tmp_path / "other installation", path))
    assert values["COMPOSE_PROJECT_NAME"] != other["COMPOSE_PROJECT_NAME"]
    config = json.loads((destination / "config/default.yaml").read_text())
    assert config["netwatcher"]["input"]["mode"] == "eve"
    assert values["NETWATCHER_LOGIN_PASSWORD"] not in json.dumps(config)
    assert path.read_bytes() == original
    with pytest.raises(ValueError):
        prepare_installation(destination, path)
    assert dotenv_values(environment) == values


def test_preflight_rejects_container_unreadable_source(tmp_path):
    path = source(tmp_path)
    path.chmod(0o600)
    with pytest.raises(ValueError, match="읽기 권한"):
        prepare_installation(tmp_path / "installation", path)
    assert not (tmp_path / "installation").exists()


def test_preflight_rejects_symlink_and_does_not_expose_invalid_content(tmp_path):
    path = source(tmp_path)
    link = path.parent / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        prepare_installation(tmp_path / "installation", link)
    path.write_text('{"timestamp":"private-data","event_type":"flow"}\n')
    with pytest.raises(ValueError) as error:
        prepare_installation(tmp_path / "installation", path)
    assert "private-data" not in str(error.value)


def test_cli_does_not_print_credentials(tmp_path):
    path = source(tmp_path)
    destination = tmp_path / "installation"
    result = subprocess.run([sys.executable, "-I", "-S", "scripts/install_eve.py", "--eve-file", str(path), "--output", str(destination)],
                            capture_output=True, text=True, check=True)
    values = dotenv_values(destination / ".env")
    for key in ("NETWATCHER_LOGIN_PASSWORD", "NETWATCHER_DB_PASSWORD", "NETWATCHER_JWT_SECRET"):
        assert values[key] not in result.stdout + result.stderr


def test_generated_paths_are_resolved_by_real_compose(tmp_path):
    import os
    import shutil

    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is required for deployment configuration verification")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True)
    if probe.returncode:
        pytest.skip("Docker Compose is not installed")
    path = source(tmp_path)
    destination = tmp_path / "installation $ literal 'quote"
    environment = prepare_installation(destination, path)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("NETWATCHER_", "PANOPTICON_"))}
    result = subprocess.run(["docker", "compose", "--env-file", str(environment), "-f", "docker-compose.yml",
                             "--profile", "db", "config", "--no-env-resolution", "--format", "json"],
                            env=env, capture_output=True, text=True, check=True)
    model = json.loads(result.stdout)
    app = model["services"]["netwatcher"]
    # Compose의 재사용 가능한 출력은 리터럴 $를 $$로 이스케이프한다.
    assert next(volume for volume in app["volumes"] if volume["target"] == "/app/config")["source"] == str(destination / "config").replace("$", "$$")
    assert app["env_file"][0]["path"] == str(environment).replace("$", "$$")
    assert app["environment"]["NETWATCHER_DB_HOST"] == "db"
    assert model["services"]["db"]["ports"][0]["published"] == dotenv_values(environment)["PANOPTICON_DB_PUBLISH_PORT"]
