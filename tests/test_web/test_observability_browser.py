"""관측 탭·에이전트 탭·기능 상태 안내의 브라우저 검증."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


def test_observability_and_agents_browser():
    driver = Path(__file__).resolve().parents[1] / "browser" / "observability.cjs"
    playwright = os.environ.get("PANOPTICON_PLAYWRIGHT_CORE") or driver.parent / "node_modules" / "playwright-core"
    chrome = os.environ.get("PANOPTICON_CHROME") or shutil.which("google-chrome")
    if not shutil.which("node") or not Path(playwright).exists() or not chrome:
        pytest.skip("Provide Node, Chrome and playwright-core")
    result = subprocess.run(
        ["node", str(driver)], capture_output=True, text=True, timeout=120,
        env={**os.environ, "PANOPTICON_PLAYWRIGHT_CORE": str(playwright), "PANOPTICON_CHROME": chrome},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "observability browser checks passed" in result.stdout
