"""MITRE matrix browser integration checks."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


def test_mitre_matrix_browser():
    driver = Path(__file__).resolve().parents[1] / "browser" / "mitre-matrix.cjs"
    playwright = os.environ.get("PANOPTICON_PLAYWRIGHT_CORE") or driver.parent / "node_modules" / "playwright-core"
    chrome = shutil.which("google-chrome")
    if not shutil.which("node") or not Path(playwright).exists() or not chrome:
        pytest.skip("Provide Node, Chrome and playwright-core")
    result = subprocess.run(
        ["node", str(driver)], capture_output=True, text=True, timeout=90,
        env={**os.environ, "PANOPTICON_PLAYWRIGHT_CORE": str(playwright), "PANOPTICON_CHROME": chrome},
    )
    assert result.returncode == 0, result.stdout + result.stderr
