"""테마·접근성 화면 계약을 실제 Chromium 으로 확인한다.

드라이버는 자체 정적 서버를 띄우고 API 실패·복구 시나리오, 두 테마의
명도 대비, 세션 종료 후 초기화, CSS 파싱을 확인한다.
"""

import asyncio
import os
from pathlib import Path
import shutil

import pytest

DRIVER = Path(__file__).resolve().parent / "browser" / "theme-scaffolding.cjs"


@pytest.mark.asyncio
async def test_theme_scaffolding_contrast_and_session_reset():
    if not shutil.which("node") or not os.environ.get("PANOPTICON_PLAYWRIGHT_CORE"):
        pytest.skip("Node와 PANOPTICON_PLAYWRIGHT_CORE 가 필요하다")
    if not shutil.which("google-chrome") and not os.environ.get("PANOPTICON_CHROME"):
        pytest.skip("Chrome 이 필요하다")
    if not DRIVER.exists():
        pytest.skip(f"드라이버 없음: {DRIVER}")

    child = await asyncio.create_subprocess_exec(
        "node", str(DRIVER),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        async with asyncio.timeout(120):
            stdout, stderr = await child.communicate()
    except asyncio.TimeoutError:
        child.kill()
        await child.wait()
        raise
    assert child.returncode == 0, stderr.decode()[-4000:]
    assert b"PASS:" in stdout, stdout.decode()[-2000:]
