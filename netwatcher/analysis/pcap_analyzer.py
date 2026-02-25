"""tshark를 통한 PCAP 파일 추출."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("netwatcher.analysis.pcap_analyzer")


class PcapAnalyzer:
    """tshark를 사용하여 PCAP 캡처에서 파일을 추출한다."""

    def __init__(
        self,
        output_dir: str = "data/extracted",
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
    ) -> None:
        """PCAP 분석기를 초기화한다. 출력 디렉토리와 최대 파일 크기를 설정한다."""
        self._output_dir = Path(output_dir)
        self._max_file_size = max_file_size

    def is_available(self) -> bool:
        """tshark가 설치되어 있는지 확인한다."""
        return shutil.which("tshark") is not None

    async def extract_files(self, pcap_path: str) -> list[dict[str, Any]]:
        """tshark --export-objects를 사용하여 PCAP에서 파일을 추출한다.

        filename, path, size, sha256 키를 포함하는 dict 목록을 반환한다.
        """
        if not self.is_available():
            logger.warning("tshark not installed — cannot extract files")
            return []

        pcap = Path(pcap_path)
        if not pcap.exists():
            logger.error("PCAP file not found: %s", pcap_path)
            return []

        export_dir = self._output_dir / f"export_{int(time.time())}_{id(self)}"
        export_dir.mkdir(parents=True, exist_ok=True)

        try:
            # asyncio.create_subprocess_exec 사용 (쉘 미사용)
            proc = await asyncio.create_subprocess_exec(
                "tshark", "-r", str(pcap), "--export-objects", f"http,{export_dir}",
                "-Q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error("tshark export failed: %s", stderr.decode(errors="replace"))
                return []
        except Exception:
            logger.exception("Failed to run tshark for file extraction")
            return []

        results: list[dict[str, Any]] = []
        for f in sorted(export_dir.iterdir()):
            if not f.is_file():
                continue
            size = f.stat().st_size
            if size > self._max_file_size:
                logger.warning("Extracted file too large (%d bytes), skipping: %s", size, f.name)
                continue
            sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
            results.append({
                "filename": f.name,
                "path": str(f),
                "size": size,
                "sha256": sha256,
            })

        logger.info("Extracted %d files from %s", len(results), pcap_path)
        return results

    async def extract_files_imf(self, pcap_path: str) -> list[dict[str, Any]]:
        """PCAP에서 이메일 객체(IMF)를 추출한다."""
        if not self.is_available():
            return []

        pcap = Path(pcap_path)
        if not pcap.exists():
            return []

        export_dir = self._output_dir / f"imf_{int(time.time())}_{id(self)}"
        export_dir.mkdir(parents=True, exist_ok=True)

        try:
            proc = await asyncio.create_subprocess_exec(
                "tshark", "-r", str(pcap), "--export-objects", f"imf,{export_dir}",
                "-Q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        except Exception:
            logger.exception("tshark IMF export failed")
            return []

        results: list[dict[str, Any]] = []
        for f in sorted(export_dir.iterdir()):
            if not f.is_file():
                continue
            size = f.stat().st_size
            if size > self._max_file_size:
                continue
            sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
            results.append({
                "filename": f.name,
                "path": str(f),
                "size": size,
                "sha256": sha256,
            })
        return results
