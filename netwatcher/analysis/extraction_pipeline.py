"""파일 추출 비동기 오케스트레이터: 카빙 -> YARA 스캔 -> 해시 조회 -> 알림 생성.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Callable, Awaitable

from netwatcher.analysis.file_carver import ExtractedFile
from netwatcher.analysis.hash_lookup import HashLookupClient
from netwatcher.analysis.yara_scanner import YaraScanner

logger = logging.getLogger("netwatcher.analysis.extraction_pipeline")


class ExtractionPipeline:
    """추출된 파일을 YARA 스캔 및 해시 조회로 분석하는 비동기 파이프라인."""

    def __init__(
        self,
        yara_scanner: YaraScanner,
        hash_client: HashLookupClient,
        alert_callback: Callable[[dict[str, Any]], Awaitable[None]] | Callable[[dict[str, Any]], None],
        output_dir: str = "data/extracted",
        max_queue_size: int = 1000,
    ) -> None:
        self._yara       = yara_scanner
        self._hash_client = hash_client
        self._alert_cb   = alert_callback
        self._output_dir = Path(output_dir)
        self._queue: asyncio.Queue[ExtractedFile] = asyncio.Queue(maxsize=max_queue_size)
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._processed_count = 0

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """컨슈머 루프를 시작한다."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consumer_loop())
        logger.info("ExtractionPipeline started")

    async def submit(self, extracted_file: ExtractedFile) -> None:
        """추출된 파일을 분석 큐에 제출한다. 큐가 가득 차면 가장 오래된 항목을 제거한다."""
        if not self._running:
            return
        if self._queue.full():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await self._queue.put(extracted_file)

    async def stop(self) -> None:
        """파이프라인을 중지한다."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._hash_client.close()
        logger.info("ExtractionPipeline stopped (processed %d files)", self._processed_count)

    @property
    def processed_count(self) -> int:
        """처리된 파일 수를 반환한다."""
        return self._processed_count

    @property
    def queue_size(self) -> int:
        """현재 대기 중인 파일 수를 반환한다."""
        return self._queue.qsize()

    # ------------------------------------------------------------------
    # 컨슈머 루프
    # ------------------------------------------------------------------

    async def _consumer_loop(self) -> None:
        """큐에서 파일을 꺼내 분석한다."""
        while self._running:
            try:
                ef = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            try:
                await self._process_file(ef)
                self._processed_count += 1
            except Exception:
                logger.exception("Failed to process extracted file: %s", ef.filename)

    async def _process_file(self, ef: ExtractedFile) -> None:
        """단일 파일을 분석한다: YARA -> 해시 조회 -> 알림 생성."""
        findings: list[str] = []
        severity = "INFO"

        # 1. YARA 스캔 (CPU-bound이므로 to_thread 사용)
        yara_matches: list[dict[str, Any]] = []
        if self._yara.is_available():
            yara_matches = await asyncio.to_thread(self._yara.scan_bytes, ef.data)
            if yara_matches:
                rule_names = [m["rule"] for m in yara_matches]
                findings.append(f"YARA rules matched: {', '.join(rule_names)}")
                severity = "WARNING"
                logger.info(
                    "YARA match for %s (sha256=%s): %s",
                    ef.filename, ef.sha256, rule_names,
                )

        # 2. 해시 조회 (async)
        hash_result = None
        if self._hash_client.available:
            hash_result = await self._hash_client.lookup(ef.sha256)
            if hash_result.known_malicious:
                findings.append(
                    f"Hash known malicious via {hash_result.source}"
                    f" (VT: {hash_result.vt_positives}/{hash_result.vt_total})"
                )
                if hash_result.malware_family:
                    findings.append(f"Malware family: {hash_result.malware_family}")
                severity = "CRITICAL"
                logger.warning(
                    "Malicious file detected: %s (sha256=%s, family=%s)",
                    ef.filename, ef.sha256, hash_result.malware_family,
                )

        # 3. 의심스러운 파일이면 디스크에 저장
        if findings:
            saved_path = await self._save_file(ef)
            findings.append(f"File saved to: {saved_path}")

        # 4. 알림 생성
        if findings:
            alert_data = {
                "engine": "file_extraction",
                "severity": severity,
                "title": f"Suspicious file detected: {ef.filename}",
                "description": "; ".join(findings),
                "source_ip": ef.source_ip,
                "dest_ip": ef.dest_ip,
                "metadata": {
                    "filename": ef.filename,
                    "content_type": ef.content_type,
                    "file_size": len(ef.data),
                    "md5": ef.md5,
                    "sha256": ef.sha256,
                    "protocol": ef.protocol,
                    "yara_matches": [m["rule"] for m in yara_matches],
                    "vt_positives": hash_result.vt_positives if hash_result else 0,
                    "vt_total": hash_result.vt_total if hash_result else 0,
                    "malware_family": hash_result.malware_family if hash_result else "",
                },
            }
            result = self._alert_cb(alert_data)
            if asyncio.iscoroutine(result):
                await result

    async def _save_file(self, ef: ExtractedFile) -> str:
        """의심스러운 파일을 디스크에 저장한다."""
        save_dir = self._output_dir / ef.protocol
        await asyncio.to_thread(os.makedirs, str(save_dir), exist_ok=True)

        safe_name = ef.sha256[:16] + "_" + ef.filename.replace("/", "_").replace("\\", "_")
        file_path = save_dir / safe_name

        await asyncio.to_thread(file_path.write_bytes, ef.data)
        logger.info("Saved suspicious file: %s", file_path)
        return str(file_path)
