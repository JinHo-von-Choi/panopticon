"""Tests for ExtractionPipeline.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netwatcher.analysis.extraction_pipeline import ExtractionPipeline
from netwatcher.analysis.file_carver import ExtractedFile
from netwatcher.analysis.hash_lookup import HashLookupClient, HashResult
from netwatcher.analysis.yara_scanner import YaraScanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_extracted_file(data: bytes = b"\x00" * 256, filename: str = "test.bin") -> ExtractedFile:
    return ExtractedFile(
        data=data,
        filename=filename,
        content_type="application/octet-stream",
        source_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        timestamp=time.time(),
        protocol="http",
    )


@pytest.fixture
def mock_yara():
    scanner = MagicMock(spec=YaraScanner)
    scanner.is_available.return_value = True
    scanner.scan_bytes.return_value = []
    return scanner


@pytest.fixture
def mock_hash_client():
    client = MagicMock(spec=HashLookupClient)
    client.available = True
    client.lookup = AsyncMock(return_value=HashResult(
        sha256="a" * 64,
        known_malicious=False,
        source="cache",
    ))
    client.close = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# 테스트
# ---------------------------------------------------------------------------

class TestExtractionPipeline:
    """ExtractionPipeline 통합 테스트."""

    @pytest.mark.asyncio
    async def test_clean_file_no_alert(self, mock_yara, mock_hash_client, tmp_path):
        """YARA 매치와 해시 매치 모두 없으면 알림이 생성되지 않는다."""
        alerts = []

        async def alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.submit(_make_extracted_file())
        # 처리 대기
        await asyncio.sleep(0.3)
        await pipeline.stop()

        assert len(alerts) == 0
        assert pipeline.processed_count == 1

    @pytest.mark.asyncio
    async def test_yara_match_generates_alert(self, mock_yara, mock_hash_client, tmp_path):
        """YARA 매치 시 알림이 생성된다."""
        mock_yara.scan_bytes.return_value = [
            {"rule": "Malware_Generic", "tags": ["malware"], "meta": {}},
        ]

        alerts = []

        async def alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.submit(_make_extracted_file())
        await asyncio.sleep(0.3)
        await pipeline.stop()

        assert len(alerts) == 1
        assert "YARA" in alerts[0]["description"]
        assert alerts[0]["severity"] == "WARNING"

    @pytest.mark.asyncio
    async def test_hash_match_generates_critical_alert(self, mock_yara, mock_hash_client, tmp_path):
        """해시 매치 시 CRITICAL 알림이 생성된다."""
        mock_hash_client.lookup = AsyncMock(return_value=HashResult(
            sha256="a" * 64,
            known_malicious=True,
            vt_positives=15,
            vt_total=60,
            malware_family="Emotet",
            source="virustotal",
        ))

        alerts = []

        async def alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.submit(_make_extracted_file())
        await asyncio.sleep(0.3)
        await pipeline.stop()

        assert len(alerts) == 1
        assert alerts[0]["severity"] == "CRITICAL"
        assert "malicious" in alerts[0]["description"].lower()
        assert alerts[0]["metadata"]["malware_family"] == "Emotet"

    @pytest.mark.asyncio
    async def test_both_yara_and_hash_match(self, mock_yara, mock_hash_client, tmp_path):
        """YARA와 해시 모두 매치 시 CRITICAL 알림이 생성된다."""
        mock_yara.scan_bytes.return_value = [
            {"rule": "Suspicious_PE", "tags": [], "meta": {}},
        ]
        mock_hash_client.lookup = AsyncMock(return_value=HashResult(
            sha256="b" * 64,
            known_malicious=True,
            vt_positives=30,
            vt_total=70,
            malware_family="Cobalt Strike",
            source="virustotal",
        ))

        alerts = []

        async def alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.submit(_make_extracted_file())
        await asyncio.sleep(0.3)
        await pipeline.stop()

        assert len(alerts) == 1
        # CRITICAL because hash match overrides YARA's WARNING
        assert alerts[0]["severity"] == "CRITICAL"
        desc = alerts[0]["description"]
        assert "YARA" in desc
        assert "malicious" in desc.lower()

    @pytest.mark.asyncio
    async def test_sync_callback_supported(self, mock_yara, mock_hash_client, tmp_path):
        """동기 콜백도 지원한다."""
        mock_yara.scan_bytes.return_value = [
            {"rule": "Test_Rule", "tags": [], "meta": {}},
        ]

        alerts = []

        def sync_alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=sync_alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.submit(_make_extracted_file())
        await asyncio.sleep(0.3)
        await pipeline.stop()

        assert len(alerts) == 1

    @pytest.mark.asyncio
    async def test_multiple_files_processed(self, mock_yara, mock_hash_client, tmp_path):
        """여러 파일이 순차적으로 처리된다."""
        alerts = []

        async def alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        for i in range(5):
            await pipeline.submit(_make_extracted_file(filename=f"file_{i}.bin"))
        await asyncio.sleep(0.5)
        await pipeline.stop()

        # 클린 파일이므로 알림 없음
        assert len(alerts) == 0
        assert pipeline.processed_count == 5

    @pytest.mark.asyncio
    async def test_file_saved_on_detection(self, mock_yara, mock_hash_client, tmp_path):
        """탐지된 파일이 디스크에 저장된다."""
        mock_yara.scan_bytes.return_value = [
            {"rule": "SaveTest", "tags": [], "meta": {}},
        ]

        alerts = []

        async def alert_cb(data):
            alerts.append(data)

        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=alert_cb,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.submit(_make_extracted_file())
        await asyncio.sleep(0.3)
        await pipeline.stop()

        # http 서브디렉토리에 파일 저장
        saved_files = list((tmp_path / "http").glob("*"))
        assert len(saved_files) == 1

    @pytest.mark.asyncio
    async def test_pipeline_stop_idempotent(self, mock_yara, mock_hash_client, tmp_path):
        """stop()을 여러 번 호출해도 안전하다."""
        pipeline = ExtractionPipeline(
            yara_scanner=mock_yara,
            hash_client=mock_hash_client,
            alert_callback=lambda d: None,
            output_dir=str(tmp_path),
        )

        await pipeline.start()
        await pipeline.stop()
        await pipeline.stop()  # 두 번째 호출도 안전해야 함
