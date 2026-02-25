"""Tests for PcapAnalyzer."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import pytest_asyncio

from netwatcher.analysis.pcap_analyzer import PcapAnalyzer


class TestPcapAnalyzerAvailability:
    """Test tshark availability detection."""

    def test_is_available_when_installed(self):
        """Should return True when tshark is in PATH."""
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            analyzer = PcapAnalyzer()
            assert analyzer.is_available() is True

    def test_is_available_when_not_installed(self):
        """Should return False when tshark is not in PATH."""
        with patch("shutil.which", return_value=None):
            analyzer = PcapAnalyzer()
            assert analyzer.is_available() is False


class TestPcapAnalyzerExtraction:
    """Test file extraction (mocked tshark)."""

    @pytest.mark.asyncio
    async def test_extract_files_tshark_unavailable(self, tmp_path):
        """When tshark not available, return empty list."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        with patch.object(analyzer, "is_available", return_value=False):
            result = await analyzer.extract_files(str(tmp_path / "test.pcap"))
        assert result == []

    @pytest.mark.asyncio
    async def test_extract_files_pcap_not_found(self, tmp_path):
        """When PCAP file doesn't exist, return empty list."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        with patch.object(analyzer, "is_available", return_value=True):
            result = await analyzer.extract_files(str(tmp_path / "nonexistent.pcap"))
        assert result == []

    @pytest.mark.asyncio
    async def test_extract_files_success(self, tmp_path):
        """Simulated successful extraction should return file metadata."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        pcap_path = tmp_path / "test.pcap"
        pcap_path.write_bytes(b"fake pcap content")

        # Mock tshark execution: simulate it creating extracted files
        async def mock_create_subprocess(*args, **kwargs):
            # Find the export dir from the tshark command args
            for i, arg in enumerate(args):
                if isinstance(arg, str) and arg.startswith("http,"):
                    export_dir = Path(arg.split(",", 1)[1])
                    export_dir.mkdir(parents=True, exist_ok=True)
                    (export_dir / "image.jpg").write_bytes(b"fake image data")
                    (export_dir / "script.js").write_bytes(b"var x = 1;")
                    break
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch.object(analyzer, "is_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess):
                result = await analyzer.extract_files(str(pcap_path))

        assert len(result) == 2
        filenames = {r["filename"] for r in result}
        assert "image.jpg" in filenames
        assert "script.js" in filenames
        for r in result:
            assert "sha256" in r
            assert len(r["sha256"]) == 64
            assert "size" in r
            assert r["size"] > 0

    @pytest.mark.asyncio
    async def test_extract_files_max_size_filter(self, tmp_path):
        """Files exceeding max_file_size should be skipped."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"), max_file_size=100)
        pcap_path = tmp_path / "test.pcap"
        pcap_path.write_bytes(b"fake pcap")

        async def mock_create_subprocess(*args, **kwargs):
            for i, arg in enumerate(args):
                if isinstance(arg, str) and arg.startswith("http,"):
                    export_dir = Path(arg.split(",", 1)[1])
                    export_dir.mkdir(parents=True, exist_ok=True)
                    (export_dir / "small.txt").write_bytes(b"small")
                    (export_dir / "big.bin").write_bytes(b"X" * 200)  # exceeds max
                    break
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch.object(analyzer, "is_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess):
                result = await analyzer.extract_files(str(pcap_path))

        assert len(result) == 1
        assert result[0]["filename"] == "small.txt"

    @pytest.mark.asyncio
    async def test_extract_files_tshark_failure(self, tmp_path):
        """When tshark returns non-zero exit code, return empty list."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        pcap_path = tmp_path / "test.pcap"
        pcap_path.write_bytes(b"fake pcap")

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b"error"))
            return proc

        with patch.object(analyzer, "is_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess):
                result = await analyzer.extract_files(str(pcap_path))

        assert result == []

    @pytest.mark.asyncio
    async def test_extract_files_exception(self, tmp_path):
        """When tshark execution throws, return empty list."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        pcap_path = tmp_path / "test.pcap"
        pcap_path.write_bytes(b"fake pcap")

        with patch.object(analyzer, "is_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=OSError("exec failed")):
                result = await analyzer.extract_files(str(pcap_path))

        assert result == []


class TestPcapAnalyzerIMF:
    """Test IMF (email) extraction."""

    @pytest.mark.asyncio
    async def test_extract_imf_unavailable(self, tmp_path):
        """When tshark unavailable, return empty."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        with patch.object(analyzer, "is_available", return_value=False):
            result = await analyzer.extract_files_imf(str(tmp_path / "test.pcap"))
        assert result == []

    @pytest.mark.asyncio
    async def test_extract_imf_file_not_found(self, tmp_path):
        """When pcap not found, return empty."""
        analyzer = PcapAnalyzer(output_dir=str(tmp_path / "out"))
        with patch.object(analyzer, "is_available", return_value=True):
            result = await analyzer.extract_files_imf(str(tmp_path / "nope.pcap"))
        assert result == []
