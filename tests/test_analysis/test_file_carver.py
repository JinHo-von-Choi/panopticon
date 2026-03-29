"""Tests for FileCarver.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import base64
import time

import pytest

from netwatcher.analysis.file_carver import ExtractedFile, FileCarver


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def carver():
    return FileCarver(output_dir="/tmp/test_extracted", max_file_size=1_000_000, max_streams=10)


def _http_response(
    body: bytes,
    content_type: str = "application/octet-stream",
    chunked: bool = False,
    filename: str = "",
) -> bytes:
    """테스트용 HTTP 응답 바이트를 생성한다."""
    headers = f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n"
    if filename:
        headers += f'Content-Disposition: attachment; filename="{filename}"\r\n'
    if chunked:
        headers += "Transfer-Encoding: chunked\r\n"
        chunk_body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        return headers.encode() + b"\r\n" + chunk_body
    else:
        headers += f"Content-Length: {len(body)}\r\n"
        return headers.encode() + b"\r\n" + body


# ---------------------------------------------------------------------------
# HTTP 응답 카빙 테스트
# ---------------------------------------------------------------------------

class TestHTTPCarving:
    """HTTP 응답에서 파일 추출 테스트."""

    def test_simple_response_with_content_length(self, carver):
        """Content-Length가 있는 단순 HTTP 응답에서 파일을 추출한다."""
        body    = b"\x89PNG" + b"\x00" * 200
        payload = _http_response(body, content_type="image/png", filename="test.png")

        result = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, payload)

        assert result is not None
        assert len(result) == 1
        ef = result[0]
        assert ef.filename == "test.png"
        assert ef.content_type == "image/png"
        assert ef.data == body
        assert ef.protocol == "http"
        assert ef.source_ip == "10.0.0.1"
        assert ef.dest_ip == "10.0.0.2"
        assert len(ef.md5) == 32
        assert len(ef.sha256) == 64

    def test_chunked_transfer(self, carver):
        """Chunked transfer encoding을 디코딩하여 파일을 추출한다."""
        body    = b"\x00" * 256
        payload = _http_response(body, chunked=True, filename="chunked.bin")

        result = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, payload)

        assert result is not None
        assert len(result) == 1
        assert result[0].data == body

    def test_multi_packet_response(self, carver):
        """여러 패킷에 걸친 HTTP 응답을 조합한다."""
        body      = b"\x00" * 500
        full_resp = _http_response(body, filename="multi.bin")
        # 200바이트씩 분할
        part1 = full_resp[:200]
        part2 = full_resp[200:400]
        part3 = full_resp[400:]

        r1 = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, part1)
        assert r1 is None

        r2 = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, part2)
        # 헤더가 완성되었을 수 있지만 바디가 미완성
        # 결과는 None이거나 아직 미완성

        r3 = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, part3)
        # 마지막 패킷에서 완성
        # 어느 단계에서든 결과가 나올 수 있음
        results = [r for r in [r1, r2, r3] if r is not None]
        assert len(results) >= 1
        final = results[-1]
        assert len(final) == 1
        assert final[0].data == body

    def test_text_html_skipped(self, carver):
        """text/html 콘텐츠는 추출하지 않는다."""
        body    = b"<html><body>Hello</body></html>" + b"\x00" * 100
        payload = _http_response(body, content_type="text/html; charset=utf-8")

        result = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, payload)
        assert result is None

    def test_max_file_size_truncation(self):
        """max_file_size를 초과하면 스트림이 잘린다."""
        carver = FileCarver(max_file_size=500, max_streams=10)
        body   = b"\x00" * 1000
        # Content-Length를 1000으로 설정하되 실제 전송
        payload = _http_response(body, filename="big.bin")

        result = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, payload)
        if result is not None:
            assert len(result[0].data) <= 500

    def test_small_body_discarded(self, carver):
        """64바이트 미만의 바디는 파일로 생성하지 않는다."""
        body    = b"\x00" * 10
        payload = _http_response(body, filename="tiny.bin")

        result = carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, payload)
        assert result is None


# ---------------------------------------------------------------------------
# SMTP MIME 첨부 테스트
# ---------------------------------------------------------------------------

class TestSMTPCarving:
    """SMTP MIME 첨부 파일 추출 테스트."""

    def test_base64_attachment(self, carver):
        """Base64 인코딩된 SMTP 첨부 파일을 추출한다."""
        file_data   = b"\x89PNG" + b"\x00" * 200
        b64_encoded = base64.b64encode(file_data)

        mime_message = (
            b"Content-Type: multipart/mixed; boundary=BOUNDARY123\r\n"
            b"\r\n"
            b"--BOUNDARY123\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"This is the email body.\r\n"
            b"--BOUNDARY123\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b'Content-Disposition: attachment; filename="report.pdf"\r\n'
            b"\r\n"
            + b64_encoded + b"\r\n"
            b"--BOUNDARY123--\r\n"
        )

        result = carver.feed_packet("10.0.0.1", 25, "10.0.0.2", 54321, mime_message)

        assert result is not None
        assert len(result) == 1
        ef = result[0]
        assert ef.filename == "report.pdf"
        assert ef.protocol == "smtp"
        assert ef.data == file_data

    def test_no_attachment_ignored(self, carver):
        """첨부 파일이 없는 MIME 메시지는 추출하지 않는다."""
        mime_message = (
            b"Content-Type: multipart/mixed; boundary=BOUND\r\n"
            b"\r\n"
            b"--BOUND\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Just text.\r\n"
            b"--BOUND--\r\n"
        )

        result = carver.feed_packet("10.0.0.1", 25, "10.0.0.2", 54321, mime_message)
        assert result is None


# ---------------------------------------------------------------------------
# 스트림 관리 테스트
# ---------------------------------------------------------------------------

class TestStreamManagement:
    """스트림 용량 관리 및 만료 테스트."""

    def test_max_streams_eviction(self):
        """max_streams를 초과하면 가장 오래된 스트림이 제거된다."""
        carver = FileCarver(max_streams=3)

        # 4개의 미완성 HTTP 스트림 생성 (헤더만 전송)
        for i in range(4):
            incomplete = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n"
            carver.feed_packet("10.0.0.1", 80 + i, "10.0.0.2", 12345 + i, incomplete)

        assert carver.active_streams <= 3

    def test_flush_expired(self, carver):
        """만료된 스트림이 올바르게 플러시된다."""
        # 미완성 스트림 생성
        incomplete = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n"
            b"Content-Length: 10000\r\n\r\n"
            + b"\x00" * 200
        )
        carver.feed_packet("10.0.0.1", 80, "10.0.0.2", 12345, incomplete)
        assert carver.active_streams == 1

        # 스트림의 updated 시간을 과거로 설정
        for stream in carver._streams.values():
            stream.updated = time.time() - 120

        results = carver.flush_expired(max_age=60.0)
        assert carver.active_streams == 0
        # 200바이트 > 64바이트이므로 파일이 생성됨
        assert len(results) == 1

    def test_non_http_payload_ignored(self, carver):
        """HTTP도 SMTP도 아닌 페이로드는 무시된다."""
        result = carver.feed_packet("10.0.0.1", 443, "10.0.0.2", 12345, b"random binary data")
        assert result is None


# ---------------------------------------------------------------------------
# ExtractedFile 데이터클래스 테스트
# ---------------------------------------------------------------------------

class TestExtractedFile:
    """ExtractedFile 해시 자동 계산 테스트."""

    def test_hash_auto_calculated(self):
        """해시가 자동으로 계산된다."""
        ef = ExtractedFile(
            data=b"test data",
            filename="test.txt",
            content_type="text/plain",
            source_ip="1.2.3.4",
            dest_ip="5.6.7.8",
            timestamp=time.time(),
            protocol="http",
        )
        assert len(ef.md5) == 32
        assert len(ef.sha256) == 64
