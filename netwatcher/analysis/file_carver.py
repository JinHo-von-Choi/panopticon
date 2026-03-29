"""HTTP/SMTP 트래픽에서 파일을 추출하는 카버.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import base64
import hashlib
import logging
import quopri
import re
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("netwatcher.analysis.file_carver")

_CONTENT_DISPOSITION_FILENAME = re.compile(
    rb'filename[*]?=["\']?([^"\';\r\n]+)', re.IGNORECASE,
)
_MIME_BOUNDARY = re.compile(rb'boundary=[""]?([^""\s;]+)', re.IGNORECASE)
_CHUNKED_SIZE = re.compile(rb'^([0-9a-fA-F]+)\r\n')


@dataclass
class ExtractedFile:
    """추출된 파일을 표현한다."""
    data: bytes
    filename: str
    content_type: str
    source_ip: str
    dest_ip: str
    timestamp: float
    protocol: str  # "http" or "smtp"
    md5: str = ""
    sha256: str = ""

    def __post_init__(self) -> None:
        """해시를 자동 계산한다."""
        if not self.md5:
            self.md5 = hashlib.md5(self.data).hexdigest()
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.data).hexdigest()


@dataclass
class _StreamBuffer:
    """단일 TCP 스트림의 파일 추출 상태."""
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)
    protocol: str = ""
    content_type: str = ""
    content_length: int = -1
    filename: str = ""
    chunked: bool = False
    headers_done: bool = False
    header_buf: bytes = b""
    body_buf: bytes = b""
    source_ip: str = ""
    dest_ip: str = ""
    # SMTP MIME 상태
    mime_boundary: bytes = b""
    mime_encoding: str = ""  # "base64" | "quoted-printable" | ""
    in_attachment: bool = False
    attachment_buf: bytes = b""


class FileCarver:
    """HTTP 응답과 SMTP 첨부 파일에서 파일을 추출한다."""

    def __init__(
        self,
        output_dir: str = "data/extracted",
        max_file_size: int = 10_000_000,
        max_streams: int = 500,
    ) -> None:
        self._output_dir   = output_dir
        self._max_file_size = max_file_size
        self._max_streams  = max_streams
        self._streams: dict[tuple[str, int, str, int], _StreamBuffer] = {}

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    def feed_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
    ) -> list[ExtractedFile] | None:
        """TCP 페이로드를 공급한다. 추출 완료 시 파일 목록을, 미완료 시 None을 반환한다."""
        if not payload:
            return None

        key = (src_ip, src_port, dst_ip, dst_port)

        # 신규 HTTP 응답 감지
        if payload[:5] == b"HTTP/" and key not in self._streams:
            return self._handle_http(key, src_ip, dst_ip, payload)

        # 신규 SMTP DATA 감지 (Content-Type: multipart/mixed)
        if key not in self._streams and b"Content-Type:" in payload[:512]:
            boundary_match = _MIME_BOUNDARY.search(payload[:1024])
            if boundary_match:
                return self._handle_smtp_start(
                    key, src_ip, dst_ip, payload, boundary_match.group(1),
                )

        # 기존 스트림 후속 데이터
        if key in self._streams:
            stream = self._streams[key]
            stream.updated = time.time()
            if stream.protocol == "http":
                return self._feed_http(key, stream, payload)
            elif stream.protocol == "smtp":
                return self._feed_smtp(key, stream, payload)

        return None

    def flush_expired(self, max_age: float = 60.0) -> list[ExtractedFile]:
        """max_age보다 오래된 스트림을 플러시하여 부분 추출된 파일을 반환한다."""
        now      = time.time()
        expired  = [k for k, s in self._streams.items() if now - s.updated > max_age]
        results: list[ExtractedFile] = []
        for k in expired:
            stream = self._streams.pop(k)
            if stream.body_buf and len(stream.body_buf) > 64:
                results.append(self._build_extracted(stream))
        return results

    @property
    def active_streams(self) -> int:
        """현재 활성 스트림 수를 반환한다."""
        return len(self._streams)

    # ------------------------------------------------------------------
    # HTTP 처리
    # ------------------------------------------------------------------

    def _handle_http(
        self,
        key: tuple[str, int, str, int],
        src_ip: str,
        dst_ip: str,
        payload: bytes,
    ) -> list[ExtractedFile] | None:
        """HTTP 응답의 첫 번째 패킷을 처리한다."""
        header_end = payload.find(b"\r\n\r\n")
        if header_end < 0:
            # 헤더가 아직 미완성 -- 버퍼링
            self._ensure_capacity()
            stream = _StreamBuffer(
                protocol="http",
                source_ip=src_ip,
                dest_ip=dst_ip,
                header_buf=payload,
            )
            self._streams[key] = stream
            return None

        headers_raw = payload[:header_end]
        body_start  = payload[header_end + 4:]
        stream = self._init_http_stream(headers_raw, src_ip, dst_ip)
        stream.headers_done = True
        stream.body_buf = body_start

        # 바이너리/파일 콘텐츠가 아니면 무시
        if not self._is_extractable_content(stream.content_type):
            return None

        # 크기 제한 적용
        if len(stream.body_buf) > self._max_file_size:
            stream.body_buf = stream.body_buf[:self._max_file_size]
            return self._finalize_stream(key, stream)

        # 청크드 전송의 경우 종료 마커 확인
        if stream.chunked and b"0\r\n\r\n" in stream.body_buf:
            decoded = self._decode_chunked(stream.body_buf)
            if decoded is not None:
                stream.body_buf = decoded
            return self._finalize_stream(key, stream)

        self._ensure_capacity()
        self._streams[key] = stream
        return self._check_http_complete(key, stream)

    def _feed_http(
        self,
        key: tuple[str, int, str, int],
        stream: _StreamBuffer,
        payload: bytes,
    ) -> list[ExtractedFile] | None:
        """기존 HTTP 스트림에 데이터를 추가한다."""
        if not stream.headers_done:
            stream.header_buf += payload
            header_end = stream.header_buf.find(b"\r\n\r\n")
            if header_end < 0:
                return None
            headers_raw = stream.header_buf[:header_end]
            body_start  = stream.header_buf[header_end + 4:]
            new_stream  = self._init_http_stream(headers_raw, stream.source_ip, stream.dest_ip)
            new_stream.headers_done = True
            new_stream.body_buf = body_start
            new_stream.created = stream.created
            if not self._is_extractable_content(new_stream.content_type):
                self._streams.pop(key, None)
                return None
            self._streams[key] = new_stream
            return self._check_http_complete(key, new_stream)

        if stream.chunked:
            stream.body_buf += payload
            # 청크 종료 마커 확인
            if b"0\r\n\r\n" in stream.body_buf or b"0\r\n" == stream.body_buf[-5:][:3]:
                decoded = self._decode_chunked(stream.body_buf)
                if decoded is not None:
                    stream.body_buf = decoded
                return self._finalize_stream(key, stream)
        else:
            stream.body_buf += payload

        # 크기 제한 초과
        if len(stream.body_buf) > self._max_file_size:
            logger.warning(
                "Stream %s exceeded max file size (%d bytes), truncating",
                key, self._max_file_size,
            )
            stream.body_buf = stream.body_buf[:self._max_file_size]
            return self._finalize_stream(key, stream)

        return self._check_http_complete(key, stream)

    def _check_http_complete(
        self,
        key: tuple[str, int, str, int],
        stream: _StreamBuffer,
    ) -> list[ExtractedFile] | None:
        """Content-Length 기준으로 HTTP 바디 완료 여부를 확인한다."""
        if stream.content_length >= 0 and len(stream.body_buf) >= stream.content_length:
            stream.body_buf = stream.body_buf[:stream.content_length]
            # 크기 제한 적용
            if len(stream.body_buf) > self._max_file_size:
                stream.body_buf = stream.body_buf[:self._max_file_size]
            return self._finalize_stream(key, stream)
        return None

    def _init_http_stream(
        self, headers_raw: bytes, src_ip: str, dst_ip: str,
    ) -> _StreamBuffer:
        """HTTP 헤더를 파싱하여 StreamBuffer를 초기화한다."""
        stream = _StreamBuffer(protocol="http", source_ip=src_ip, dest_ip=dst_ip)
        headers_lower = headers_raw.lower()

        # Content-Type
        ct_match = re.search(rb'content-type:\s*([^\r\n]+)', headers_lower)
        if ct_match:
            stream.content_type = ct_match.group(1).decode("ascii", errors="replace").strip()

        # Content-Length
        cl_match = re.search(rb'content-length:\s*(\d+)', headers_lower)
        if cl_match:
            stream.content_length = int(cl_match.group(1))

        # Transfer-Encoding: chunked
        if b"transfer-encoding:" in headers_lower and b"chunked" in headers_lower:
            stream.chunked = True

        # Content-Disposition (filename)
        disp_match = _CONTENT_DISPOSITION_FILENAME.search(headers_raw)
        if disp_match:
            stream.filename = disp_match.group(1).decode("utf-8", errors="replace").strip()

        return stream

    # ------------------------------------------------------------------
    # SMTP MIME 처리
    # ------------------------------------------------------------------

    def _handle_smtp_start(
        self,
        key: tuple[str, int, str, int],
        src_ip: str,
        dst_ip: str,
        payload: bytes,
        boundary: bytes,
    ) -> list[ExtractedFile] | None:
        """SMTP multipart 메시지의 시작을 처리한다."""
        self._ensure_capacity()
        stream = _StreamBuffer(
            protocol="smtp",
            source_ip=src_ip,
            dest_ip=dst_ip,
            mime_boundary=boundary,
            body_buf=payload,
        )
        self._streams[key] = stream
        return self._process_smtp_parts(key, stream)

    def _feed_smtp(
        self,
        key: tuple[str, int, str, int],
        stream: _StreamBuffer,
        payload: bytes,
    ) -> list[ExtractedFile] | None:
        """기존 SMTP 스트림에 데이터를 추가한다."""
        stream.body_buf += payload

        if len(stream.body_buf) > self._max_file_size:
            stream.body_buf = stream.body_buf[:self._max_file_size]
            return self._process_smtp_parts(key, stream, force_flush=True)

        # 최종 경계 마커 확인
        final_marker = b"--" + stream.mime_boundary + b"--"
        if final_marker in stream.body_buf:
            return self._process_smtp_parts(key, stream, force_flush=True)

        return None

    def _process_smtp_parts(
        self,
        key: tuple[str, int, str, int],
        stream: _StreamBuffer,
        force_flush: bool = False,
    ) -> list[ExtractedFile] | None:
        """SMTP MIME 파트를 파싱하여 첨부 파일을 추출한다."""
        boundary     = b"--" + stream.mime_boundary
        parts        = stream.body_buf.split(boundary)
        results: list[ExtractedFile] = []

        for part in parts[1:]:  # 첫 번째는 프리앰블
            if part.startswith(b"--"):
                continue  # 최종 경계

            header_end = part.find(b"\r\n\r\n")
            if header_end < 0:
                continue

            part_headers = part[:header_end].lower()
            part_body    = part[header_end + 4:]

            # 첨부 파일만 추출 (Content-Disposition: attachment 또는 Content-Transfer-Encoding)
            if b"attachment" not in part_headers and b"application/" not in part_headers:
                continue

            # 파일명 추출
            filename = "attachment"
            fname_match = _CONTENT_DISPOSITION_FILENAME.search(part[:header_end])
            if fname_match:
                filename = fname_match.group(1).decode("utf-8", errors="replace").strip()

            # Content-Type 추출
            ct = "application/octet-stream"
            ct_match = re.search(rb'content-type:\s*([^\r\n;]+)', part_headers)
            if ct_match:
                ct = ct_match.group(1).decode("ascii", errors="replace").strip()

            # 디코딩
            decoded = part_body.rstrip(b"\r\n-")
            if b"base64" in part_headers:
                try:
                    decoded = base64.b64decode(decoded, validate=False)
                except Exception:
                    logger.debug("Failed to base64-decode SMTP attachment")
                    continue
            elif b"quoted-printable" in part_headers:
                try:
                    decoded = quopri.decodestring(decoded)
                except Exception:
                    continue

            if len(decoded) > 64:
                results.append(ExtractedFile(
                    data=decoded[:self._max_file_size],
                    filename=filename,
                    content_type=ct,
                    source_ip=stream.source_ip,
                    dest_ip=stream.dest_ip,
                    timestamp=stream.created,
                    protocol="smtp",
                ))

        if force_flush or results:
            self._streams.pop(key, None)

        return results if results else None

    # ------------------------------------------------------------------
    # 공통 유틸리티
    # ------------------------------------------------------------------

    def _finalize_stream(
        self,
        key: tuple[str, int, str, int],
        stream: _StreamBuffer,
    ) -> list[ExtractedFile] | None:
        """완료된 스트림에서 파일을 생성하고 스트림을 제거한다."""
        self._streams.pop(key, None)
        if not stream.body_buf or len(stream.body_buf) < 64:
            return None
        return [self._build_extracted(stream)]

    def _build_extracted(self, stream: _StreamBuffer) -> ExtractedFile:
        """StreamBuffer를 ExtractedFile로 변환한다."""
        filename = stream.filename or self._guess_filename(stream.content_type)
        return ExtractedFile(
            data=stream.body_buf,
            filename=filename,
            content_type=stream.content_type or "application/octet-stream",
            source_ip=stream.source_ip,
            dest_ip=stream.dest_ip,
            timestamp=stream.created,
            protocol=stream.protocol,
        )

    def _ensure_capacity(self) -> None:
        """스트림 수가 max_streams를 초과하지 않도록 가장 오래된 스트림을 제거한다."""
        while len(self._streams) >= self._max_streams:
            oldest_key = min(self._streams, key=lambda k: self._streams[k].updated)
            self._streams.pop(oldest_key)
            logger.debug("Evicted oldest stream to maintain capacity")

    @staticmethod
    def _is_extractable_content(content_type: str) -> bool:
        """바이너리/파일 콘텐츠인지 판단한다. text/html 등은 제외."""
        if not content_type:
            return False
        ct = content_type.lower()
        # 텍스트/HTML/JSON은 일반적으로 파일 추출 대상이 아님
        skip_prefixes = ("text/html", "text/css", "text/javascript", "application/json")
        for prefix in skip_prefixes:
            if ct.startswith(prefix):
                return False
        # 바이너리 타입 또는 파일 다운로드 관련 타입
        extractable = (
            "application/", "image/", "audio/", "video/",
            "text/plain", "text/csv", "text/xml",
        )
        return any(ct.startswith(e) for e in extractable)

    @staticmethod
    def _guess_filename(content_type: str) -> str:
        """Content-Type에서 확장자를 추측하여 파일명을 생성한다."""
        ext_map = {
            "application/pdf": "file.pdf",
            "application/zip": "file.zip",
            "application/x-rar-compressed": "file.rar",
            "application/x-7z-compressed": "file.7z",
            "application/vnd.ms-excel": "file.xls",
            "application/msword": "file.doc",
            "application/x-executable": "file.exe",
            "application/x-msdos-program": "file.exe",
            "application/octet-stream": "file.bin",
            "image/png": "file.png",
            "image/jpeg": "file.jpg",
            "image/gif": "file.gif",
        }
        ct = (content_type or "").lower().split(";")[0].strip()
        return ext_map.get(ct, "file.bin")

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes | None:
        """HTTP chunked transfer encoding을 디코딩한다."""
        result   = bytearray()
        pos      = 0
        max_iter = 10_000  # 무한 루프 방지

        for _ in range(max_iter):
            # 청크 크기 라인 찾기
            line_end = data.find(b"\r\n", pos)
            if line_end < 0:
                break

            size_str = data[pos:line_end].strip()
            if not size_str:
                pos = line_end + 2
                continue

            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                return None  # 잘못된 청크 형식

            if chunk_size == 0:
                return bytes(result)

            chunk_start = line_end + 2
            chunk_end   = chunk_start + chunk_size

            if chunk_end > len(data):
                # 불완전한 청크 -- 가용 데이터만 사용
                result.extend(data[chunk_start:])
                return bytes(result)

            result.extend(data[chunk_start:chunk_end])
            pos = chunk_end + 2  # CRLF 건너뛰기

        return bytes(result) if result else None
