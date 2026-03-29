"""Elasticsearch 직접 인덱싱 출력 채널.

aiohttp를 사용한 비동기 bulk 인덱싱으로, elasticsearch-py 의존성을 추가하지 않는다.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp

from netwatcher.alerts.channels.base import NotificationChannel
from netwatcher.detection.models import Alert
from netwatcher.integrations.ecs_mapper import alert_to_ecs

logger = logging.getLogger("netwatcher.integrations.elasticsearch")

_FLUSH_INTERVAL_SECONDS = 5
_MAX_BATCH_SIZE         = 100


class ElasticsearchChannel(NotificationChannel):
    """Elasticsearch bulk indexing 채널."""

    name = "elasticsearch"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._hosts        = config.get("hosts", ["http://localhost:9200"])
        self._index_prefix = config.get("index_prefix", "netwatcher-events")
        self._api_key      = config.get("api_key", "")
        self._username     = config.get("username", "")
        self._password     = config.get("password", "")

        self._buffer: list[dict[str, Any]] = []
        self._lock           = asyncio.Lock()
        self._flush_task:  asyncio.Task | None = None
        self._session:     aiohttp.ClientSession | None = None

    def _get_index_name(self) -> str:
        """날짜 기반 인덱스 이름을 생성한다: {prefix}-YYYY.MM"""
        now = datetime.now(timezone.utc)
        return f"{self._index_prefix}-{now.strftime('%Y.%m')}"

    def _build_headers(self) -> dict[str, str]:
        """ES API 요청 헤더를 구성한다."""
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"
        return headers

    def _build_auth(self) -> aiohttp.BasicAuth | None:
        """Basic 인증 객체를 생성한다."""
        if self._username and self._password:
            return aiohttp.BasicAuth(self._username, self._password)
        return None

    async def send(self, alert: Alert) -> bool:
        """알림을 버퍼에 추가하고 임계값 도달 시 플러시한다."""
        doc = alert_to_ecs(alert)

        async with self._lock:
            self._buffer.append(doc)
            if len(self._buffer) >= _MAX_BATCH_SIZE:
                return await self._flush_locked()

        return True

    async def flush(self) -> bool:
        """버퍼의 모든 문서를 Elasticsearch에 인덱싱한다."""
        async with self._lock:
            return await self._flush_locked()

    async def _flush_locked(self) -> bool:
        """락을 이미 획득한 상태에서 bulk 인덱싱을 수행한다."""
        if not self._buffer:
            return True

        batch      = self._buffer[:]
        self._buffer.clear()
        index_name = self._get_index_name()
        ndjson     = self._build_bulk_body(batch, index_name)

        return await self._send_bulk(ndjson)

    def _build_bulk_body(
        self, docs: list[dict[str, Any]], index_name: str
    ) -> str:
        """bulk API용 NDJSON 본문을 구성한다."""
        lines: list[str] = []
        for doc in docs:
            action = json.dumps({"index": {"_index": index_name}})
            lines.append(action)
            lines.append(json.dumps(doc, default=str))
        lines.append("")  # trailing newline
        return "\n".join(lines)

    async def _send_bulk(self, body: str) -> bool:
        """bulk API를 호출하여 문서를 인덱싱한다."""
        headers = self._build_headers()
        auth    = self._build_auth()

        for host in self._hosts:
            url = f"{host.rstrip('/')}/_bulk"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        data=body,
                        headers=headers,
                        auth=auth,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status in (200, 201):
                            result = await resp.json()
                            if result.get("errors"):
                                failed = sum(
                                    1 for item in result.get("items", [])
                                    if item.get("index", {}).get("error")
                                )
                                logger.warning(
                                    "ES bulk 부분 실패: %d/%d",
                                    failed, len(result.get("items", [])),
                                )
                            else:
                                logger.debug(
                                    "ES bulk 성공: %d 문서",
                                    len(result.get("items", [])),
                                )
                            return True
                        else:
                            text = await resp.text()
                            logger.error(
                                "ES bulk 실패 (%s): %d - %s",
                                host, resp.status, text[:500],
                            )
            except Exception:
                logger.exception("ES bulk 전송 오류 (%s)", host)

        return False

    async def start_periodic_flush(self) -> None:
        """주기적 플러시 태스크를 시작한다."""
        if self._flush_task is not None:
            return
        self._flush_task = asyncio.create_task(self._periodic_flush_loop())

    async def _periodic_flush_loop(self) -> None:
        """_FLUSH_INTERVAL_SECONDS 간격으로 버퍼를 플러시한다."""
        while True:
            await asyncio.sleep(_FLUSH_INTERVAL_SECONDS)
            try:
                await self.flush()
            except Exception:
                logger.exception("ES 주기적 플러시 실패")

    async def stop(self) -> None:
        """주기적 플러시를 중지하고 남은 버퍼를 전송한다."""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        await self.flush()
